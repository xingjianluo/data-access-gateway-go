package gateway

import (
	"fmt"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/mask"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// AccessInput 是网关一次访问的输入。
type AccessInput struct {
	RequestID string
	policy.Request
}

// AccessOutput 是网关一次访问的输出。
type AccessOutput struct {
	Decision policy.Decision
	Reason   string
	Version  int
	Data     map[string]any // allow 为明文；mask 为脱敏后数据；deny 为 nil
	Masked   []string       // 实际被脱敏的字段
	AuditSeq int64
}

// Gateway 编排：取当前策略快照 -> 判定 -> 读数据/脱敏 -> 写审计。
// 同一次 Access 内只取一次快照、复用同一个 *policy.Engine，
// 即使处理期间发生热更新，本次请求前后判定也保持同一版本、不会不一致。
type Gateway struct {
	policies *policy.Store
	data     *data.Store
	audit    *audit.Log
}

// New 创建网关。
func New(policies *policy.Store, ds *data.Store, log *audit.Log) *Gateway {
	return &Gateway{policies: policies, data: ds, audit: log}
}

// Access 执行一次访问并留下审计记录。
// 判定与数据读取使用同一策略版本；deny 路径在读取数据之前短路，绝不明文返回。
func (g *Gateway) Access(in AccessInput) (AccessOutput, error) {
	if in.RequestID == "" {
		return AccessOutput{}, fmt.Errorf("gateway: request id is required")
	}

	// 整个请求只取这一次快照；后续不再访问 Store 的当前版本。
	snap, err := g.policies.Snapshot(0)
	if err != nil {
		return AccessOutput{}, fmt.Errorf("gateway: load policy: %w", err)
	}
	eng := policy.NewEngine(snap)
	dr, err := eng.Evaluate(in.Request)
	if err != nil {
		return AccessOutput{}, fmt.Errorf("gateway: evaluate: %w", err)
	}

	out := AccessOutput{Decision: dr.Decision, Reason: dr.Reason, Version: dr.Version}

	switch dr.Decision {
	case policy.DecisionDeny:
		// 拒绝优先：不读取数据，Data 保持 nil。
		out.AuditSeq = g.writeAudit(in, dr, nil, "access denied before data read")
		return out, nil

	case policy.DecisionMask:
		rec, found := g.data.Get(in.Resource)
		if !found {
			out.Reason = dr.Reason + "; resource not found"
			out.AuditSeq = g.writeAudit(in, dr, nil, "mask allowed but resource missing")
			return out, nil
		}
		masked := mask.Apply(rec.Data, dr.MaskRules)
		out.Data = masked
		out.Masked = maskedFields(rec.Data, dr.MaskRules)
		out.AuditSeq = g.writeAudit(in, dr, rec.Data,
			fmt.Sprintf("returned %d masked fields: %v", len(out.Masked), out.Masked))
		return out, nil

	case policy.DecisionAllow:
		rec, found := g.data.Get(in.Resource)
		if !found {
			out.Reason = dr.Reason + "; resource not found"
			out.AuditSeq = g.writeAudit(in, dr, nil, "allowed but resource missing")
			return out, nil
		}
		// 仍返回拷贝，避免调用方修改存储内部对象。
		cp := make(map[string]any, len(rec.Data))
		for k, v := range rec.Data {
			cp[k] = v
		}
		out.Data = cp
		out.AuditSeq = g.writeAudit(in, dr, rec.Data, "returned plaintext data")
		return out, nil
	}

	return AccessOutput{}, fmt.Errorf("gateway: unknown decision %q", dr.Decision)
}

// maskedFields 返回记录中实际存在、因而真正被脱敏的字段。
func maskedFields(rec map[string]any, rules []policy.MaskRule) []string {
	var fs []string
	for _, r := range rules {
		if _, ok := rec[r.Field]; ok {
			fs = append(fs, r.Field)
		}
	}
	return fs
}

func (g *Gateway) writeAudit(in AccessInput, dr policy.DecisionResult, data map[string]any, detail string) int64 {
	hits := make([]string, 0, len(dr.Hits))
	for _, h := range dr.Hits {
		hits = append(hits, fmt.Sprintf("%s[%s] matched=%t: %s", h.RuleID, h.Effect, h.Matched, h.Reason))
	}
	e, err := g.audit.Append(audit.Entry{
		RequestID: in.RequestID,
		Subject:   in.Subject,
		Action:    string(in.Action),
		Resource:  in.Resource,
		Decision:  string(dr.Decision),
		PolicyVer: dr.Version,
		Reason:    dr.Reason,
		Hits:      hits,
		Detail:    detail,
	})
	if err != nil {
		// 审计是强制要求；写审计失败让请求显式失败，不能静默放过。
		panic(fmt.Errorf("gateway: append audit: %w", err))
	}
	return e.Seq
}
