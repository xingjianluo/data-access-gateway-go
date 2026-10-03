package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

// PublishAction 是策略发布事件在审计日志中的动作名。
const PublishAction = "policy.publish"

// PublishRecord 描述一次策略发布/切换：什么时间、从哪个版本换到哪个版本、
// 这批规则大致是什么。记录本体写入哈希链审计日志，随 Log.Verify 一并校验，不可篡改。
type PublishRecord struct {
	Seq         int64     `json:"seq"`          // 审计条目序号
	Time        time.Time `json:"time"`         // 发布时间
	FromVersion int       `json:"from_version"` // 切换前版本（首次发布为 0）
	ToVersion   int       `json:"to_version"`
	Name        string    `json:"name"`
	RuleCount   int       `json:"rule_count"`
	RuleIDs     []string  `json:"rule_ids"`              // 访问规则 ID（升序）
	RulesHash   string    `json:"rules_hash"`            // 规则内容规范化 SHA-256，供比对两版差异
	RetentionN  int       `json:"retention_rule_count"`  // 保留期处置规则数
}

// publishRequestID 生成发布事件的请求标识，便于按版本检索。
func publishRequestID(version int) string { return fmt.Sprintf("policy-publish:%d", version) }

// History 把策略发布事件追加到哈希链审计日志，并提供按版本回溯查询。
// 因为发布记录就是审计链上的普通条目，现有 Verify 自然将其纳入完整性校验。
type History struct {
	log *audit.Log
}

// NewHistory 基于既有审计日志创建策略变更追溯器。
func NewHistory(log *audit.Log) *History {
	return &History{log: log}
}

// RecordPublish 把一次发布写入审计链。fromVersion 为切换前的当前版本（无则为 0）。
func (h *History) RecordPublish(fromVersion int, p *Policy) (PublishRecord, error) {
	if p == nil {
		return PublishRecord{}, fmt.Errorf("policy history: cannot record nil policy")
	}
	rec := PublishRecord{
		FromVersion: fromVersion,
		ToVersion:   p.Version,
		Name:        p.Name,
		RuleCount:   len(p.Rules),
		RetentionN:  len(p.Retention),
	}
	for _, r := range p.Rules {
		rec.RuleIDs = append(rec.RuleIDs, r.ID)
	}
	sort.Strings(rec.RuleIDs)
	rec.RulesHash = hashRules(p)

	detail, err := json.Marshal(rec)
	if err != nil {
		return PublishRecord{}, fmt.Errorf("policy history: marshal record: %w", err)
	}
	e, err := h.log.Append(audit.Entry{
		RequestID: publishRequestID(p.Version),
		Subject:   "policy-admin",
		Action:    PublishAction,
		Resource:  fmt.Sprintf("policy/%d", p.Version),
		Decision:  "published",
		PolicyVer: p.Version,
		Reason:    fmt.Sprintf("policy switched v%d -> v%d (%s): %d access rules, %d retention rules", fromVersion, p.Version, p.Name, len(p.Rules), len(p.Retention)),
		Detail:    string(detail),
	})
	if err != nil {
		return PublishRecord{}, fmt.Errorf("policy history: append audit: %w", err)
	}
	rec.Seq = e.Seq
	rec.Time = e.Time
	return rec, nil
}

// Lookup 按版本号回溯该版本是什么时候、从哪个版本切换、以什么规则内容装入的。
func (h *History) Lookup(version int) (PublishRecord, bool) {
	e, ok := h.log.EntryByRequest(publishRequestID(version))
	if !ok {
		return PublishRecord{}, false
	}
	var rec PublishRecord
	if err := json.Unmarshal([]byte(e.Detail), &rec); err != nil {
		return PublishRecord{}, false
	}
	rec.Seq = e.Seq
	rec.Time = e.Time
	return rec, true
}

// TraceByRequest 由一次访问的审计记录顺藤摸瓜：取出该次访问使用的策略版本，
// 再定位该版本的发布记录。任一环缺失时返回对应 false。
func (h *History) TraceByRequest(requestID string) (audit.Entry, PublishRecord, bool) {
	e, ok := h.log.EntryByRequest(requestID)
	if !ok {
		return audit.Entry{}, PublishRecord{}, false
	}
	rec, ok := h.Lookup(e.PolicyVer)
	if !ok {
		return e, PublishRecord{}, false
	}
	return e, rec, true
}

// hashRules 对策略的规则内容做规范化 SHA-256，供快速比对两个版本是否一致。
func hashRules(p *Policy) string {
	type norm struct {
		Rules     []Rule          `json:"rules"`
		Retention []RetentionRule `json:"retention"`
	}
	b, err := json.Marshal(norm{Rules: p.Rules, Retention: p.Retention})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
