// Command demo 在本地端到端演示：策略判定（放行/拒绝/脱敏）、策略热更新、
// 数据主体导出/删除、保留期清理与审计完整性校验。
package main

import (
	"fmt"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/dsr"
	"github.com/xingjianluo/data-access-gateway-go/internal/gateway"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

func main() {
	ps := policy.NewStore()
	ds := data.NewStore(3)
	lg := audit.NewLog()
	gw := gateway.New(ps, ds, lg)
	proc := dsr.New(ds, lg)

	// 1) 受管数据（3 个副本）
	past := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	ds.Put(data.Record{ID: "users/1", SubjectID: "subj-1", Resource: "users/1",
		Data:        map[string]any{"name": "alice", "email": "alice@example.com", "ssn": "123-45-6789"},
		RetainUntil: &past})
	ds.Put(data.Record{ID: "users/2", SubjectID: "subj-2", Resource: "users/2",
		Data:        map[string]any{"name": "bob", "email": "bob@example.com"},
		RetainUntil: &past})

	// 2) 策略 v1：user:* 读 users/* 脱敏 email/ssn；finance 一律拒绝
	ps.Publish(&policy.Policy{Version: 1, Name: "base", Rules: []policy.Rule{
		{ID: "deny-finance", Effect: policy.EffectDeny, Priority: 30,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			Conditions: []policy.Condition{{Key: "subject.dept", Op: "eq", Val: "finance"}}},
		{ID: "mask-pii", Effect: policy.EffectMask, Priority: 20,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			Mask: []policy.MaskRule{{Field: "email", Method: "partial", Keep: 1}, {Field: "ssn", Method: "redact"}}},
		{ID: "allow-read", Effect: policy.EffectAllow, Priority: 10,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})

	access := func(id, subj, dept string) {
		in := gateway.AccessInput{RequestID: id, Request: policy.Request{
			Subject: subj, Action: policy.ActionRead, Resource: "users/1",
			SubjectAttrs: map[string]any{"dept": dept},
		}}
		if dept == "" {
			in.SubjectAttrs = nil
		}
		out, err := gw.Access(in)
		if err != nil {
			fmt.Printf("[%s] ERROR %v\n", id, err)
			return
		}
		fmt.Printf("[%s] %s v%d reason=%q data=%v\n", id, out.Decision, out.Version, out.Reason, out.Data)
	}

	fmt.Println("== 访问决策 ==")
	access("req-1", "user:1001", "eng")     // mask
	access("req-2", "user:1002", "finance") // deny 优先
	access("req-3", "stranger:9", "")       // 默认拒绝

	fmt.Println("== 策略热更新（v2：放行明文）==")
	ps.Publish(&policy.Policy{Version: 2, Name: "open", Rules: []policy.Rule{
		{ID: "open-read", Effect: policy.EffectAllow,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})
	access("req-4", "user:1001", "eng")
	fmt.Printf("req-1 仍可追溯到其生命周期内的版本与判定:\n")
	if e, ok := lg.EntryByRequest("req-1"); ok {
		fmt.Printf("  audit seq=%d ver=%d decision=%s reason=%q\n", e.Seq, e.PolicyVer, e.Decision, e.Reason)
	}

	fmt.Println("== 数据主体导出/删除（覆盖 3 副本）==")
	exp, err := proc.Export("dsr-exp-1", "subj-1")
	fmt.Printf("export err=%v records=%d replicas=%d idempotent=%v\n", err, len(exp.Records), exp.Replicas, exp.Idempotent)
	exp2, _ := proc.Export("dsr-exp-1", "subj-1")
	fmt.Printf("replay export idempotent=%v (重复请求显式可识别)\n", exp2.Idempotent)

	del, err := proc.Delete("dsr-del-1", "subj-1")
	fmt.Printf("delete err=%v replicas=%d seqs=%v\n", err, del.Replicas, del.AuditSeqs)

	fmt.Println("== 保留期清理 ==")
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	affected, err := proc.RetentionSweep(now, dsr.SweepAnonymize, []string{"email", "ssn"})
	fmt.Printf("sweep affected=%v err=%v\n", affected, err)
	if r, ok := ds.Get("users/1"); ok {
		fmt.Printf("users/1 after anonymize=%v retainUntil=%v\n", r.Data, r.RetainUntil)
	}

	fmt.Println("== 审计完整性 ==")
	fmt.Printf("entries=%d\n", lg.Len())
	if seq, err := lg.Verify(); seq == -1 {
		fmt.Println("verify: OK (哈希链完整)")
	} else {
		fmt.Printf("verify: BAD seq=%d %v\n", seq, err)
	}
	lg.TamperForTest(1, func(e *audit.Entry) { e.Decision = "deny" })
	if seq, err := lg.Verify(); seq != -1 {
		fmt.Printf("tamper detected at seq=%d: %v\n", seq, err)
	}
}
