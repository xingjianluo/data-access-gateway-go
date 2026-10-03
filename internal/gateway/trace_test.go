package gateway

import (
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

func TestTracePolicy_FollowsVersionToChangeRecord(t *testing.T) {
	ps := policy.NewStore()
	ds := data.NewStore(2)
	lg := audit.NewLog()
	ps.AttachAudit(lg) // 策略变更与访问审计进同一条哈希链
	ds.Put(data.Record{ID: "users/1", SubjectID: "subj-1", Resource: "users/1",
		Data: map[string]any{"name": "alice"}})
	gw := New(ps, ds, lg)

	ps.Publish(&policy.Policy{Version: 1, Name: "base", Rules: []policy.Rule{
		{ID: "allow-read", Effect: policy.EffectAllow,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})
	if _, err := gw.Access(AccessInput{RequestID: "req-v1", Request: policy.Request{
		Subject: "user:1", Action: policy.ActionRead, Resource: "users/1"}}); err != nil {
		t.Fatal(err)
	}

	ps.Publish(&policy.Policy{Version: 2, Name: "base", Rules: []policy.Rule{
		{ID: "deny-read", Effect: policy.EffectDeny,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})
	if _, err := gw.Access(AccessInput{RequestID: "req-v2", Request: policy.Request{
		Subject: "user:1", Action: policy.ActionRead, Resource: "users/1"}}); err != nil {
		t.Fatal(err)
	}

	// 由 req-v1 的审计结论顺藤摸瓜：v1 是首次安装（0->1）
	tr1, err := gw.TracePolicy("req-v1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TRACE req-v1: decision=%s version=%d <- change=%d->%d at %s summary=%q",
		tr1.Decision, tr1.PolicyVer, tr1.Change.FromVersion, tr1.Change.ToVersion,
		tr1.Change.Time.Format("15:04:05.000"), tr1.Change.Summary)
	if tr1.PolicyVer != 1 || !tr1.ChangeFound || tr1.Change.FromVersion != 0 || tr1.Change.ToVersion != 1 {
		t.Fatalf("req-v1 must trace to install of v1, got %+v", tr1)
	}

	// req-v2 用的是 v2，能追到 1->2 的切换记录
	tr2, err := gw.TracePolicy("req-v2")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TRACE req-v2: decision=%s version=%d <- change=%d->%d summary=%q",
		tr2.Decision, tr2.PolicyVer, tr2.Change.FromVersion, tr2.Change.ToVersion, tr2.Change.Summary)
	if tr2.PolicyVer != 2 || !tr2.ChangeFound || tr2.Change.FromVersion != 1 || tr2.Change.RuleIDs[0] != "deny-read" {
		t.Fatalf("req-v2 must trace to switch 1->2 with rule summary, got %+v", tr2)
	}

	// 策略变更条目与访问条目在同一条链上，完整性校验一并覆盖
	var kinds []string
	for _, e := range lg.Entries() {
		kinds = append(kinds, e.Action)
	}
	t.Logf("AUDIT chain actions=%v", kinds)
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("chain covering policy changes and accesses must verify, badSeq=%d err=%v", seq, err)
	}

	if _, err := gw.TracePolicy("req-missing"); err == nil {
		t.Fatal("unknown request id must return an explicit error")
	}
}
