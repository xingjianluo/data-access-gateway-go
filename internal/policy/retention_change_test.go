package policy

import (
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

// retentionLog 打印资源名、解析出的处置方式与判定依据（命中规则 / 兜底）。
func retentionLog(t *testing.T, p *Policy, resource string) (RetentionRule, bool) {
	t.Helper()
	rule, ok := p.RetentionFor(resource)
	if ok {
		t.Logf("RETENTION resource=%q -> rule=%s action=%s fields=%v priority=%d",
			resource, rule.ID, rule.Action, rule.AnonymizeFields, rule.Priority)
	} else {
		t.Logf("RETENTION resource=%q -> no rule matched, caller fallback applies", resource)
	}
	return rule, ok
}

func TestRetentionFor_PerResourceAndPerType(t *testing.T) {
	p := &Policy{Version: 1, Name: "ret", Retention: []RetentionRule{
		// 资源类型级：users/* 到期匿名化 email/ssn
		{ID: "rt-users-anon", Resources: []string{"users/*"}, Action: RetentionAnonymize,
			AnonymizeFields: []string{"email", "ssn"}, Priority: 10},
		// 具体资源级：users/1 到期整条清除（优先级更高，覆盖类型级规则）
		{ID: "rt-users1-delete", Resources: []string{"users/1"}, Action: RetentionDelete, Priority: 20},
		// 另一个类型：logs/* 到期整条清除
		{ID: "rt-logs-delete", Resources: []string{"logs/*"}, Action: RetentionDelete, Priority: 10},
	}}

	r, ok := retentionLog(t, p, "users/1")
	if !ok || r.Action != RetentionDelete || r.ID != "rt-users1-delete" {
		t.Fatalf("users/1 must resolve to delete via exact rule, got %+v ok=%v", r, ok)
	}
	r, ok = retentionLog(t, p, "users/2")
	if !ok || r.Action != RetentionAnonymize || len(r.AnonymizeFields) != 2 {
		t.Fatalf("users/2 must resolve to anonymize [email ssn], got %+v ok=%v", r, ok)
	}
	r, ok = retentionLog(t, p, "logs/9")
	if !ok || r.Action != RetentionDelete {
		t.Fatalf("logs/9 must resolve to delete, got %+v ok=%v", r, ok)
	}
	if _, ok = retentionLog(t, p, "orders/1"); ok {
		t.Fatal("orders/1 has no retention rule; must fall back to caller default")
	}
}

func TestRetentionFor_StableTieBreak(t *testing.T) {
	// 同优先级命中多条：按 ID 升序取前者，结果与规则书写顺序无关
	mk := func(order []RetentionRule) *Policy {
		return &Policy{Version: 1, Retention: order}
	}
	a := RetentionRule{ID: "rt-a", Resources: []string{"users/*"}, Action: RetentionDelete, Priority: 5}
	b := RetentionRule{ID: "rt-b", Resources: []string{"users/*"}, Action: RetentionAnonymize, Priority: 5}
	r1, _ := retentionLog(t, mk([]RetentionRule{a, b}), "users/1")
	r2, _ := retentionLog(t, mk([]RetentionRule{b, a}), "users/1")
	if r1.ID != "rt-a" || r2.ID != "rt-a" {
		t.Fatalf("tie must break by ascending ID deterministically, got %s / %s", r1.ID, r2.ID)
	}
}

func TestPublish_RecordsChangeHistoryAndAudit(t *testing.T) {
	lg := audit.NewLog()
	s := NewStore()
	s.AttachAudit(lg)

	if err := s.Publish(&Policy{Version: 1, Name: "base", Rules: []Rule{
		{ID: "allow-read", Effect: EffectAllow},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(&Policy{Version: 2, Name: "base", Rules: []Rule{
		{ID: "allow-read", Effect: EffectAllow},
		{ID: "mask-pii", Effect: EffectMask},
	}, Retention: []RetentionRule{
		{ID: "rt-users", Resources: []string{"users/*"}, Action: RetentionDelete},
	}}); err != nil {
		t.Fatal(err)
	}

	changes := s.Changes()
	if len(changes) != 2 {
		t.Fatalf("want 2 change records, got %d", len(changes))
	}
	for _, c := range changes {
		t.Logf("CHANGE seq=%d time=%s v%d->v%d rules=%v retention=%v",
			c.Seq, c.Time.Format("15:04:05.000"), c.FromVersion, c.ToVersion, c.RuleIDs, c.RetentionIDs)
	}
	if changes[0].FromVersion != 0 || changes[0].ToVersion != 1 {
		t.Fatalf("first install must be 0->1, got %d->%d", changes[0].FromVersion, changes[0].ToVersion)
	}
	if changes[1].FromVersion != 1 || changes[1].ToVersion != 2 {
		t.Fatalf("switch must be 1->2, got %d->%d", changes[1].FromVersion, changes[1].ToVersion)
	}
	if changes[1].RuleIDs[1] != "mask-pii" || changes[1].RetentionIDs[0] != "rt-users" {
		t.Fatalf("change record must carry rule summary, got %+v", changes[1])
	}

	// 顺藤摸瓜：由版本号找到它是何时、怎么装进来的
	c, ok := s.ChangeForVersion(2)
	if !ok || c.ToVersion != 2 || c.FromVersion != 1 || c.Time.IsZero() {
		t.Fatalf("ChangeForVersion(2) must trace install of v2, got %+v ok=%v", c, ok)
	}
	t.Logf("TRACE v2 installed at %s summary=%q", c.Time.Format("15:04:05.000"), c.Summary)

	// 每次发布都有一条不可篡改审计，且被哈希链完整性校验覆盖
	entries := lg.Entries()
	if len(entries) != 2 {
		t.Fatalf("each publish must append one audit entry, got %d", len(entries))
	}
	for _, e := range entries {
		t.Logf("AUDIT  seq=%d action=%s policy_version=%d reason=%q", e.Seq, e.Action, e.PolicyVer, e.Reason)
		if e.Action != "policy.publish" {
			t.Fatalf("policy change must be audited as policy.publish, got %q", e.Action)
		}
	}
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain with policy changes must verify, badSeq=%d err=%v", seq, err)
	}

	// 篡改策略变更记录（改写来源版本）必须被完整性校验检出
	if !lg.TamperForTest(entries[1].Seq, func(e *audit.Entry) { e.Detail = "from_version=0 to_version=2" }) {
		t.Fatal("tamper target missing")
	}
	seq, err := lg.Verify()
	if seq != entries[1].Seq {
		t.Fatalf("tampered policy change must be detected at seq %d, got seq=%d err=%v", entries[1].Seq, seq, err)
	}
	t.Logf("TAMPER detected at seq=%d: %v", seq, err)
}

func TestPublish_DeepCopiesRetentionRules(t *testing.T) {
	s := NewStore()
	p := &Policy{Version: 1, Retention: []RetentionRule{
		{ID: "rt-users", Resources: []string{"users/*"}, Action: RetentionAnonymize, AnonymizeFields: []string{"email"}},
	}}
	if err := s.Publish(p); err != nil {
		t.Fatal(err)
	}
	// 发布后再改原对象，已发布版本不得受影响
	p.Retention[0].Action = RetentionDelete
	p.Retention[0].AnonymizeFields[0] = "ssn"
	snap, _ := s.Snapshot(1)
	r, ok := snap.RetentionFor("users/1")
	if !ok || r.Action != RetentionAnonymize || r.AnonymizeFields[0] != "email" {
		t.Fatalf("published retention rule must be isolated from caller mutation, got %+v", r)
	}
	t.Logf("ISOLATION ok: published rule stays anonymize[email] after caller mutated source")
}
