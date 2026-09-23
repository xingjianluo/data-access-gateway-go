package policy

import (
	"testing"
)

// evalLog 打印测试输入、每条规则命中情况与最终判定依据。
func evalLog(t *testing.T, p *Policy, req Request) DecisionResult {
	t.Helper()
	dr, err := NewEngine(p).Evaluate(req)
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	t.Logf("INPUT   : subject=%q action=%q resource=%q sAttrs=%v rAttrs=%v env=%v",
		req.Subject, req.Action, req.Resource, req.SubjectAttrs, req.ResourceAttrs, req.Env)
	for _, h := range dr.Hits {
		t.Logf("  RULE  : id=%s effect=%s matched=%-5v because: %s", h.RuleID, h.Effect, h.Matched, h.Reason)
	}
	t.Logf("DECISION: %s (policy v%d) REASON: %s", dr.Decision, dr.Version, dr.Reason)
	return dr
}

func TestEvaluate_AllowDenyMaskAndDefault(t *testing.T) {
	p := &Policy{Version: 1, Rules: []Rule{
		{ID: "allow-all", Effect: EffectAllow, Actions: []Action{ActionRead},
			Subjects: []string{"user:*"}, Resources: []string{"users/*"}, Priority: 10},
		{ID: "mask-email", Effect: EffectMask, Actions: []Action{ActionRead},
			Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			Mask: []MaskRule{{Field: "email", Method: "partial", Keep: 1}}, Priority: 20},
		{ID: "deny-finance", Effect: EffectDeny, Actions: []Action{ActionRead},
			Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			Conditions: []Condition{{Key: "subject.dept", Op: "eq", Val: "finance"}}, Priority: 30},
	}}

	// 普通用户 -> mask（高优先级 mask 优先于 allow）
	masked := evalLog(t, p, Request{Subject: "user:1001", Action: ActionRead, Resource: "users/1",
		SubjectAttrs: map[string]any{"dept": "eng"}})
	if masked.Decision != DecisionMask {
		t.Fatalf("want mask, got %s", masked.Decision)
	}
	if masked.MaskRules[0].Field != "email" {
		t.Fatalf("want email masked, got %+v", masked.MaskRules)
	}

	// finance 部门 -> 即使同时命中 allow 与 mask，deny 优先
	denied := evalLog(t, p, Request{Subject: "user:1002", Action: ActionRead, Resource: "users/1",
		SubjectAttrs: map[string]any{"dept": "finance"}})
	if denied.Decision != DecisionDeny {
		t.Fatalf("want deny, got %s", denied.Decision)
	}
	if denied.Reason == masked.Reason || denied.Reason == "" {
		t.Fatalf("deny reason must be distinct and stable, got %q", denied.Reason)
	}

	// 越权：未在任何主体/资源作用域内 -> 默认拒绝
	out := evalLog(t, p, Request{Subject: "anonymous", Action: ActionRead, Resource: "users/1"})
	if out.Decision != DecisionDeny {
		t.Fatalf("unauthorized subject must be denied, got %s", out.Decision)
	}
	if out.Reason != "denied by default: no rule matched subject=\"anonymous\" action=\"read\" resource=\"users/1\"" {
		t.Fatalf("unexpected default-deny reason: %q", out.Reason)
	}
}

func TestEvaluate_MissingAttributeFailsClosed(t *testing.T) {
	p := &Policy{Version: 7, Rules: []Rule{
		{ID: "allow-mfa", Effect: EffectAllow, Actions: []Action{ActionRead},
			Subjects: []string{"*"}, Resources: []string{"*"},
			Conditions: []Condition{{Key: "env.mfa", Op: "eq", Val: true}}},
	}}
	// 属性缺失：安全失败，绝不明文放行
	dr := evalLog(t, p, Request{Subject: "user:1", Action: ActionRead, Resource: "r/1"})
	if dr.Decision != DecisionDeny {
		t.Fatalf("missing attribute must fail closed, got %s", dr.Decision)
	}
	// 条件满足时才放行
	ok := evalLog(t, p, Request{Subject: "user:1", Action: ActionRead, Resource: "r/1",
		Env: map[string]any{"mfa": true}})
	if ok.Decision != DecisionAllow {
		t.Fatalf("mfa=true should allow, got %s", ok.Decision)
	}
}

func TestEvaluate_ConflictDenyAlwaysWins(t *testing.T) {
	// deny 优先级数值最低，仍必须压过 allow/mask（冲突解决基于 effect 而非优先级）
	p := &Policy{Version: 2, Rules: []Rule{
		{ID: "a", Effect: EffectAllow, Priority: 100, Subjects: []string{"*"},
			Actions: []Action{ActionRead}, Resources: []string{"*"}},
		{ID: "m", Effect: EffectMask, Priority: 90, Subjects: []string{"*"},
			Actions: []Action{ActionRead}, Resources: []string{"*"},
			Mask: []MaskRule{{Field: "ssn", Method: "redact"}}},
		{ID: "d", Effect: EffectDeny, Priority: 1, Subjects: []string{"*"},
			Actions: []Action{ActionRead}, Resources: []string{"*"},
			Conditions: []Condition{{Key: "env.region", Op: "in", Val: []string{"cn", "ru"}}}},
	}}
	dr := evalLog(t, p, Request{Subject: "u", Action: ActionRead, Resource: "r",
		Env: map[string]any{"region": "cn"}})
	if dr.Decision != DecisionDeny {
		t.Fatalf("deny must win conflict, got %s", dr.Decision)
	}

	dr2 := evalLog(t, p, Request{Subject: "u", Action: ActionRead, Resource: "r",
		Env: map[string]any{"region": "us"}})
	if dr2.Decision != DecisionMask {
		t.Fatalf("non-blocked region should fall through to mask, got %s", dr2.Decision)
	}
}

func TestStore_PublishAndSnapshotImmutable(t *testing.T) {
	s := NewStore()
	p := &Policy{Version: 1, Rules: []Rule{{ID: "r1", Effect: EffectAllow,
		Actions: []Action{ActionRead}, Subjects: []string{"*"}, Resources: []string{"*"}}}}
	if err := s.Publish(p); err != nil {
		t.Fatal(err)
	}
	// 发布后篡改原对象，不应影响已发布快照
	p.Rules[0].Effect = EffectDeny
	p.Version = 99
	snap, err := s.Snapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Rules[0].Effect != EffectAllow {
		t.Fatal("published snapshot must be immutable")
	}
	// 版本必须单调递增
	if err := s.Publish(&Policy{Version: 1}); err == nil {
		t.Fatal("duplicate version must be rejected")
	}
	if err := s.Publish(&Policy{Version: 0}); err == nil {
		t.Fatal("non-increasing version must be rejected")
	}
}
