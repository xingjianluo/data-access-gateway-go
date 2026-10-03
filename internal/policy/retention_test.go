package policy

import "testing"

// TestRetentionFor_PerResourceAndType 覆盖：按具体资源与按资源类型（前缀通配）
// 分别声明不同处置方式；同资源多规则命中时按优先级稳定裁决。
func TestRetentionFor_PerResourceAndType(t *testing.T) {
	p := &Policy{
		Version: 1,
		Retention: []RetentionRule{
			{ID: "anon-users", Resources: []string{"users/*"}, Action: RetentionAnonymize, Fields: []string{"email", "ssn"}, Priority: 10},
			{ID: "delete-logs", Resources: []string{"logs/*"}, Action: RetentionDelete, Priority: 10},
			{ID: "delete-vip", Resources: []string{"users/vip-1"}, Action: RetentionDelete, Priority: 20},
		},
	}

	cases := []struct {
		resource   string
		wantOK     bool
		wantAction RetentionAction
		wantFields []string
		wantRule   string
	}{
		{"users/1", true, RetentionAnonymize, []string{"email", "ssn"}, "anon-users"},
		{"users/vip-1", true, RetentionDelete, nil, "delete-vip"}, // 精确规则优先级更高，覆盖类型规则
		{"logs/2026-10", true, RetentionDelete, nil, "delete-logs"},
		{"orders/1", false, "", nil, ""}, // 未配置：调用方走兜底
	}
	for _, c := range cases {
		rule, ok := p.RetentionFor(c.resource)
		t.Logf("resource=%q -> matched=%t rule=%q action=%q fields=%v", c.resource, ok, rule.ID, rule.Action, rule.Fields)
		if ok != c.wantOK {
			t.Fatalf("resource %s: matched=%t want %t", c.resource, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if rule.Action != c.wantAction || rule.ID != c.wantRule {
			t.Fatalf("resource %s: got rule %s action %s, want rule %s action %s",
				c.resource, rule.ID, rule.Action, c.wantRule, c.wantAction)
		}
		if len(rule.Fields) != len(c.wantFields) {
			t.Fatalf("resource %s: fields=%v want %v", c.resource, rule.Fields, c.wantFields)
		}
		for i := range rule.Fields {
			if rule.Fields[i] != c.wantFields[i] {
				t.Fatalf("resource %s: fields=%v want %v", c.resource, rule.Fields, c.wantFields)
			}
		}
	}
}

// TestRetentionFor_StableTieBreak 同优先级多条命中时按 ID 升序取第一条，结果可复现。
func TestRetentionFor_StableTieBreak(t *testing.T) {
	p := &Policy{Version: 1, Retention: []RetentionRule{
		{ID: "b-rule", Resources: []string{"r*"}, Action: RetentionDelete, Priority: 5},
		{ID: "a-rule", Resources: []string{"r*"}, Action: RetentionAnonymize, Fields: []string{"x"}, Priority: 5},
	}}
	rule, ok := p.RetentionFor("r1")
	t.Logf("tie-break: matched rule=%q (两规则同优先级，按 ID 升序应取 a-rule)", rule.ID)
	if !ok || rule.ID != "a-rule" {
		t.Fatalf("tie-break got %q, want a-rule", rule.ID)
	}
}

// TestRetentionFor_NilOrEmpty 无策略/未配置保留期规则时返回未命中。
func TestRetentionFor_NilOrEmpty(t *testing.T) {
	var nilPol *Policy
	if _, ok := nilPol.RetentionFor("users/1"); ok {
		t.Fatal("nil policy should not match")
	}
	empty := &Policy{Version: 1}
	if _, ok := empty.RetentionFor("users/1"); ok {
		t.Fatal("policy without retention rules should not match")
	}
	t.Log("nil policy 与空 Retention 均判定为未命中 -> 调用方沿用兜底处置")
}
