package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Engine 基于一个固定版本的策略快照进行判定。
// 快照在引擎构造时确定，因此单个请求生命周期内不会因热更新而前后不一致。
type Engine struct {
	snap *Policy
}

// NewEngine 基于给定策略快照构造引擎。
func NewEngine(p *Policy) *Engine {
	return &Engine{snap: p}
}

// Version 返回引擎绑定的策略版本。
func (e *Engine) Version() int {
	if e.snap == nil {
		return 0
	}
	return e.snap.Version
}

// Evaluate 按"拒绝优先、其次脱敏、最后放行、默认拒绝"的顺序给出决策。
//
// 冲突解决规则（稳定且可区分）：
//  1. 任意命中 deny => 拒绝（deny 永远优先于 allow/mask，即便存在冲突策略）；
//  2. 否则存在命中 mask => 脱敏放行，合并所有 mask 规则的字段；
//  3. 否则存在命中 allow => 明文放行；
//  4. 均不满足 => 默认拒绝（属性缺失导致条件无法满足时安全失败，绝不明文放行）。
func (e *Engine) Evaluate(req Request) (DecisionResult, error) {
	if e.snap == nil {
		return DecisionResult{}, fmt.Errorf("policy engine: nil policy snapshot")
	}
	res := DecisionResult{Version: e.snap.Version}

	// 稳定排序：优先级降序，ID 升序，保证冲突下结果确定可复现。
	rules := make([]Rule, len(e.snap.Rules))
	copy(rules, e.snap.Rules)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})

	var denyIDs, maskIDs, allowIDs []string
	var maskHits []Rule
	for _, r := range rules {
		ok, reason := r.matches(req)
		res.Hits = append(res.Hits, Hit{RuleID: r.ID, Effect: r.Effect, Matched: ok, Reason: reason})
		if !ok {
			continue
		}
		switch r.Effect {
		case EffectDeny:
			denyIDs = append(denyIDs, r.ID)
		case EffectMask:
			maskIDs = append(maskIDs, r.ID)
			maskHits = append(maskHits, r)
		case EffectAllow:
			allowIDs = append(allowIDs, r.ID)
		default:
			return DecisionResult{}, fmt.Errorf("policy engine: rule %s has unknown effect %q", r.ID, r.Effect)
		}
	}

	switch {
	case len(denyIDs) > 0:
		res.Decision = DecisionDeny
		res.Reason = fmt.Sprintf("denied by rule(s): %s", strings.Join(denyIDs, ","))
		return res, nil
	case len(maskIDs) > 0:
		res.Decision = DecisionMask
		res.MaskRules = mergeMaskRules(maskHits)
		fields := make([]string, 0, len(res.MaskRules))
		for _, m := range res.MaskRules {
			fields = append(fields, m.Field)
		}
		res.Reason = fmt.Sprintf("masked by rule(s): %s; masked fields: %s",
			strings.Join(maskIDs, ","), strings.Join(fields, ","))
		return res, nil
	case len(allowIDs) > 0:
		res.Decision = DecisionAllow
		res.Reason = fmt.Sprintf("allowed by rule(s): %s", strings.Join(allowIDs, ","))
		return res, nil
	default:
		res.Decision = DecisionDeny
		res.Reason = fmt.Sprintf("denied by default: no rule matched subject=%q action=%q resource=%q",
			req.Subject, req.Action, req.Resource)
		return res, nil
	}
}

// mergeMaskRules 合并多条 mask 命中：同字段以排序靠前（优先级更高）的规则为准。
func mergeMaskRules(hits []Rule) []MaskRule {
	byField := map[string]MaskRule{}
	var order []string
	for _, r := range hits {
		for _, m := range r.Mask {
			if _, exists := byField[m.Field]; exists {
				continue
			}
			byField[m.Field] = m
			order = append(order, m.Field)
		}
	}
	sort.Strings(order)
	out := make([]MaskRule, 0, len(order))
	for _, f := range order {
		out = append(out, byField[f])
	}
	return out
}

// matches 判断规则是否适用于请求，并给出稳定的说明（供审计追溯）。
// 作用域（主体/动作/资源）不匹配的规则不进入条件评估。
func (r *Rule) matches(req Request) (bool, string) {
	if !matchAny(req.Subject, r.Subjects) {
		return false, fmt.Sprintf("subject %q not in %v", req.Subject, r.Subjects)
	}
	if !actionIn(req.Action, r.Actions) {
		return false, fmt.Sprintf("action %q not in %v", req.Action, r.Actions)
	}
	if !matchAny(req.Resource, r.Resources) {
		return false, fmt.Sprintf("resource %q not in %v", req.Resource, r.Resources)
	}
	for _, c := range r.Conditions {
		if ok, detail := evalCondition(c, req); !ok {
			return false, fmt.Sprintf("condition %s failed: %s", c.Key, detail)
		}
	}
	return true, "scope and all conditions matched"
}

func actionIn(a Action, list []Action) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// matchAny 支持精确匹配与以 "*" 结尾的通配（"*" 匹配一切）。
func matchAny(v string, patterns []string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(v, prefix) {
				return true
			}
			continue
		}
		if v == p {
			return true
		}
	}
	return false
}

// attrOf 取属性值。带 "subject."/"resource."/"env." 前缀的键定位到对应属性集；
// 不带前缀则依次在主体、资源、环境属性中查找。第二个返回值表示键是否存在。
func attrOf(key string, req Request) (any, bool) {
	lookup := func(m map[string]any, k string) (any, bool) {
		if m == nil {
			return nil, false
		}
		v, ok := m[k]
		return v, ok
	}
	switch {
	case strings.HasPrefix(key, "subject."):
		return lookup(req.SubjectAttrs, strings.TrimPrefix(key, "subject."))
	case strings.HasPrefix(key, "resource."):
		return lookup(req.ResourceAttrs, strings.TrimPrefix(key, "resource."))
	case strings.HasPrefix(key, "env."):
		return lookup(req.Env, strings.TrimPrefix(key, "env."))
	default:
		if v, ok := lookup(req.SubjectAttrs, key); ok {
			return v, true
		}
		if v, ok := lookup(req.ResourceAttrs, key); ok {
			return v, true
		}
		return lookup(req.Env, key)
	}
}

// evalCondition 评估单个条件。属性缺失时条件失败（安全失败），并说明原因。
func evalCondition(c Condition, req Request) (bool, string) {
	v, present := attrOf(c.Key, req)
	switch c.Op {
	case "exists":
		if !present {
			return false, "attribute missing"
		}
		return true, "attribute present"
	case "eq", "ne", "in", "notin":
		if !present {
			return false, "attribute missing"
		}
		switch c.Op {
		case "eq":
			if equalLoose(v, c.Val) {
				return true, ""
			}
			return false, fmt.Sprintf("%v != %v", v, c.Val)
		case "ne":
			if !equalLoose(v, c.Val) {
				return true, ""
			}
			return false, fmt.Sprintf("%v == %v", v, c.Val)
		case "in":
			for _, item := range toAnySlice(c.Val) {
				if equalLoose(v, item) {
					return true, ""
				}
			}
			return false, fmt.Sprintf("%v not in %v", v, c.Val)
		case "notin":
			for _, item := range toAnySlice(c.Val) {
				if equalLoose(v, item) {
					return false, fmt.Sprintf("%v in %v", v, c.Val)
				}
			}
			return true, ""
		}
	}
	return false, fmt.Sprintf("unknown operator %q", c.Op)
}

func toAnySlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	}
	return nil
}

// equalLoose 做宽松相等：字符串/布尔直接比，数字按 float64 比（兼容 JSON 解码）。
func equalLoose(a, b any) bool {
	an, aok := toFloat(a)
	bn, bok := toFloat(b)
	if aok && bok {
		return an == bn
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}
