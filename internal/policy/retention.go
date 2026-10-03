package policy

import "sort"

// RetentionFor 在策略快照中解析某资源到期后的处置规则。
// 多条规则命中时按 Priority 降序、ID 升序取第一条，结果稳定可复现。
// 返回 false 表示该资源未配置保留期策略，调用方应沿用兜底处置（兼容旧行为）。
func (p *Policy) RetentionFor(resource string) (RetentionRule, bool) {
	if p == nil {
		return RetentionRule{}, false
	}
	rules := make([]RetentionRule, 0, len(p.Retention))
	for _, r := range p.Retention {
		if matchAny(resource, r.Resources) {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return RetentionRule{}, false
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	return rules[0], true
}
