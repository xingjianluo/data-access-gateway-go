package policy

// Action 表示对资源执行的操作类型。
type Action string

const (
	ActionRead   Action = "read"
	ActionExport Action = "export"
	ActionDelete Action = "delete"
)

// Effect 是单条规则命中后的判定意图。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
	// EffectMask 表示允许访问，但命中的字段需要脱敏。
	EffectMask Effect = "mask"
)

// Decision 是引擎最终对请求作出的决策。
type Decision string

const (
	// DecisionAllow 明文放行。
	DecisionAllow Decision = "allow"
	// DecisionDeny 拒绝访问。拒绝优先于放行与脱敏。
	DecisionDeny Decision = "deny"
	// DecisionMask 放行但字段级脱敏。
	DecisionMask Decision = "mask"
)

// Condition 是规则对环境/请求属性的简单条件。
// Op 支持: eq, ne, in, notin, exists。
type Condition struct {
	Key string
	Op  string
	Val any
}

// MaskRule 描述单个字段的脱敏方式。
type MaskRule struct {
	Field string
	// Method 支持: redact(整体抹除), partial(保留前后若干字符), hash。
	Method string
	Keep   int // partial 时保留的首尾字符数
}

// RetentionAction 是保留期到期后的处置方式。
type RetentionAction string

const (
	// RetentionDelete 到期后整条清除。
	RetentionDelete RetentionAction = "delete"
	// RetentionAnonymize 到期后仅匿名化指定字段，记录保留。
	RetentionAnonymize RetentionAction = "anonymize"
)

// RetentionRule 声明一类资源到期后的处置方式。
// 处置方式统一收敛在策略里，而不是由调用方在每次扫描时临时决定。
type RetentionRule struct {
	ID string
	// Resources 为资源模式，支持精确匹配与前缀 * 通配（与 Rule.Resources 同语义），
	// 因此既可以按具体资源、也可以按资源类型（如 "users/*"）分别声明处置。
	Resources []string
	Action    RetentionAction
	// AnonymizeFields 仅 Action=anonymize 时生效：匿名化哪些字段由策略决定。
	AnonymizeFields []string
	// Priority 数值越大优先级越高；多条规则命中同一资源时取优先级最高者，
	// 同优先级按 ID 升序取前者，保证解析结果稳定可复现。
	Priority int
}

// Rule 是策略内的一条规则。
type Rule struct {
	ID         string
	Effect     Effect
	Actions    []Action
	Resources  []string // 资源模式，支持精确匹配与前缀 * 通配
	Subjects   []string // 主体模式，支持精确匹配与前缀 * 通配
	Conditions []Condition
	Mask       []MaskRule // Effect=mask 时生效
	// Priority 数值越大优先级越高，用于同 Effect 间稳定排序。
	Priority int
}

// Policy 是一个不可变的策略版本。
type Policy struct {
	Version int
	Name    string
	Rules   []Rule
	// Retention 为保留期处置规则；未配置任何命中规则的资源沿用调用方指定的
	// 兜底处置（兼容旧行为）。
	Retention []RetentionRule
}

// RetentionFor 解析某资源到期后的处置方式。
// 命中多条规则时按 Priority 降序、ID 升序取第一条（与访问规则的稳定排序口径一致）；
// 未命中任何规则时返回 false，调用方按兼容逻辑走兜底处置。
func (p *Policy) RetentionFor(resource string) (RetentionRule, bool) {
	if p == nil {
		return RetentionRule{}, false
	}
	var best *RetentionRule
	for i := range p.Retention {
		r := &p.Retention[i]
		if !matchAny(resource, r.Resources) {
			continue
		}
		if best == nil ||
			r.Priority > best.Priority ||
			(r.Priority == best.Priority && r.ID < best.ID) {
			best = r
		}
	}
	if best == nil {
		return RetentionRule{}, false
	}
	return *best, true
}

// Request 是一次访问决策请求的输入。
type Request struct {
	Subject  string
	Action   Action
	Resource string
	// SubjectAttrs / ResourceAttrs / Env 为属性集合，可能缺失。
	SubjectAttrs  map[string]any
	ResourceAttrs map[string]any
	Env           map[string]any
}

// Hit 记录一条被命中的规则及其评估信息，用于稳定的判定原因与审计追溯。
type Hit struct {
	RuleID  string
	Effect  Effect
	Matched bool
	Reason  string // 命中/条件评估说明
}

// DecisionResult 是引擎评估输出。
type DecisionResult struct {
	Decision  Decision
	Version   int // 本次评估使用的策略版本（请求生命周期内固定）
	Hits      []Hit
	Reason    string // 人类可读、稳定可区分的最终判定原因
	MaskRules []MaskRule
}
