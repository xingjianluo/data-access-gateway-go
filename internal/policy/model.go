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

// RetentionAction 是保留期到期后的处置方式。
type RetentionAction string

const (
	// RetentionDelete 到期后整条清除。
	RetentionDelete RetentionAction = "delete"
	// RetentionAnonymize 到期后仅匿名化指定字段，记录保留。
	RetentionAnonymize RetentionAction = "anonymize"
)

// RetentionRule 声明某类资源到期后的处置方式。
// 到期时刻本身由数据记录上的 RetainUntil 决定，本规则只决定"到期之后怎么处置"。
type RetentionRule struct {
	ID string
	// Resources 为资源模式，支持精确匹配与前缀 * 通配（与访问规则同一口径），
	// 因此既可按具体资源也可按资源类型（前缀）声明。
	Resources []string
	Action    RetentionAction
	// Fields 仅 Action=anonymize 时生效：匿名化哪些字段由策略决定。
	Fields []string
	// Priority 数值越大优先级越高；多条规则命中同一资源时取优先级最高者。
	Priority int
}

// Policy 是一个不可变的策略版本。
type Policy struct {
	Version int
	Name    string
	Rules   []Rule
	// Retention 为保留期处置规则；为空的资源沿用调用方指定的兜底处置（兼容旧行为）。
	Retention []RetentionRule
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
