package policy

// Action describes the operation type on a resource.
type Action string

const (
	ActionRead   Action = "read"
	ActionExport Action = "export"
	ActionDelete Action = "delete"
)

// RuleEffect determines what a matching rule does.
type RuleEffect string

const (
	EffectDeny    RuleEffect = "deny"
	EffectAllow   RuleEffect = "allow"
	EffectMask    RuleEffect = "mask"
)

// AttributeBag holds subject / resource / environment attributes.
type AttributeBag map[string]any

// MatchClause is a small attribute-matching DSL: all entries must hold
// (logical AND). A value of nil means "attribute must be present".
type MatchClause map[string]any

// MaskOp is the field masking algorithm.
type MaskOp string

const (
	MaskRedact   MaskOp = "redact"   // replace with fixed token
	MaskHash     MaskOp = "hash"     // keyed SHA-256 truncation
	MaskPartial  MaskOp = "partial"  // keep prefix/suffix, mask middle
)

// FieldRule masks one record field when the enclosing rule matches.
type FieldRule struct {
	Field string
	Op    MaskOp
}

// Rule is a single policy rule.
type Rule struct {
	ID       string
	Name     string
	Effect   RuleEffect
	Resource string
	Actions  []Action
	When     MatchClause
	Fields   []FieldRule
	Priority int // higher wins; deny always wins regardless
}

// Policy is an immutable, versioned set of rules.
type Policy struct {
	Version   string
	Rules     []Rule
	CreatedAt string
}

// RetentionRule defines a retention duration per resource type.
type RetentionRule struct {
	Resource      string
	TTLSeconds    int64
	OnExpiry      string // "delete" or "anonymize"
	AnonymizeWith []FieldRule
}

// String returns the policy version for stable logging.
func (p *Policy) String() string { return "policy@" + p.Version }
