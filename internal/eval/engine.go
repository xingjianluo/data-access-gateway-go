package eval

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// Decision is the verdict for one request.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionMask  Decision = "mask"
)

// FieldMask records how one field was treated.
type FieldMask struct {
	Field string
	Op    policy.MaskOp
}

// Result is the evaluation output. Reasons are stable, machine-readable codes
// so callers can distinguish deny/mask/allow deterministically:
//
//	default_deny:no_matching_rule
//	denied_by_rule=<id>
//	allowed_by_rule=<id>
//	masked_by_rule=<id>
type Result struct {
	Decision      Decision
	PolicyVersion string
	Reason        string
	MatchedRules  []string
	Fields        []FieldMask
}

// Request is the authorization query.
type Request struct {
	Subject       policy.AttributeBag
	Resource      string
	Action        policy.Action
	Env           policy.AttributeBag
	ResourceAttrs policy.AttributeBag
}

// Engine evaluates requests against one fixed policy snapshot. Construct a
// new engine per policy version; a request holds one engine for its whole
// lifetime and therefore can never see mixed versions.
type Engine struct {
	policy *policy.Policy
}

// NewEngine constructs an engine bound to a policy snapshot.
func NewEngine(p *policy.Policy) *Engine {
	return &Engine{policy: p}
}

// attrValue resolves a dotted, namespace-prefixed key such as
// "subject.role" or "env.ip" against the request's attribute bags.
// The second return value reports whether the attribute exists.
func attrValue(req Request, key string) (any, bool) {
	var bag policy.AttributeBag
	switch {
	case strings.HasPrefix(key, "subject."):
		bag = req.Subject
		key = strings.TrimPrefix(key, "subject.")
	case strings.HasPrefix(key, "resource."):
		bag = req.ResourceAttrs
		key = strings.TrimPrefix(key, "resource.")
	case strings.HasPrefix(key, "env."):
		bag = req.Env
		key = strings.TrimPrefix(key, "env.")
	default:
		// Unprefixed keys are resolved against subject for backwards
		// friendliness but still require presence.
		bag = req.Subject
	}
	if bag == nil {
		return nil, false
	}
	v, ok := bag[key]
	return v, ok
}

// matchClause evaluates one AND-clause. A missing attribute always makes the
// clause false: absence can never authorize access.
func matchClause(req Request, clause policy.MatchClause) bool {
	keys := make([]string, 0, len(clause))
	for k := range clause {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		expected := clause[k]
		actual, present := attrValue(req, k)
		if !present {
			return false
		}
		if expected == nil {
			continue // presence-only check
		}
		if fmt.Sprint(actual) != fmt.Sprint(expected) {
			return false
		}
	}
	return true
}

func actionMatches(rule *policy.Rule, action policy.Action) bool {
	for _, a := range rule.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// Evaluate decides one request against the bound policy snapshot.
//
// Precedence: (1) any matching DENY rule wins over everything; the deny
// reason names the highest-priority matching deny rule. (2) Otherwise the
// highest-priority matching ALLOW/MASK rule decides; ties are broken by the
// rule's stable position in the policy. (3) No match means default deny,
// which also covers the case where attributes required by rules are absent.
func (e *Engine) Evaluate(ctx context.Context, req Request) Result {
	base := Result{PolicyVersion: e.policy.Version}

	type hit struct {
		idx  int
		rule *policy.Rule
	}
	var hits []hit
	for i := range e.policy.Rules {
		r := &e.policy.Rules[i]
		if r.Resource != req.Resource {
			continue
		}
		if !actionMatches(r, req.Action) {
			continue
		}
		if !matchClause(req, r.When) {
			continue
		}
		hits = append(hits, hit{i, r})
		base.MatchedRules = append(base.MatchedRules, r.ID)
	}

	if len(hits) == 0 {
		base.Decision = DecisionDeny
		base.Reason = "default_deny:no_matching_rule"
		return base
	}

	// Highest priority wins; stable tie-break: earlier rule index.
	sort.SliceStable(hits, func(a, b int) bool {
		if hits[a].rule.Priority != hits[b].rule.Priority {
			return hits[a].rule.Priority > hits[b].rule.Priority
		}
		return hits[a].idx < hits[b].idx
	})

	// DENY always wins even if an allow/mask rule has higher priority.
	var topDeny *policy.Rule
	for _, h := range hits {
		if h.rule.Effect == policy.EffectDeny {
			if topDeny == nil || h.rule.Priority > topDeny.Priority {
				topDeny = h.rule
			}
		}
	}
	if topDeny != nil {
		base.Decision = DecisionDeny
		base.Reason = "denied_by_rule=" + topDeny.ID
		return base
	}

	winner := hits[0].rule
	switch winner.Effect {
	case policy.EffectMask:
		base.Decision = DecisionMask
		base.Reason = "masked_by_rule=" + winner.ID
		for _, f := range winner.Fields {
			base.Fields = append(base.Fields, FieldMask{Field: f.Field, Op: f.Op})
		}
		return base
	default:
		base.Decision = DecisionAllow
		base.Reason = "allowed_by_rule=" + winner.ID
		return base
	}
}
