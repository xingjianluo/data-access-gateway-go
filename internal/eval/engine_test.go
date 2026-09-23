package eval

import (
	"context"
	"log"
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// debugEval logs test inputs, matched rules and the decision basis, as
// required for auditability of the unit-test trace.
func debugEval(t *testing.T, name string, req Request, res Result) {
	t.Helper()
	log.Printf("[%s] INPUT subject=%v resource=%s action=%s env=%v resAttrs=%v",
		name, req.Subject, req.Resource, req.Action, req.Env, req.ResourceAttrs)
	log.Printf("[%s] MATCHED_RULES=%v", name, res.MatchedRules)
	log.Printf("[%s] DECISION=%s VERSION=%s REASON=%s FIELDS=%v",
		name, res.Decision, res.PolicyVersion, res.Reason, res.Fields)
}

func conflictPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "p-conflict-1",
		Rules: []policy.Rule{
			{ID: "deny-outside", Name: "deny external access", Effect: policy.EffectDeny,
				Resource: "patient_record", Actions: []policy.Action{policy.ActionRead},
				When: policy.MatchClause{"env.network": "external"}, Priority: 50},
			{ID: "mask-analyst", Name: "analyst sees masked phi", Effect: policy.EffectMask,
				Resource: "patient_record", Actions: []policy.Action{policy.ActionRead},
				When: policy.MatchClause{"subject.role": "analyst"}, Priority: 20,
				Fields: []policy.FieldRule{{Field: "diagnosis", Op: policy.MaskRedact}, {Field: "ssn", Op: policy.MaskPartial}}},
			{ID: "allow-doctor", Name: "doctor full access", Effect: policy.EffectAllow,
				Resource: "patient_record", Actions: []policy.Action{policy.ActionRead},
				When: policy.MatchClause{"subject.role": "doctor"}, Priority: 10},
			// Conflicting rule: explicitly denies doctors when MFA absent.
			{ID: "deny-no-mfa", Name: "deny without mfa", Effect: policy.EffectDeny,
				Resource: "patient_record", Actions: []policy.Action{policy.ActionRead},
				When: policy.MatchClause{"subject.role": "doctor", "env.mfa": false}, Priority: 5},
		},
	}
}

func TestUnauthorizedAccessIsDenied(t *testing.T) {
	e := NewEngine(conflictPolicy())
	req := Request{
		Subject:  policy.AttributeBag{"id": "u-99", "role": "guest"},
		Resource: "patient_record",
		Action:   policy.ActionRead,
		Env:      policy.AttributeBag{"network": "internal", "mfa": true},
	}
	res := e.Evaluate(context.Background(), req)
	debugEval(t, "unauthorized-guest", req, res)
	if res.Decision != DecisionDeny || res.Reason != "default_deny:no_matching_rule" {
		t.Fatalf("guest must be default-denied, got %s (%s)", res.Decision, res.Reason)
	}
}

func TestMissingAttributeNeverAuthorizes(t *testing.T) {
	e := NewEngine(conflictPolicy())
	// env.network and env.mfa absent; analyst rule still matches but the
	// key invariant is: a deny rule requiring an attribute must NOT fire on
	// absence and absence must not be misread as a matching value.
	req := Request{
		Subject:  policy.AttributeBag{"id": "u-1", "role": "doctor"},
		Resource: "patient_record",
		Action:   policy.ActionRead,
		Env:      policy.AttributeBag{},
	}
	res := e.Evaluate(context.Background(), req)
	debugEval(t, "missing-attrs", req, res)
	if res.Decision != DecisionAllow || res.Reason != "allowed_by_rule=allow-doctor" {
		t.Fatalf("doctor without env attrs: deny-no-mfa must not fire on missing mfa, got %s (%s)", res.Decision, res.Reason)
	}

	// mfa explicitly false -> deny rule fires and beats the allow.
	req2 := req
	req2.Env = policy.AttributeBag{"mfa": false}
	res2 := e.Evaluate(context.Background(), req2)
	debugEval(t, "mfa-false-conflict", req2, res2)
	if res2.Decision != DecisionDeny || res2.Reason != "denied_by_rule=deny-no-mfa" {
		t.Fatalf("deny must win over allow on conflict, got %s (%s)", res2.Decision, res2.Reason)
	}
}

func TestDenyWinsOverMaskAndAllow(t *testing.T) {
	e := NewEngine(conflictPolicy())
	// Analyst would be masked, but external network triggers deny: deny wins.
	req := Request{
		Subject:  policy.AttributeBag{"id": "u-2", "role": "analyst"},
		Resource: "patient_record",
		Action:   policy.ActionRead,
		Env:      policy.AttributeBag{"network": "external", "mfa": true},
	}
	res := e.Evaluate(context.Background(), req)
	debugEval(t, "deny-over-mask", req, res)
	if res.Decision != DecisionDeny || res.Reason != "denied_by_rule=deny-outside" {
		t.Fatalf("deny must win over mask, got %s (%s)", res.Decision, res.Reason)
	}
}

func TestMaskDecisionCarriesFields(t *testing.T) {
	e := NewEngine(conflictPolicy())
	req := Request{
		Subject:  policy.AttributeBag{"id": "u-3", "role": "analyst"},
		Resource: "patient_record",
		Action:   policy.ActionRead,
		Env:      policy.AttributeBag{"network": "internal", "mfa": true},
	}
	res := e.Evaluate(context.Background(), req)
	debugEval(t, "analyst-mask", req, res)
	if res.Decision != DecisionMask || res.Reason != "masked_by_rule=mask-analyst" {
		t.Fatalf("analyst must be masked, got %s (%s)", res.Decision, res.Reason)
	}
	if len(res.Fields) != 2 {
		t.Fatalf("expected 2 masked fields, got %d", len(res.Fields))
	}
}

func TestUnknownResourceAndActionDefaultDeny(t *testing.T) {
	e := NewEngine(conflictPolicy())
	req := Request{
		Subject:  policy.AttributeBag{"id": "u-1", "role": "doctor"},
		Resource: "billing_record",
		Action:   policy.ActionRead,
		Env:      policy.AttributeBag{"mfa": true},
	}
	res := e.Evaluate(context.Background(), req)
	debugEval(t, "unknown-resource", req, res)
	if res.Decision != DecisionDeny {
		t.Fatalf("unknown resource default deny, got %s", res.Decision)
	}
}
