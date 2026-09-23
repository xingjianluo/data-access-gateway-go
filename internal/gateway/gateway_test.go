package gateway

import (
	"context"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

func testPolicy(v string, analystEffect policy.RuleEffect) *policy.Policy {
	return &policy.Policy{
		Version: v,
		Rules: []policy.Rule{
			{ID: "allow-doctor", Effect: policy.EffectAllow, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead, policy.ActionExport},
				When:    policy.MatchClause{"subject.role": "doctor"}, Priority: 10},
			{ID: "mask-analyst", Effect: analystEffect, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead}, Priority: 20,
				When: policy.MatchClause{"subject.role": "analyst"},
				Fields: []policy.FieldRule{{Field: "diagnosis", Op: policy.MaskRedact},
					{Field: "ssn", Op: policy.MaskPartial}}},
			{ID: "deny-guest", Effect: policy.EffectDeny, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead},
				When:    policy.MatchClause{"subject.role": "guest"}, Priority: 100},
		},
	}
}

func newHarness(t *testing.T, p *policy.Policy) (*Gateway, *audit.Log) {
	t.Helper()
	st := store.New(3)
	if _, err := st.Put(context.Background(), store.Record{
		ID: "rec-1", Resource: "patient_record", SubjectID: "s-1",
		Data:      map[string]any{"name": "Alice", "diagnosis": "flu", "ssn": "123-45-6789"},
		CreatedAt: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	al := audit.NewAuditLog()
	gw := New(policy.NewStore(p), st, al)
	return gw, al
}

func debugResp(t *testing.T, name string, o AccessOptions, r *AccessResponse) {
	t.Helper()
	log.Printf("[%s] INPUT subj=%s attrs=%v resource=%s record=%s action=%s",
		name, o.SubjectID, o.Subject, o.Resource, o.RecordID, o.Action)
	log.Printf("[%s] VERDICT denied=%v masked=%v allowed=%v reason=%s policy=%s rules=%v",
		name, r.Denied, r.Masked, r.Allowed, r.Reason, r.PolicyVersion, r.MatchedRules)
	if r.MaskedData != nil {
		log.Printf("[%s] MASKED_DATA=%v", name, r.MaskedData)
	}
}

func TestAccessDenyNeverReturnsPlaintext(t *testing.T) {
	gw, _ := newHarness(t, testPolicy("v1", policy.EffectMask))
	o := AccessOptions{
		SubjectID: "s-1", Resource: "patient_record", RecordID: "rec-1",
		Action: policy.ActionRead, Subject: policy.AttributeBag{"role": "guest"},
		Env: policy.AttributeBag{"network": "internal"},
	}
	r, err := gw.Access(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	debugResp(t, "deny-guest", o, r)
	if !r.Denied || r.Record != nil || r.MaskedData != nil {
		t.Fatalf("deny must return no record/plaintext, got record=%v masked=%v", r.Record, r.MaskedData)
	}
	if r.Reason != "denied_by_rule=deny-guest" {
		t.Fatalf("unexpected reason: %s", r.Reason)
	}
}

func TestAccessMaskRedactsFields(t *testing.T) {
	gw, _ := newHarness(t, testPolicy("v1", policy.EffectMask))
	o := AccessOptions{
		SubjectID: "s-1", Resource: "patient_record", RecordID: "rec-1",
		Action: policy.ActionRead, Subject: policy.AttributeBag{"role": "analyst"},
	}
	r, err := gw.Access(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	debugResp(t, "mask-analyst", o, r)
	if !r.Masked {
		t.Fatal("expected mask verdict")
	}
	if r.MaskedData["diagnosis"] != "[REDACTED]" {
		t.Fatalf("diagnosis must be redacted, got %v", r.MaskedData["diagnosis"])
	}
	if r.MaskedData["ssn"] == "123-45-6789" {
		t.Fatalf("ssn must be masked, got plaintext %v", r.MaskedData["ssn"])
	}
	if r.MaskedData["name"] != "Alice" {
		t.Fatalf("unmasked field should pass through, got %v", r.MaskedData["name"])
	}
	// Plaintext exists server-side but verdict distinguishes serving path.
	if r.Record.Data["diagnosis"] != "flu" {
		t.Fatal("server record metadata must remain intact for mask")
	}
}

func TestAccessAllowServesPlaintext(t *testing.T) {
	gw, _ := newHarness(t, testPolicy("v1", policy.EffectMask))
	o := AccessOptions{
		SubjectID: "s-1", Resource: "patient_record", RecordID: "rec-1",
		Action: policy.ActionRead, Subject: policy.AttributeBag{"role": "doctor"},
	}
	r, err := gw.Access(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	debugResp(t, "allow-doctor", o, r)
	if !r.Allowed || r.Record.Data["ssn"] != "123-45-6789" {
		t.Fatalf("doctor must see plaintext, got %+v", r)
	}
}

func TestCrossSubjectAccessIsRejected(t *testing.T) {
	gw, _ := newHarness(t, testPolicy("v1", policy.EffectMask))
	// Authorized doctor but claiming a different subject id than the record.
	o := AccessOptions{
		SubjectID: "s-other", Resource: "patient_record", RecordID: "rec-1",
		Action: policy.ActionRead, Subject: policy.AttributeBag{"role": "doctor"},
	}
	r, err := gw.Access(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	debugResp(t, "owner-mismatch", o, r)
	if !r.Denied || r.Reason != "default_deny:record_owner_mismatch" {
		t.Fatalf("cross-subject fetch must be denied, got %+v", r)
	}
}

// TestHotReloadConsistency drives concurrent access and policy hot-reloads.
// Every single response must be self-consistent: the reason must reference
// a rule of the exact policy version recorded on that same response, and
// denied responses must never carry data.
func TestHotReloadConsistency(t *testing.T) {
	p1 := testPolicy("v1", policy.EffectMask)
	p2 := testPolicy("v2", policy.EffectDeny) // analyst denied under v2
	p3 := testPolicy("v3", policy.EffectMask)
	gw, al := newHarness(t, p1)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	violations := make(chan error, 20000)

	// Reloader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		versions := []*policy.Policy{p1, p2, p3}
		i := 0
		for ctx.Err() == nil {
			i++
			p := versions[i%len(versions)]
			_ = gw.UpdatePolicy(ctx, p) // ErrVersionExists after first cycle is fine
			time.Sleep(time.Millisecond)
		}
	}()

	roles := []string{"doctor", "analyst", "guest"}
	// Accessors.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for ctx.Err() == nil {
				role := roles[id%len(roles)]
				o := AccessOptions{
					SubjectID: "s-1", Resource: "patient_record", RecordID: "rec-1",
					Action: policy.ActionRead, Subject: policy.AttributeBag{"role": role},
				}
				r, err := gw.Access(ctx, o)
				if err != nil {
					continue
				}
				if !responseInternallyConsistent(p1, p2, p3, role, r) {
					violations <- &inconsistency{role: role, r: r}
				}
			}
		}(w)
	}
	wg.Wait()
	close(violations)
	for v := range violations {
		t.Fatalf("hot-reload inconsistency: %v", v)
	}

	// Audit chain must verify after the concurrent storm.
	events, err := al.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 100 {
		t.Fatalf("expected many audit events, got %d", len(events))
	}
	seqs := map[int64]bool{}
	for _, e := range events {
		if seqs[e.Seq] {
			t.Fatalf("duplicate audit seq %d", e.Seq)
		}
		seqs[e.Seq] = true
	}
	if int64(len(events)) != events[len(events)-1].Seq {
		t.Fatalf("audit seq not contiguous: count=%d last=%d", len(events), events[len(events)-1].Seq)
	}
	if ok, bad, err := al.Verify(context.Background()); !ok {
		t.Fatalf("audit chain invalid at seq %d: %v", bad, err)
	}
	log.Printf("[hot-reload] TOTAL_AUDIT_EVENTS=%d (no loss/dup, chain valid)", len(events))
}

type inconsistency struct {
	role string
	r    *AccessResponse
}

func (i *inconsistency) Error() string {
	return "role=" + i.role + " reason=" + i.r.Reason + " policy=" + i.r.PolicyVersion
}

// responseInternallyConsistent checks that the verdict's referenced rule
// exists in the response's claimed policy version and matches that rule's
// effect, and that deny responses never carry data.
func responseInternallyConsistent(p1, p2, p3 *policy.Policy, role string, r *AccessResponse) bool {
	versions := map[string]*policy.Policy{p1.Version: p1, p2.Version: p2, p3.Version: p3}
	p, ok := versions[r.PolicyVersion]
	if !ok {
		return false
	}
	// Expected verdict under the claimed version.
	analystRule := p.Rules[1] // mask-analyst (effect flips between mask/deny)
	switch role {
	case "doctor":
		if r.Reason != "allowed_by_rule=allow-doctor" || !r.Allowed {
			return false
		}
	case "guest":
		if r.Reason != "denied_by_rule=deny-guest" || !r.Denied || r.Record != nil {
			return false
		}
	case "analyst":
		switch analystRule.Effect {
		case policy.EffectMask:
			if r.Reason != "masked_by_rule=mask-analyst" || !r.Masked || r.MaskedData == nil {
				return false
			}
		case policy.EffectDeny:
			if r.Reason != "denied_by_rule=mask-analyst" || !r.Denied || r.Record != nil {
				return false
			}
		}
	}
	// Every non-error reason references an actual rule id in the version.
	if len(r.MatchedRules) > 0 {
		ids := map[string]bool{}
		for _, rule := range p.Rules {
			ids[rule.ID] = true
		}
		for _, m := range r.MatchedRules {
			if !ids[m] {
				return false
			}
		}
	}
	return true
}
