// Command gateway runs a small in-process demonstration of the local data
// access gateway: policy decisions, field masking, hot policy reload,
// retention enforcement, data-subject requests and audit verification.
//
// Run with: go run ./cmd/gateway
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/dsr"
	"github.com/xingjianluo/data-access-gateway-go/internal/gateway"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/retention"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

func main() {
	ctx := context.Background()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	st := store.New(3)
	_, _ = st.Put(ctx, store.Record{
		ID: "rec-1", Resource: "patient_record", SubjectID: "s-1",
		Data:      map[string]any{"name": "Alice", "diagnosis": "flu", "ssn": "123-45-6789"},
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	})
	_, _ = st.Put(ctx, store.Record{
		ID: "rec-2", Resource: "patient_record", SubjectID: "s-1",
		Data:      map[string]any{"name": "Old", "diagnosis": "cold", "ssn": "999"},
		CreatedAt: now.Add(-720 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	})

	p1 := &policy.Policy{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "deny-external", Effect: policy.EffectDeny, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead}, Priority: 100,
				When: policy.MatchClause{"env.network": "external"}},
			{ID: "mask-analyst", Effect: policy.EffectMask, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead}, Priority: 20,
				When: policy.MatchClause{"subject.role": "analyst"},
				Fields: []policy.FieldRule{{Field: "diagnosis", Op: policy.MaskRedact}, {Field: "ssn", Op: policy.MaskPartial}}},
			{ID: "allow-doctor", Effect: policy.EffectAllow, Resource: "patient_record",
				Actions: []policy.Action{policy.ActionRead, policy.ActionExport, policy.ActionDelete},
				Priority: 10, When: policy.MatchClause{"subject.role": "doctor"}},
		},
	}
	log := audit.NewAuditLog()
	gw := gateway.New(policy.NewStore(p1), st, log)

	fmt.Println("== access decisions ==")
	demo := func(label string, o gateway.AccessOptions) {
		r, err := gw.Access(ctx, o)
		if err != nil {
			fmt.Printf("%-28s ERROR %v\n", label, err)
			return
		}
		payload := any(nil)
		if r.MaskedData != nil {
			payload = r.MaskedData
		} else if r.Record != nil {
			payload = r.Record.Data
		}
		fmt.Printf("%-28s %-7s policy=%s reason=%s data=%v\n", label, r.Reason[:min(7, len(r.Reason))], r.PolicyVersion, r.Reason, payload)
	}
	read := func(role string, env map[string]any) gateway.AccessOptions {
		return gateway.AccessOptions{SubjectID: "s-1", Resource: "patient_record", RecordID: "rec-1",
			Action: policy.ActionRead, Subject: policy.AttributeBag{"role": role}, Env: env}
	}
	demo("doctor internal", read("doctor", map[string]any{"network": "internal"}))
	demo("analyst internal (mask)", read("analyst", map[string]any{"network": "internal"}))
	demo("analyst external (deny)", read("analyst", map[string]any{"network": "external"}))
	demo("guest (default deny)", read("guest", map[string]any{"network": "internal"}))

	fmt.Println("== hot policy reload ==")
	p2 := &policy.Policy{Version: "v2", Rules: []policy.Rule{
		{ID: "deny-all", Effect: policy.EffectDeny, Resource: "patient_record",
			Actions: []policy.Action{policy.ActionRead}, Priority: 100},
	}}
	if err := gw.UpdatePolicy(ctx, p2); err != nil {
		panic(err)
	}
	demo("doctor after v2 reload", read("doctor", map[string]any{"network": "internal"}))

	fmt.Println("== retention enforcement ==")
	job := retention.NewJob(st, []policy.RetentionRule{
		{Resource: "patient_record", TTLSeconds: 3600, OnExpiry: "anonymize",
			AnonymizeWith: []policy.FieldRule{{Field: "diagnosis"}, {Field: "ssn"}}},
	}, log)
	outcomes, err := job.RunOnce(ctx, now)
	if err != nil {
		panic(err)
	}
	for _, o := range outcomes {
		fmt.Printf("  %s -> %s (%s)\n", o.RecordID, o.Action, o.Reason)
	}

	fmt.Println("== data-subject requests ==")
	proc := dsr.NewProcessor(gw, st, log)
	exp, err := proc.Submit(ctx, dsr.Request{RequestID: "dsr-export-1", Type: dsr.TypeExport, SubjectID: "s-1"})
	fmt.Printf("export: status=%s reason=%s replicas=%d err=%v\n", exp.Status, exp.Reason, len(exp.Replicas), err)
	del, err := proc.Submit(ctx, dsr.Request{RequestID: "dsr-delete-1", Type: dsr.TypeDelete, SubjectID: "s-1"})
	fmt.Printf("delete: status=%s reason=%s err=%v\n", del.Status, del.Reason, err)
	dup, err := proc.Submit(ctx, dsr.Request{RequestID: "dsr-delete-1", Type: dsr.TypeDelete, SubjectID: "s-1"})
	fmt.Printf("replay: status=%s reason=%s err=%v\n", dup.Status, dup.Reason, err)

	fmt.Println("== audit verification ==")
	events, _ := log.All(ctx)
	ok, bad, verr := log.Verify(ctx)
	fmt.Printf("events=%d chain_valid=%v badSeq=%d err=%v\n", len(events), ok, bad, verr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
