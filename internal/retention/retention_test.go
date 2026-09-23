package retention

import (
	"context"
	"errors"
	"log"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

func TestRetentionBoundary(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	st := store.New(2)
	mk := func(id string, expiry time.Time) {
		if _, err := st.Put(ctx, store.Record{
			ID: id, Resource: "patient_record", SubjectID: "s-" + id,
			Data:      map[string]any{"name": "N-" + id, "diagnosis": "X", "ssn": "123"},
			CreatedAt: now.Add(-72 * time.Hour),
			ExpiresAt: expiry,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("future", now.Add(1*time.Hour))       // not expired
	mk("boundary", now)                      // expiry == now => expired
	mk("past", now.Add(-1*time.Hour))        // expired
	mk("anon", now.Add(-2*time.Hour))        // expired, anonymized

	al := audit.NewAuditLog()
	rules := []policy.RetentionRule{
		{Resource: "patient_record", TTLSeconds: 3600, OnExpiry: "anonymize",
			AnonymizeWith: []policy.FieldRule{{Field: "diagnosis"}, {Field: "ssn"}}},
	}
	job := NewJob(st, rules, al)

	outcomes, err := job.RunOnce(ctx, now)
	log.Printf("[retention] RUN now=%s outcomes=%d err=%v", now.Format(time.RFC3339), len(outcomes), err)
	for _, o := range outcomes {
		log.Printf("[retention] OUTPUT record=%s action=%s reason=%s auditSeq=%d", o.RecordID, o.Action, o.Reason, o.AuditSeq)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 3 {
		t.Fatalf("boundary+past+anon must be processed, got %d", len(outcomes))
	}

	// Future record survives untouched on every replica.
	r, err := st.Get(ctx, "future", "replica-0")
	if err != nil || r.Data["diagnosis"] != "X" {
		t.Fatalf("unexpired record must survive: %v %v", r, err)
	}

	// Anonymization applied to boundary/past/anon with same fixed token.
	for _, id := range []string{"boundary", "past", "anon"} {
		for _, rep := range st.Replicas() {
			rec, gerr := st.Get(ctx, id, rep)
			if gerr != nil {
				t.Fatalf("anonymized record %s missing on %s", id, rep)
			}
			if rec.Data["diagnosis"] != "[REDACTED-ANON]" || rec.Data["ssn"] != "[REDACTED-ANON]" {
				t.Fatalf("record %s on %s not anonymized: %v", id, rep, rec.Data)
			}
			if rec.Data["name"] != "N-"+id {
				t.Fatalf("non-listed field must remain: %v", rec.Data)
			}
		}
	}

	// Idempotency: re-running at the same instant produces no new changes;
	// anonymized (non-tombstoned) records re-match but converge identically.
	outcomes2, _ := job.RunOnce(ctx, now)
	log.Printf("[retention] RERUN outcomes=%d (idempotent convergence)", len(outcomes2))
	for _, o := range outcomes2 {
		if o.Err != nil {
			t.Fatalf("retry produced error: %v", o.Err)
		}
	}

	if ok, bad, err := al.Verify(ctx); !ok {
		t.Fatalf("audit chain broken at %d: %v", bad, err)
	}
}

func TestRetentionDeleteAndPartialFailureRetry(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := store.New(3)
	for _, id := range []string{"a", "b"} {
		if _, err := st.Put(ctx, store.Record{ID: id, Resource: "session", SubjectID: "u",
			Data: map[string]any{"token": "t"}, ExpiresAt: now.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	al := audit.NewAuditLog()
	job := NewJob(st, []policy.RetentionRule{{Resource: "session", OnExpiry: "delete"}}, al)

	// Inject a fault on one replica: run must report a retryable failure.
	injected := errors.New("replica disk offline")
	st.SetReplicaFault("replica-1", injected)
	outcomes, err := job.RunOnce(ctx, now)
	if err == nil {
		t.Fatal("partial replica failure must surface an error")
	}
	log.Printf("[retention] PARTIAL_FAILURE err=%v outcomes=%d", err, len(outcomes))
	if len(Failed(outcomes)) != 2 {
		t.Fatalf("both records should be reported failed, got %d", len(Failed(outcomes)))
	}
	for _, o := range outcomes {
		log.Printf("[retention] FAILED_INPUT record=%s reason=%s", o.RecordID, o.Reason)
	}

	// Heal and retry: all copies must then be gone.
	st.SetReplicaFault("replica-1", nil)
	outcomes2, err := job.RunOnce(ctx, now)
	if err != nil {
		t.Fatalf("retry after heal must succeed: %v", err)
	}
	for _, o := range outcomes2 {
		log.Printf("[retention] RETRY_OUTPUT record=%s action=%s reason=%s", o.RecordID, o.Action, o.Reason)
	}
	for _, rep := range st.Replicas() {
		for _, id := range []string{"a", "b"} {
			if _, gerr := st.Get(ctx, id, rep); gerr != store.ErrNotFound {
				t.Fatalf("record %s must be gone from %s", id, rep)
			}
		}
	}
	if ok, bad, verr := al.Verify(ctx); !ok {
		t.Fatalf("audit chain broken at %d: %v", bad, verr)
	}
}
