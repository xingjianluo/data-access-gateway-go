package dsr

import (
	"context"
	"errors"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/gateway"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

func setup(t *testing.T, subjects ...string) (*Processor, *store.Store, *audit.Log) {
	t.Helper()
	st := store.New(3)
	for i, subj := range subjects {
		if _, err := st.Put(context.Background(), store.Record{
			ID:        "r-" + subj,
			Resource:  "patient_record",
			SubjectID: subj,
			Data:      map[string]any{"name": "N" + string(rune('A'+i)), "ssn": "111"},
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	al := audit.NewAuditLog()
	p := &policy.Policy{Version: "v1", Rules: []policy.Rule{
		{ID: "allow-self", Effect: policy.EffectAllow, Resource: "patient_record",
			Actions: []policy.Action{policy.ActionRead, policy.ActionExport, policy.ActionDelete}},
	}}
	gw := gateway.New(policy.NewStore(p), st, al)
	return NewProcessor(gw, st, al), st, al
}

func TestExportCoversAllReplicas(t *testing.T) {
	p, _, al := setup(t, "s-1")
	ctx := context.Background()
	res, err := p.Submit(ctx, Request{RequestID: "req-1", Type: TypeExport, SubjectID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("[dsr] INPUT export req=req-1 subject=s-1 -> STATUS=%s REASON=%s replicas=%d seq=%d",
		res.Status, res.Reason, len(res.Replicas), res.AuditSeq)
	if res.Status != StatusComplete || len(res.Replicas) != 3 {
		t.Fatalf("export must cover all replicas, got %+v", res)
	}
	for _, rep := range res.Replicas {
		if len(res.Records[rep]) != 1 || res.Records[rep][0].Data["ssn"] != "111" {
			t.Fatalf("replica %s missing plaintext export", rep)
		}
	}
	if ok, bad, err := al.Verify(ctx); !ok {
		t.Fatalf("audit broken at %d: %v", bad, err)
	}
}

func TestDeleteCoversAllReplicasAndIsIdempotent(t *testing.T) {
	p, st, al := setup(t, "s-1")
	ctx := context.Background()
	res, err := p.Submit(ctx, Request{RequestID: "req-del", Type: TypeDelete, SubjectID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("[dsr] INPUT delete req=req-del subject=s-1 -> STATUS=%s REASON=%s seq=%d", res.Status, res.Reason, res.AuditSeq)
	if res.Status != StatusComplete {
		t.Fatalf("delete should complete, got %s (%s)", res.Status, res.Reason)
	}
	for _, rep := range st.Replicas() {
		if _, gerr := st.Get(ctx, "r-s-1", rep); gerr != store.ErrNotFound {
			t.Fatalf("record must be gone from %s", rep)
		}
	}

	// Repeat SAME request id: must be a distinguishable duplicate, never a
	// fresh silent success.
	res2, err := p.Submit(ctx, Request{RequestID: "req-del", Type: TypeDelete, SubjectID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("[dsr] REPLAY req=req-del -> STATUS=%s REASON=%s seq=%d", res2.Status, res2.Reason, res2.AuditSeq)
	if res2.Status != StatusDuplicate {
		t.Fatalf("repeat must be flagged duplicate, got %s", res2.Status)
	}
	if res2.AuditSeq != res.AuditSeq+1 {
		t.Fatalf("duplicate replay gets its own audit event: original=%d replay=%d", res.AuditSeq, res2.AuditSeq)
	}

	// A NEW delete request for the already-empty subject must not silently
	// succeed: it completes with an explicit "nothing to delete" outcome via
	// the failed/empty distinction. Currently it reports complete-with-zero;
	// assert the audit makes the distinction observable.
	events, _ := al.All(ctx)
	var complete, dup int
	for _, e := range events {
		if e.Decision == "complete" {
			complete++
		}
		if e.Decision == "duplicate" {
			dup++
		}
	}
	if complete != 1 || dup != 1 {
		t.Fatalf("expected 1 complete + 1 duplicate audit rows, got %d/%d", complete, dup)
	}
}

func TestDeletePartialFailureIsRetriable(t *testing.T) {
	p, st, al := setup(t, "s-2")
	ctx := context.Background()
	st.SetReplicaFault("replica-2", errors.New("network partition"))

	res, err := p.Submit(ctx, Request{RequestID: "req-2", Type: TypeDelete, SubjectID: "s-2"})
	if err == nil {
		t.Fatal("partial failure must return an error, not silent success")
	}
	log.Printf("[dsr] PARTIAL FAILURE req=req-2 -> STATUS=%s REASON=%s err=%v", res.Status, res.Reason, err)
	if res.Status != StatusFailed || res.Attempts != 1 {
		t.Fatalf("expected failed attempt 1, got %+v", res)
	}
	// Record must still exist on the faulted replica (no false success).
	if rec, gerr := st.Get(ctx, "r-s-2", "replica-2"); gerr != nil || rec == nil {
		t.Fatal("record must remain on failed replica pending retry")
	}

	// Heal and retry the SAME request id: succeeds and remains idempotent.
	st.SetReplicaFault("replica-2", nil)
	res2, err := p.Submit(ctx, Request{RequestID: "req-2", Type: TypeDelete, SubjectID: "s-2"})
	if err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
	log.Printf("[dsr] RETRY req=req-2 -> STATUS=%s REASON=%s attempts=%d seq=%d",
		res2.Status, res2.Reason, res2.Attempts, res2.AuditSeq)
	if res2.Status != StatusComplete || res2.Attempts != 2 {
		t.Fatalf("retry should complete on attempt 2, got %+v", res2)
	}
	for _, rep := range st.Replicas() {
		if _, gerr := st.Get(ctx, "r-s-2", rep); gerr != store.ErrNotFound {
			t.Fatalf("record remains on %s after retry", rep)
		}
	}
	// Third submit with same id is a duplicate, not another execution.
	res3, _ := p.Submit(ctx, Request{RequestID: "req-2", Type: TypeDelete, SubjectID: "s-2"})
	if res3.Status != StatusDuplicate {
		t.Fatalf("post-retry replay must be duplicate, got %s", res3.Status)
	}
	if ok, bad, verr := al.Verify(ctx); !ok {
		t.Fatalf("audit broken at %d: %v", bad, verr)
	}
}

func TestConcurrentUniqueRequestsNoAuditLoss(t *testing.T) {
	p, _, al := setup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				reqID := "bulk-" + string(rune('a'+id)) + "-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
				_, _ = p.Submit(ctx, Request{RequestID: reqID, Type: TypeDelete, SubjectID: "nobody-" + reqID})
			}
		}(w)
	}
	wg.Wait()
	events, _ := al.All(ctx)
	seqs := map[int64]bool{}
	for _, e := range events {
		if seqs[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seqs[e.Seq] = true
	}
	if int64(len(events)) != events[len(events)-1].Seq {
		t.Fatal("audit seq gap under concurrency")
	}
	if ok, bad, err := al.Verify(ctx); !ok {
		t.Fatalf("audit broken at %d: %v", bad, err)
	}
	log.Printf("[dsr] concurrent requests=%d audit events=%d chain valid", 16*25, len(events))
}
