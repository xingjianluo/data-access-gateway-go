package audit

import (
	"context"
	"log"
	"sync"
	"testing"
)

func TestHashChainVerifiesAndDetectsTampering(t *testing.T) {
	l := NewAuditLog()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e, err := l.Append(ctx, Event{
			Kind:      KindAccess,
			SubjectID: "s-1",
			Resource:  "patient_record",
			Action:    "read",
			Decision:  "allow",
			Reason:    "allowed_by_rule=allow-doctor",
			PolicyVer: "v1",
			Detail:    map[string]string{"i": string(rune('0' + i))},
		})
		if err != nil {
			t.Fatal(err)
		}
		log.Printf("[audit] APPEND seq=%d hash=%s prev=%s reason=%s", e.Seq, e.Hash[:12], e.PrevHash[:12], e.Reason)
	}
	if ok, bad, err := l.Verify(ctx); !ok {
		t.Fatalf("fresh chain must verify: seq=%d err=%v", bad, err)
	}

	// Tamper with event 3's reason in-place: recompute-free chain must break.
	events, _ := l.All(ctx)
	original := events[2].Reason
	tampered := events[2]
	tampered.Reason = "allowed_by_rule=backdoor"
	copyIntoLog(l, 2, tampered)
	ok, bad, err := l.Verify(ctx)
	if ok {
		t.Fatal("tampered chain must fail verification")
	}
	log.Printf("[audit] TAMPER_DETECTED at seq=%d err=%v (changed %q -> backdoor)", bad, err, original)
	if bad != 3 {
		t.Fatalf("first bad seq must be 3, got %d", bad)
	}

	// Restore: chain verifies again.
	restored := tampered
	restored.Reason = original
	copyIntoLog(l, 2, restored)
	if ok, _, err := l.Verify(ctx); !ok {
		t.Fatalf("restored chain must verify: %v", err)
	}
}

func TestConcurrentAppendNoLossOrDuplicateSeq(t *testing.T) {
	l := NewAuditLog()
	ctx := context.Background()
	var wg sync.WaitGroup
	n := 200
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				_, _ = l.Append(ctx, Event{Kind: KindAccess, Reason: "concurrent"})
			}
		}()
	}
	wg.Wait()
	events, _ := l.All(ctx)
	if len(events) != 16*n {
		t.Fatalf("lost events: want %d got %d", 16*n, len(events))
	}
	seen := map[int64]bool{}
	for _, e := range events {
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
	}
	if ok, bad, err := l.Verify(ctx); !ok {
		t.Fatalf("concurrent chain invalid at %d: %v", bad, err)
	}
}

// copyIntoLog replaces an event by reconstructing the internal slice via
// reflection-free test helper exported through same-package access.
func copyIntoLog(l *Log, idx int, e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events[idx] = e
}
