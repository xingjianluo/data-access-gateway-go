package store

import (
	"context"
	"testing"
	"time"
)

func TestPutFansOutToEveryReplica(t *testing.T) {
	s := New(3)
	r := Record{ID: "x", Resource: "doc", SubjectID: "u",
		Data: map[string]any{"a": 1}, ExpiresAt: time.Now()}
	if _, err := s.Put(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for _, rep := range s.Replicas() {
		got, err := s.Get(context.Background(), "x", rep)
		if err != nil {
			t.Fatalf("missing on %s: %v", rep, err)
		}
		if got.Version != 1 || got.Data["a"] != 1 {
			t.Fatalf("replica %s content mismatch: %+v", rep, got)
		}
	}
}

func TestPutFaultThenHealIsRetriable(t *testing.T) {
	s := New(2)
	s.SetReplicaFault("replica-1", context.DeadlineExceeded)
	_, err := s.Put(context.Background(), Record{ID: "y", Resource: "doc", SubjectID: "u"})
	if err == nil {
		t.Fatal("faulted put must report partial failure")
	}
	if _, gerr := s.Get(context.Background(), "y", "replica-0"); gerr != nil {
		t.Fatal("healthy replica must have the copy")
	}
	if _, gerr := s.Get(context.Background(), "y", "replica-1"); gerr != ErrNotFound {
		t.Fatal("faulted replica must not have the copy")
	}
	// Heal and re-put: versions converge and both copies exist.
	s.SetReplicaFault("replica-1", nil)
	if _, err := s.Put(context.Background(), Record{ID: "y", Resource: "doc", SubjectID: "u"}); err != nil {
		t.Fatalf("retry put: %v", err)
	}
	for _, rep := range s.Replicas() {
		if got, _ := s.Get(context.Background(), "y", rep); got == nil || got.Version != 2 {
			t.Fatalf("replica %s not converged after retry", rep)
		}
	}
}
