package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Record is one managed-data record plus its metadata.
type Record struct {
	ID         string
	Resource   string
	SubjectID  string
	Data       map[string]any
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Version    int64
	Tombstoned bool
}

// ErrNotFound is returned when no record exists for the given id.
var ErrNotFound = errors.New("record not found")

// cloneRecord returns a deep enough copy for safe hand-out.
func cloneRecord(r *Record) *Record {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Data != nil {
		cp.Data = make(map[string]any, len(r.Data))
		for k, v := range r.Data {
			cp.Data[k] = v
		}
	}
	return &cp
}

// ReplicaResults maps replica name to a nullable error message.
type ReplicaResults map[string]error

// Failed returns replica/error pairs, if any.
func (rr ReplicaResults) Failed() map[string]error {
	out := map[string]error{}
	for name, err := range rr {
		if err != nil {
			out[name] = err
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Store simulates managed storage with multiple named replicas. Mutating
// operations fan out to every replica; callers get per-replica results so a
// partial failure can be retried. Reads from any replica must agree.
type Store struct {
	mu       sync.RWMutex
	replicas []string
	data     map[string]map[string]*Record // replica -> id -> record
	faults   map[string]error              // injected per-replica faults
}

// New constructs an in-memory store with replicaCount replicas named
// replica-0, replica-1, ... At least one replica is always created.
func New(replicaCount int) *Store {
	if replicaCount < 1 {
		replicaCount = 1
	}
	s := &Store{
		replicas: make([]string, 0, replicaCount),
		data:     make(map[string]map[string]*Record),
		faults:   make(map[string]error),
	}
	for i := 0; i < replicaCount; i++ {
		name := fmt.Sprintf("replica-%d", i)
		s.replicas = append(s.replicas, name)
		s.data[name] = make(map[string]*Record)
	}
	return s
}

// Replicas lists replica names in stable order.
func (s *Store) Replicas() []string {
	out := append([]string(nil), s.replicas...)
	return out
}

// SetReplicaFault injects (or clears, with nil) a fault for one replica.
// Faulting replicas make every mutating op on them fail, which lets tests
// exercise partial-failure retries.
func (s *Store) SetReplicaFault(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.faults, name)
	} else {
		s.faults[name] = err
	}
}

// Put writes a record to every replica. A per-replica fault fails that
// replica only; the returned ReplicaResults reports exactly which copies
// did not land. Success on all replicas returns nil error.
func (s *Store) Put(ctx context.Context, r Record) (ReplicaResults, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := ReplicaResults{}
	// Determine next version from any existing copy.
	var version int64 = 1
	for _, rep := range s.replicas {
		if existing := s.data[rep][r.ID]; existing != nil && existing.Version >= version {
			version = existing.Version + 1
		}
	}
	in := cloneRecord(&r)
	in.Version = version
	in.Tombstoned = false
	for _, rep := range s.replicas {
		if err := s.faults[rep]; err != nil {
			results[rep] = err
			continue
		}
		s.data[rep][r.ID] = cloneRecord(in)
	}
	if failed := results.Failed(); failed != nil {
		return results, fmt.Errorf("put incomplete on %d replica(s)", len(failed))
	}
	return nil, nil
}

// Get reads one record from one replica (or replica-0 if ""). All replicas
// are expected to agree; cross-replica comparison is the caller's job.
func (s *Store) Get(ctx context.Context, id, replica string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if replica == "" {
		replica = s.replicas[0]
	}
	set, ok := s.data[replica]
	if !ok {
		return nil, fmt.Errorf("unknown replica: %s", replica)
	}
	r, ok := set[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneRecord(r), nil
}

// fanOutLocked applies mutate to the record on every replica.
func (s *Store) fanOutLocked(id string, mutate func(r *Record)) ReplicaResults {
	results := ReplicaResults{}
	for _, rep := range s.replicas {
		if err := s.faults[rep]; err != nil {
			results[rep] = err
			continue
		}
		r := s.data[rep][id]
		if r == nil {
			results[rep] = ErrNotFound
			continue
		}
		mutate(r)
	}
	return results
}

// DeleteAll removes all records of a subject across all replicas.
func (s *Store) DeleteAll(ctx context.Context, subjectID string) (ReplicaResults, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := ReplicaResults{}
	failCount := 0
	for _, rep := range s.replicas {
		if err := s.faults[rep]; err != nil {
			results[rep] = err
			failCount++
			continue
		}
		for id, r := range s.data[rep] {
			if r.SubjectID == subjectID {
				delete(s.data[rep], id)
			}
		}
	}
	if failCount > 0 {
		return results, fmt.Errorf("delete all incomplete on %d replica(s)", failCount)
	}
	return nil, nil
}

// ExportAll returns all records of a subject from every replica.
func (s *Store) ExportAll(ctx context.Context, subjectID string) (map[string][]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]*Record, len(s.replicas))
	for _, rep := range s.replicas {
		var list []*Record
		for _, r := range s.data[rep] {
			if r.SubjectID == subjectID && !r.Tombstoned {
				list = append(list, cloneRecord(r))
			}
		}
		out[rep] = list
	}
	return out, nil
}

// ScanExpired returns the union across ALL replicas of records whose expiry
// has passed and which are not already tombstoned. Union semantics are
// essential for partial-failure retries: a record whose delete failed on one
// replica still exists there even if healthy replicas already dropped it, so
// scanning only one replica would strand it forever.
func (s *Store) ScanExpired(ctx context.Context, now time.Time) ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []*Record
	for _, rep := range s.replicas {
		for _, r := range s.data[rep] {
			if seen[r.ID] {
				continue
			}
			if !r.Tombstoned && !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
				seen[r.ID] = true
				out = append(out, cloneRecord(r))
			}
		}
	}
	return out, nil
}

// Anonymize overwrites the given fields with a fixed token on every replica.
func (s *Store) Anonymize(ctx context.Context, id string, fields []string) (ReplicaResults, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := s.fanOutLocked(id, func(r *Record) {
		for _, f := range fields {
			if _, ok := r.Data[f]; ok {
				r.Data[f] = "[REDACTED-ANON]"
			}
		}
		r.Version++
	})
	if failed := results.Failed(); failed != nil {
		return results, fmt.Errorf("anonymize incomplete on %d replica(s)", len(failed))
	}
	return nil, nil
}

// HardDelete removes one record on every replica.
func (s *Store) HardDelete(ctx context.Context, id string) (ReplicaResults, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := ReplicaResults{}
	failCount := 0
	for _, rep := range s.replicas {
		if err := s.faults[rep]; err != nil {
			results[rep] = err
			failCount++
			continue
		}
		delete(s.data[rep], id)
	}
	if failCount > 0 {
		return results, fmt.Errorf("hard delete incomplete on %d replica(s)", failCount)
	}
	return nil, nil
}

// Count returns how many records one replica currently holds (test/debug).
func (s *Store) Count(replica string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data[replica])
}
