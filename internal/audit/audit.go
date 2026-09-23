package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind enumerates audited event types.
type Kind string

const (
	KindAccess    Kind = "access"
	KindPolicy    Kind = "policy_update"
	KindRetention Kind = "retention"
	KindDSR       Kind = "dsr"
)

// Event is one audit entry. Hash fields are filled by the log on Append;
// callers only supply business fields.
type Event struct {
	Seq         int64
	Time        time.Time
	Kind        Kind
	SubjectID   string
	Resource    string
	Action      string
	Decision    string
	Reason      string
	PolicyVer   string
	Detail      map[string]string
	RequestHash string
	PrevHash    string
	Hash        string
}

// canonical renders the hash-covered bytes. The format is fixed and
// length-prefixed-by-newline so two equal events always hash identically.
func canonical(e Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seq=%d\n", e.Seq)
	fmt.Fprintf(&b, "time=%d\n", e.Time.UnixNano())
	fmt.Fprintf(&b, "kind=%s\n", e.Kind)
	fmt.Fprintf(&b, "subject=%s\n", e.SubjectID)
	fmt.Fprintf(&b, "resource=%s\n", e.Resource)
	fmt.Fprintf(&b, "action=%s\n", e.Action)
	fmt.Fprintf(&b, "decision=%s\n", e.Decision)
	fmt.Fprintf(&b, "reason=%s\n", e.Reason)
	fmt.Fprintf(&b, "policy=%s\n", e.PolicyVer)
	fmt.Fprintf(&b, "request_hash=%s\n", e.RequestHash)
	fmt.Fprintf(&b, "prev=%s\n", e.PrevHash)
	keys := make([]string, 0, len(e.Detail))
	for k := range e.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "detail:%s=%s\n", k, e.Detail[k])
	}
	return b.String()
}

// SealHash computes the SHA-256 chain hash for an event given its fields
// (exposed for tests/tools).
func SealHash(e Event) string {
	sum := sha256.Sum256([]byte(canonical(e)))
	return hex.EncodeToString(sum[:])
}

// Log is an append-only hash-chained audit log. Events are only added,
// never modified or deleted; every event commits the previous hash, so any
// tampering breaks the chain and is detected by Verify.
type Log struct {
	mu     sync.Mutex
	events []Event
}

// NewAuditLog constructs an empty audit log.
func NewAuditLog() *Log { return &Log{} }

// Append seals and stores one event. Seq/Time/PrevHash/Hash are assigned by
// the log and must not be set by the caller. Returns the stored copy.
func (l *Log) Append(ctx context.Context, e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = int64(len(l.events)) + 1
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Seq == 1 {
		e.PrevHash = strings.Repeat("0", 64)
	} else {
		e.PrevHash = l.events[len(l.events)-1].Hash
	}
	if e.Detail != nil {
		cp := make(map[string]string, len(e.Detail))
		for k, v := range e.Detail {
			cp[k] = v
		}
		e.Detail = cp
	}
	e.Hash = SealHash(e)
	l.events = append(l.events, e)
	return e, nil
}

// All returns a copy of all events in append order.
func (l *Log) All(ctx context.Context) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out, nil
}

// Get returns one event by sequence number.
func (l *Log) Get(ctx context.Context, seq int64) (Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq < 1 || int(seq) > len(l.events) {
		return Event{}, false
	}
	return l.events[seq-1], true
}

// Len returns the number of stored events.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// Verify replays the hash chain. ok=false names the first sequence whose
// stored hash (or back-pointer) does not recompute.
func (l *Log) Verify(ctx context.Context) (bool, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := strings.Repeat("0", 64)
	for i := range l.events {
		e := l.events[i]
		if e.Seq != int64(i+1) {
			return false, e.Seq, errors.New("sequence gap or reorder")
		}
		if e.PrevHash != prev {
			return false, e.Seq, errors.New("prev hash mismatch")
		}
		if SealHash(e) != e.Hash {
			return false, e.Seq, errors.New("content hash mismatch")
		}
		prev = e.Hash
	}
	return true, 0, nil
}
