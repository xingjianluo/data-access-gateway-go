package dsr

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/gateway"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

// RequestType enumerates data-subject requests.
type RequestType string

const (
	TypeExport RequestType = "export"
	TypeDelete RequestType = "delete"
)

// Status enumerates DSR processing states.
type Status string

const (
	StatusComplete  Status = "complete"
	StatusFailed    Status = "failed"
	StatusDuplicate Status = "duplicate"
)

// Request is a data-subject request.
type Request struct {
	RequestID string
	Type      RequestType
	SubjectID string
}

// Result is the idempotent outcome of a DSR request.
type Result struct {
	RequestID string
	Status    Status
	Reason    string
	Attempts  int
	// Export payload, grouped by replica (must agree across replicas).
	Records map[string][]*store.Record
	// Delete coverage.
	Replicas []string
	AuditSeq int64
}

// Processor handles export/delete subject requests. Results are keyed by
// RequestID: a repeat of a completed request returns Status=duplicate with
// the stored outcome (never a fresh silent success); a repeat of a failed
// request is retried. All operations cover every storage replica.
type Processor struct {
	gw  *gateway.Gateway
	st  *store.Store
	log *audit.Log

	mu      sync.Mutex
	results map[string]*Result
}

// NewProcessor constructs a DSR processor.
func NewProcessor(gw *gateway.Gateway, st *store.Store, log *audit.Log) *Processor {
	return &Processor{gw: gw, st: st, log: log, results: make(map[string]*Result)}
}

var (
	// ErrInvalidRequest is returned for malformed subject requests.
	ErrInvalidRequest = errors.New("invalid dsr request")
	// ErrReplicasDisagree is returned when exported replicas diverge.
	ErrReplicasDisagree = errors.New("storage replicas disagree")
)

// Submit runs (or replays) one request. The whole idempotency window,
// including the audit append, happens under the processor lock so the
// "complete -> duplicate" sequence can never interleave with itself or with
// other requests (audit events are still globally ordered).
func (p *Processor) Submit(ctx context.Context, req Request) (*Result, error) {
	if req.RequestID == "" || req.SubjectID == "" {
		return nil, ErrInvalidRequest
	}
	switch req.Type {
	case TypeExport, TypeDelete:
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidRequest, req.Type)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, seen := p.results[req.RequestID]; seen {
		if existing.Status == StatusComplete {
			// Idempotent replay: surface the stored result and flag it as a
			// duplicate rather than pretending this call did the work.
			dup := *existing
			dup.Status = StatusDuplicate
			dup.Reason = "duplicate_request:replayed_result_of_request=" + req.RequestID
			ev := audit.Event{
				Kind:      audit.KindDSR,
				SubjectID: req.SubjectID,
				Action:    string(req.Type),
				Decision:  "duplicate",
				Reason:    dup.Reason,
				Detail:    map[string]string{"request_id": req.RequestID, "replayed_seq": fmt.Sprintf("%d", existing.AuditSeq)},
			}
			stored, _ := p.log.Append(ctx, ev)
			dup.AuditSeq = stored.Seq
			return &dup, nil
		}
		// Previous attempt failed: allow a retry under the same ID.
		existing.Attempts++
	} else {
		p.results[req.RequestID] = &Result{RequestID: req.RequestID, Attempts: 1}
	}

	var res *Result
	var err error
	switch req.Type {
	case TypeExport:
		res, err = p.runExportLocked(ctx, req)
	case TypeDelete:
		res, err = p.runDeleteLocked(ctx, req)
	}
	saved := *res
	p.results[req.RequestID] = &saved
	return res, err
}

// runExportLocked assumes p.mu is held.
func (p *Processor) runExportLocked(ctx context.Context, req Request) (*Result, error) {
	attempts := p.results[req.RequestID].Attempts
	byReplica, err := p.st.ExportAll(ctx, req.SubjectID)
	if err != nil {
		return p.failResultLocked(req, "export_failed:"+err.Error(), attempts), err
	}
	if err := checkReplicaAgreement(byReplica); err != nil {
		return p.failResultLocked(req, "export_failed:"+err.Error(), attempts), err
	}
	res := &Result{
		RequestID: req.RequestID,
		Status:    StatusComplete,
		Reason:    "export_complete:all_replicas_covered",
		Attempts:  attempts,
		Records:   byReplica,
		Replicas:  p.st.Replicas(),
	}
	ev := audit.Event{
		Kind:      audit.KindDSR,
		SubjectID: req.SubjectID,
		Action:    "export",
		Decision:  "complete",
		Reason:    res.Reason,
		Detail: map[string]string{
			"request_id":   req.RequestID,
			"replicas":     fmt.Sprintf("%d", len(byReplica)),
			"record_total": fmt.Sprintf("%d", totalRecords(byReplica)),
		},
	}
	stored, _ := p.log.Append(ctx, ev)
	res.AuditSeq = stored.Seq
	return res, nil
}

// runDeleteLocked assumes p.mu is held.
func (p *Processor) runDeleteLocked(ctx context.Context, req Request) (*Result, error) {
	attempts := p.results[req.RequestID].Attempts
	results, err := p.st.DeleteAll(ctx, req.SubjectID)
	if err != nil {
		reason := fmt.Sprintf("delete_failed:partial_replica_failure:%v", results.Failed())
		res := p.failResultLocked(req, reason, attempts)
		stored, _ := p.log.Append(ctx, audit.Event{
			Kind:      audit.KindDSR,
			SubjectID: req.SubjectID,
			Action:    "delete",
			Decision:  "failed",
			Reason:    reason,
			Detail:    map[string]string{"request_id": req.RequestID, "error": err.Error()},
		})
		res.AuditSeq = stored.Seq
		return res, err
	}
	// Verify coverage: nothing should remain on any replica.
	remaining, _ := p.st.ExportAll(ctx, req.SubjectID)
	if totalRecords(remaining) != 0 {
		reason := "delete_failed:records_remain_after_delete"
		return p.failResultLocked(req, reason, attempts), errors.New(reason)
	}
	res := &Result{
		RequestID: req.RequestID,
		Status:    StatusComplete,
		Reason:    "delete_complete:all_replicas_cleared",
		Attempts:  attempts,
		Replicas:  p.st.Replicas(),
	}
	stored, _ := p.log.Append(ctx, audit.Event{
		Kind:      audit.KindDSR,
		SubjectID: req.SubjectID,
		Action:    "delete",
		Decision:  "complete",
		Reason:    res.Reason,
		Detail: map[string]string{
			"request_id": req.RequestID,
			"replicas":   fmt.Sprintf("%d", len(p.st.Replicas())),
		},
	})
	res.AuditSeq = stored.Seq
	return res, nil
}

func (p *Processor) failResultLocked(req Request, reason string, attempts int) *Result {
	return &Result{
		RequestID: req.RequestID,
		Status:    StatusFailed,
		Reason:    reason,
		Attempts:  attempts,
		Replicas:  p.st.Replicas(),
	}
}

func totalRecords(byReplica map[string][]*store.Record) int {
	n := 0
	for _, list := range byReplica {
		n += len(list)
	}
	return n
}

// checkReplicaAgreement verifies every replica returned the same set of
// record IDs and versions.
func checkReplicaAgreement(byReplica map[string][]*store.Record) error {
	sig := map[string]struct{}{}
	for _, list := range byReplica {
		set := map[string]int64{}
		for _, r := range list {
			set[r.ID] = r.Version
		}
		sig[fmt.Sprint(set)] = struct{}{}
	}
	if len(sig) > 1 {
		return ErrReplicasDisagree
	}
	return nil
}
