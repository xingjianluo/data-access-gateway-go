package retention

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

// Outcome describes one expired record's treatment.
type Outcome struct {
	RecordID string
	Resource string
	Action   string // "deleted" | "anonymized"
	Reason   string
	AuditSeq int64
	Err      error
}

// Failed returns just the outcomes that failed (retry candidates).
func Failed(outcomes []Outcome) []Outcome {
	var bad []Outcome
	for _, o := range outcomes {
		if o.Err != nil {
			bad = append(bad, o)
		}
	}
	return bad
}

// Job enforces retention rules. Each expired record is either hard-deleted
// or anonymized on EVERY replica; per-record failures are returned, not
// swallowed, so the caller can retry. Re-running the job is idempotent:
// deleted records vanish from the scan, anonymized fields get the same
// fixed token again.
type Job struct {
	st    *store.Store
	rules map[string]policy.RetentionRule
	log   *audit.Log
}

// NewJob constructs a retention job.
func NewJob(st *store.Store, rules []policy.RetentionRule, log *audit.Log) *Job {
	j := &Job{st: st, rules: map[string]policy.RetentionRule{}, log: log}
	for _, r := range rules {
		j.rules[r.Resource] = r
	}
	return j
}

// RunOnce processes every record expired at/before now. It processes all
// records even if some fail and returns an aggregate error naming the
// failures; the returned outcomes distinguish per-record results.
func (j *Job) RunOnce(ctx context.Context, now time.Time) ([]Outcome, error) {
	expired, err := j.st.ScanExpired(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("scan expired: %w", err)
	}
	outcomes := make([]Outcome, 0, len(expired))
	var failures int
	for _, r := range expired {
		rule, ok := j.rules[r.Resource]
		if !ok {
			// No retention rule: conservative default is hard delete.
			rule = policy.RetentionRule{Resource: r.Resource, OnExpiry: "delete"}
		}
		switch rule.OnExpiry {
		case "anonymize":
			fields := make([]string, 0, len(rule.AnonymizeWith))
			for _, f := range rule.AnonymizeWith {
				fields = append(fields, f.Field)
			}
			results, aerr := j.st.Anonymize(ctx, r.ID, fields)
			o := Outcome{RecordID: r.ID, Resource: r.Resource, Action: "anonymized",
				Reason: "retention_expired:anonymize_fields"}
			if aerr != nil {
				o.Err = fmt.Errorf("record %s: %w (replicas=%v)", r.ID, aerr, results.Failed())
				o.Reason = "retention_failed:" + aerr.Error()
				failures++
			}
			ev := j.auditEvent(r.ID, r.SubjectID, r.Resource, o, rule.TTLSeconds)
			stored, _ := j.log.Append(ctx, ev)
			o.AuditSeq = stored.Seq
			outcomes = append(outcomes, o)
		default: // "delete" or anything unrecognized
			results, derr := j.st.HardDelete(ctx, r.ID)
			o := Outcome{RecordID: r.ID, Resource: r.Resource, Action: "deleted",
				Reason: "retention_expired:hard_delete"}
			if derr != nil {
				o.Err = fmt.Errorf("record %s: %w (replicas=%v)", r.ID, derr, results.Failed())
				o.Reason = "retention_failed:" + derr.Error()
				failures++
			}
			ev := j.auditEvent(r.ID, r.SubjectID, r.Resource, o, rule.TTLSeconds)
			stored, _ := j.log.Append(ctx, ev)
			o.AuditSeq = stored.Seq
			outcomes = append(outcomes, o)
		}
	}
	if failures > 0 {
		return outcomes, fmt.Errorf("retention run had %d failure(s), retry the job", failures)
	}
	return outcomes, nil
}

func (j *Job) auditEvent(recordID, subjectID, resource string, o Outcome, ttl int64) audit.Event {
	decision := o.Action
	reason := o.Reason
	if o.Err != nil {
		decision = "failed"
	}
	return audit.Event{
		Kind:      audit.KindRetention,
		SubjectID: subjectID,
		Resource:  resource,
		Action:    "expire",
		Decision:  decision,
		Reason:    reason,
		Detail: map[string]string{
			"record_id":   recordID,
			"ttl_seconds": fmt.Sprintf("%d", ttl),
			"error":       errText(o.Err),
		},
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ErrNoRules is returned when a job is constructed without rules (optional
// helper for callers that require explicit configuration).
var ErrNoRules = errors.New("no retention rules configured")
