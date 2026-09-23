package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/eval"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
	"github.com/xingjianluo/data-access-gateway-go/internal/store"
)

// AccessOptions carries the attribute-based request inputs.
type AccessOptions struct {
	SubjectID  string
	Resource   string
	RecordID   string
	Action     policy.Action
	Subject    policy.AttributeBag // role, department, ...
	ResourceAttrs policy.AttributeBag // sensitivity, owner, ...
	Env        policy.AttributeBag // ip, time-of-day, mfa, ...
}

// AccessResponse is the gateway result of an access request.
type AccessResponse struct {
	Allowed       bool
	Masked        bool
	Denied        bool
	Reason        string
	PolicyVersion string
	MatchedRules  []string
	// Record is nil on deny. On mask, callers must serve MaskedData; the
	// plaintext-bearing Record is still returned for server-side logic but
	// must never cross an untrusted boundary on a masked verdict.
	Record     *store.Record
	MaskedData map[string]any
	AuditSeq   int64
}

// Gateway wires policy snapshot, storage and audit together.
type Gateway struct {
	ps  *policy.Store
	st  *store.Store
	log *audit.Log
}

// New constructs a gateway.
func New(ps *policy.Store, st *store.Store, log *audit.Log) *Gateway {
	return &Gateway{ps: ps, st: st, log: log}
}

// Store / PolicyStore / Audit expose collaborators to other services.
func (g *Gateway) Store() *store.Store       { return g.st }
func (g *Gateway) PolicyStore() *policy.Store { return g.ps }
func (g *Gateway) Audit() *audit.Log          { return g.log }

// requestHash binds the audit row to the exact request inputs.
func requestHash(o AccessOptions, version string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", o.SubjectID, o.Resource, o.RecordID, o.Action, version)
	writeAttrs(h, "env", o.Env)
	writeAttrs(h, "subj", o.Subject)
	writeAttrs(h, "res", o.ResourceAttrs)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func writeAttrs(h interface{ Write([]byte) (int, error) }, prefix string, attrs policy.AttributeBag) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	// sorted rendering keeps the hash stable for equal inputs
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		fmt.Fprintf(h, "|%s.%s=%v", prefix, k, attrs[k])
	}
}

// Access authorizes and serves one read/export request. The policy snapshot
// is captured exactly once at entry and reused for the entire request
// lifetime, so a concurrent hot update cannot make the decision and its
// served data disagree. Denies never touch plaintext data.
func (g *Gateway) Access(ctx context.Context, o AccessOptions) (*AccessResponse, error) {
	if o.Env == nil {
		o.Env = policy.AttributeBag{}
	}

	// 1) Capture one immutable snapshot for this request.
	snap, err := g.ps.Current(ctx)
	if err != nil {
		return nil, err
	}
	reqHash := requestHash(o, snap.Version)

	// 2) Evaluate first; denied requests must not read data at all.
	subjectAttrs := policy.AttributeBag{}
	for k, v := range o.Subject {
		subjectAttrs[k] = v
	}
	subjectAttrs["id"] = o.SubjectID

	engine := eval.NewEngine(snap)
	res := engine.Evaluate(ctx, eval.Request{
		Subject:       subjectAttrs,
		Resource:      o.Resource,
		Action:        o.Action,
		Env:           o.Env,
		ResourceAttrs: o.ResourceAttrs,
	})

	resp := &AccessResponse{
		Reason:        res.Reason,
		PolicyVersion: snap.Version,
		MatchedRules: append([]string(nil), res.MatchedRules...),
	}

	ev := audit.Event{
		Kind:        audit.KindAccess,
		SubjectID:   o.SubjectID,
		Resource:    o.Resource,
		Action:      string(o.Action),
		PolicyVer:   snap.Version,
		Reason:      res.Reason,
		RequestHash: reqHash,
		Detail: map[string]string{
			"record_id":     o.RecordID,
			"matched_rules": strings.Join(res.MatchedRules, ","),
		},
	}

	if res.Decision == eval.DecisionDeny {
		resp.Denied = true
		ev.Decision = string(eval.DecisionDeny)
		stored, _ := g.log.Append(ctx, ev)
		resp.AuditSeq = stored.Seq
		return resp, nil
	}

	// 3) Authorized: fetch from the primary replica.
	rec, err := g.st.Get(ctx, o.RecordID, "")
	if err != nil {
		// Storage failure is auditable and must not masquerade as a deny.
		ev.Decision = "error"
		ev.Reason = "storage_error:" + err.Error()
		stored, _ := g.log.Append(ctx, ev)
		resp.AuditSeq = stored.Seq
		return nil, fmt.Errorf("fetch %s: %w", o.RecordID, err)
	}
	if rec.Resource != o.Resource || rec.SubjectID != o.SubjectID {
		// Defense in depth: fetched record belongs to another subject/type.
		resp.Denied = true
		resp.Reason = "default_deny:record_owner_mismatch"
		ev.Decision = string(eval.DecisionDeny)
		ev.Reason = resp.Reason
		stored, _ := g.log.Append(ctx, ev)
		resp.AuditSeq = stored.Seq
		return resp, nil
	}

	switch res.Decision {
	case eval.DecisionMask:
		resp.Masked = true
		ev.Decision = string(eval.DecisionMask)
		masked := make(map[string]any, len(rec.Data))
		fieldOps := map[string]string{}
		for _, fm := range res.Fields {
			fieldOps[fm.Field] = string(fm.Op)
		}
		for k, v := range rec.Data {
			if op, ok := fieldOps[k]; ok {
				masked[k] = maskValue(v, op)
			} else {
				masked[k] = v
			}
		}
		resp.MaskedData = masked
		resp.Record = rec
	default:
		resp.Allowed = true
		ev.Decision = string(eval.DecisionAllow)
		resp.Record = rec
	}

	stored, err := g.log.Append(ctx, ev)
	if err != nil {
		return nil, err
	}
	resp.AuditSeq = stored.Seq
	return resp, nil
}

// UpdatePolicy installs a new policy version and records the switch
// immutably. In-flight requests holding an older snapshot finish on the
// older version; only new requests see the new version.
func (g *Gateway) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	if p == nil {
		return errors.New("nil policy")
	}
	if err := g.ps.Update(ctx, p); err != nil {
		return err
	}
	_, err := g.log.Append(ctx, audit.Event{
		Kind:      audit.KindPolicy,
		Action:    "hot_reload",
		Decision:  "installed",
		Reason:    "policy_version_installed",
		PolicyVer: p.Version,
		Detail: map[string]string{
			"rule_count":   fmt.Sprintf("%d", len(p.Rules)),
			"installed_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	return err
}
