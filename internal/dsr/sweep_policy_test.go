package dsr

import (
	"strings"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// setupSweep 构造 3 副本存储与 3 条均已到期的记录：
// users/1（策略：整条删除）、users/2（策略：匿名化 email/ssn）、logs/1（无策略：走兜底）。
func setupSweep(t *testing.T, expiredAt time.Time) (*data.Store, *audit.Log, *Processor, *policy.Policy) {
	t.Helper()
	ds := data.NewStore(3)
	lg := audit.NewLog()
	p := New(ds, lg)
	put := func(resource, subject string, d map[string]any) {
		if err := ds.Put(data.Record{ID: resource, SubjectID: subject, Resource: resource,
			Data: d, RetainUntil: &expiredAt}); err != nil {
			t.Fatal(err)
		}
	}
	put("users/1", "s1", map[string]any{"name": "alice", "email": "a@x.com", "ssn": "111"})
	put("users/2", "s2", map[string]any{"name": "bob", "email": "b@x.com", "ssn": "222"})
	put("logs/1", "s3", map[string]any{"msg": "hello", "secret": "tok-1"})

	snap := &policy.Policy{Version: 1, Name: "ret", Retention: []policy.RetentionRule{
		{ID: "rt-users1-delete", Resources: []string{"users/1"}, Action: policy.RetentionDelete, Priority: 20},
		{ID: "rt-users-anon", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize,
			AnonymizeFields: []string{"email", "ssn"}, Priority: 10},
	}}
	return ds, lg, p, snap
}

func auditActions(lg *audit.Log) []string {
	var out []string
	for _, e := range lg.Entries() {
		out = append(out, e.Action+" "+e.Resource)
	}
	return out
}

func TestRetentionSweepByPolicy_PerResourceDisposition(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-time.Hour)
	ds, lg, p, snap := setupSweep(t, expiredAt)

	// 同一次扫描：users/1 删除、users/2 匿名化、logs/1 走兜底（匿名化 secret）
	affected, err := p.RetentionSweepByPolicy(now, snap, SweepAnonymize, []string{"secret"})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	t.Logf("SWEEP affected=%v (policy-driven, mixed dispositions)", affected)
	if len(affected) != 3 {
		t.Fatalf("all 3 expired resources must be disposed, got %v", affected)
	}

	// users/1：全部副本整条清除
	for i := 0; i < 3; i++ {
		if _, ok := ds.GetReplica(i, "users/1"); ok {
			t.Fatalf("users/1 must be deleted from replica %d", i)
		}
	}
	// users/2：全部副本 email/ssn 匿名化，name 保留，保留期标记清除
	for i := 0; i < 3; i++ {
		rec, ok := ds.GetReplica(i, "users/2")
		if !ok {
			t.Fatalf("users/2 must remain (anonymize, not delete) in replica %d", i)
		}
		if rec.Data["email"] != "<anonymized>" || rec.Data["ssn"] != "<anonymized>" || rec.Data["name"] != "bob" {
			t.Fatalf("replica %d users/2 wrong anonymization: %v", i, rec.Data)
		}
		if rec.RetainUntil != nil {
			t.Fatalf("replica %d users/2 retention marker must be cleared", i)
		}
	}
	// logs/1：无保留期策略 -> 兜底匿名化 secret，msg 保留
	rec, _ := ds.GetReplica(0, "logs/1")
	if rec.Data["secret"] != "<anonymized>" || rec.Data["msg"] != "hello" {
		t.Fatalf("logs/1 must use fallback disposition, got %v", rec.Data)
	}
	t.Logf("POLICY users/1=deleted users/2=anonymized[email,ssn] logs/1=fallback anonymized[secret]")

	// 审计：每条处置一条，动作与资源对应，链完整
	acts := auditActions(lg)
	t.Logf("AUDIT entries=%v", acts)
	if len(acts) != 3 {
		t.Fatalf("one audit entry per disposed resource, got %v", acts)
	}
	if seq, verr := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at %d: %v", seq, verr)
	}

	// 再次扫描：全部已处置，不得重复处置、不得重复写审计
	again, err := p.RetentionSweepByPolicy(now, snap, SweepAnonymize, []string{"secret"})
	if err != nil || len(again) != 0 {
		t.Fatalf("second sweep must be a no-op, affected=%v err=%v", again, err)
	}
	if lg.Len() != 3 {
		t.Fatalf("second sweep must not append audit, len=%d", lg.Len())
	}
	t.Logf("RE-SWEEP no-op: affected=0 audit_len=%d (no duplicate disposition/audit)", lg.Len())
}

func TestRetentionSweep_ReplicaFailureRecoveryConverges(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-time.Hour)
	ds, lg, p, snap := setupSweep(t, expiredAt)

	// 副本 1 故障：扫描必须显式失败，不得报成功；资源互不影响地逐个报错
	ds.SetReplicaHealthy(1, false)
	affected, err := p.RetentionSweepByPolicy(now, snap, SweepAnonymize, []string{"secret"})
	t.Logf("SWEEP with replica 1 down: affected=%v err=%v", affected, err)
	if err == nil {
		t.Fatal("sweep with an unhealthy replica must fail explicitly, never report success")
	}
	if len(affected) != 0 {
		t.Fatalf("no resource may be reported disposed while a replica is down, got %v", affected)
	}
	for _, res := range []string{"users/1", "users/2", "logs/1"} {
		if !strings.Contains(err.Error(), res) {
			t.Fatalf("aggregated error must name failed resource %s: %v", res, err)
		}
	}
	if lg.Len() != 0 {
		t.Fatalf("failed sweep must not write audit, len=%d", lg.Len())
	}
	if _, ok := ds.Get("users/1"); !ok {
		t.Fatal("failed sweep must not partially dispose data")
	}

	// 副本恢复后重跑：全部收敛，残留清干净
	ds.SetReplicaHealthy(1, true)
	affected, err = p.RetentionSweepByPolicy(now, snap, SweepAnonymize, []string{"secret"})
	if err != nil || len(affected) != 3 {
		t.Fatalf("re-run after recovery must converge all 3, affected=%v err=%v", affected, err)
	}
	for i := 0; i < 3; i++ {
		if _, ok := ds.GetReplica(i, "users/1"); ok {
			t.Fatalf("users/1 residue left in replica %d after recovery sweep", i)
		}
		rec, ok := ds.GetReplica(i, "users/2")
		if !ok || rec.Data["email"] != "<anonymized>" || rec.RetainUntil != nil {
			t.Fatalf("users/2 not converged in replica %d: %+v", i, rec)
		}
	}
	if lg.Len() != 3 {
		t.Fatalf("exactly one audit per resource after convergence, got %d", lg.Len())
	}
	t.Logf("RECOVERY re-run converged: affected=%v audit=%v", affected, auditActions(lg))

	// 第三次扫描：无重复处置、无重复审计
	again, _ := p.RetentionSweepByPolicy(now, snap, SweepAnonymize, []string{"secret"})
	if len(again) != 0 || lg.Len() != 3 {
		t.Fatalf("post-convergence sweep must be no-op, affected=%v audit=%d", again, lg.Len())
	}
	if seq, verr := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at %d: %v", seq, verr)
	}
	t.Logf("STABLE third sweep no-op; audit chain verified (%d entries)", lg.Len())
}

func TestRetentionSweep_SameResourceNewExpiryStartsNewCycle(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	exp1 := now.Add(-2 * time.Hour)
	ds, lg, p, snap := setupSweep(t, exp1)

	if _, err := p.RetentionSweepByPolicy(now, snap, SweepDelete, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := ds.Get("users/1"); ok {
		t.Fatal("users/1 must be deleted in first cycle")
	}
	before := lg.Len()

	// 同名资源被重新写入并带新的到期时刻：必须视为新一轮处置，而不是被跳过
	exp2 := now.Add(-time.Minute)
	if err := ds.Put(data.Record{ID: "users/1", SubjectID: "s9", Resource: "users/1",
		Data: map[string]any{"name": "carol"}, RetainUntil: &exp2}); err != nil {
		t.Fatal(err)
	}
	affected, err := p.RetentionSweepByPolicy(now, snap, SweepDelete, nil)
	if err != nil || len(affected) != 1 || affected[0] != "users/1" {
		t.Fatalf("new expiry of same resource must start a new disposition cycle, affected=%v err=%v", affected, err)
	}
	if _, ok := ds.Get("users/1"); ok {
		t.Fatal("re-created users/1 must be deleted again")
	}
	if lg.Len() != before+1 {
		t.Fatalf("new cycle must append its own audit, before=%d now=%d", before, lg.Len())
	}
	t.Logf("NEW-CYCLE users/1 re-created with new expiry -> disposed again, audit %d->%d", before, lg.Len())
}
