package dsr

import (
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
)

func setupDSR(t *testing.T, replicas int) (*data.Store, *audit.Log, *Processor) {
	t.Helper()
	ds := data.NewStore(replicas)
	lg := audit.NewLog()
	p := New(ds, lg)
	ds.Put(data.Record{ID: "users/1", SubjectID: "s1", Resource: "users/1",
		Data: map[string]any{"email": "a@x.com", "ssn": "111"}})
	ds.Put(data.Record{ID: "users/2", SubjectID: "s1", Resource: "users/2",
		Data: map[string]any{"email": "b@x.com", "ssn": "222"}})
	ds.Put(data.Record{ID: "users/3", SubjectID: "s2", Resource: "users/3",
		Data: map[string]any{"email": "c@x.com"}})
	return ds, lg, p
}

func TestExport_CoversAllReplicas_AndIdempotent(t *testing.T) {
	_, lg, p := setupDSR(t, 3)

	res, err := p.Export("exp-1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Idempotent {
		t.Fatal("first execution must not be marked idempotent")
	}
	if len(res.Records) != 2 || res.Replicas != 3 {
		t.Fatalf("export must cover s1's 2 records, replicas=3, got %d/%d", len(res.Records), res.Replicas)
	}
	t.Logf("EXPORT first : records=%d replicas=%d status=%s auditSeqs=%v",
		len(res.Records), res.Replicas, res.Status, res.AuditSeqs)

	// 重复请求：幂等返回首次结果并显式标记，而非静默成功
	res2, err := p.Export("exp-1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Idempotent || len(res2.Records) != 2 {
		t.Fatalf("repeat request must be idempotent with original payload, got %+v", res2)
	}
	if lg.Len() != 1 {
		t.Fatalf("idempotent replay must not append a second audit entry, len=%d", lg.Len())
	}
	t.Logf("EXPORT replay: Idempotent=%v (explicit, not silent success)", res2.Idempotent)

	// 不同 ID 是一个新请求
	res3, err := p.Export("exp-2", "s1")
	if err != nil || res3.Idempotent {
		t.Fatalf("new request id must execute fresh: %+v err=%v", res3, err)
	}
}

func TestCompareReplicasDetectsDivergence(t *testing.T) {
	now := time.Now().UTC()
	base := []data.Record{{Resource: "users/1", SubjectID: "s1",
		Data: map[string]any{"email": "a@x.com"}, UpdatedAt: now}}
	// 数据值分歧
	diverged := []data.Record{{Resource: "users/1", SubjectID: "s1",
		Data: map[string]any{"email": "MUTATED"}, UpdatedAt: now}}
	if err := compareReplicas([][]data.Record{base, diverged}); err == nil {
		t.Fatal("data divergence between replicas must fail export coverage check")
	} else {
		t.Logf("DIVERGENCE DETECTED: %v", err)
	}
	// 记录数分歧
	if err := compareReplicas([][]data.Record{base, {}}); err == nil {
		t.Fatal("missing record on a replica must fail export coverage check")
	}
	// 一致
	if err := compareReplicas([][]data.Record{base, cloneRecs(base)}); err != nil {
		t.Fatalf("identical replicas must pass: %v", err)
	}
}

func cloneRecs(in []data.Record) []data.Record {
	out := make([]data.Record, len(in))
	copy(out, in)
	return out
}

func TestDelete_AllReplicasRetryIdempotent(t *testing.T) {
	ds, lg, p := setupDSR(t, 3)

	// 先制造失败：副本 2 不健康 -> 删除必须失败且带原因，可重试
	ds.SetReplicaHealthy(2, false)
	if _, err := p.Delete("del-1", "s1"); err == nil {
		t.Fatal("delete with unhealthy replica must fail, never silently succeed")
	} else {
		t.Logf("DELETE expected failure (retryable): %v", err)
	}
	// 数据仍在（存储层预检，未发生部分删除）
	if len(ds.FindBySubject("s1")) != 2 {
		t.Fatal("failed delete must not partially remove data")
	}

	// 恢复后用同一请求 ID 重试 -> 成功并覆盖全部副本
	ds.SetReplicaHealthy(2, true)
	res, err := p.Delete("del-1", "s1")
	if err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
	if res.Idempotent || res.Replicas != 3 {
		t.Fatalf("retry after failure executes fresh across 3 replicas, got %+v", res)
	}
	for i := 0; i < 3; i++ {
		if len(ds.ExportReplica(i, "s1")) != 0 {
			t.Fatalf("replica %d still contains s1 data", i)
		}
	}
	// 其他主体不受影响
	if len(ds.FindBySubject("s2")) != 1 {
		t.Fatal("delete must be scoped to the requesting subject")
	}
	t.Logf("DELETE retry success: replicas=%d auditSeqs=%v", res.Replicas, res.AuditSeqs)

	// 重复删除：幂等可识别
	res2, err := p.Delete("del-1", "s1")
	if err != nil || !res2.Idempotent || res2.Status != StatusCompleted {
		t.Fatalf("repeat delete must replay completed result, got %+v err=%v", res2, err)
	}

	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain must be intact after delete/failure/retry, badSeq=%d err=%v", seq, err)
	}
	t.Logf("DELETE idempotent replay recognized; audit chain verified")
}

func TestRetentionSweep_DeleteAndAnonymizeBoundary(t *testing.T) {
	ds, lg, p := setupDSR(t, 2)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	expAt := now.Add(-24 * time.Hour)

	// 给 users/1 设置昨天到期
	rec, _ := ds.Get("users/1")
	rec.RetainUntil = &expAt
	if err := ds.Put(rec); err != nil {
		t.Fatal(err)
	}

	// now-48h 时还不应被清理（边界前）
	if a, _ := p.RetentionSweep(now.Add(-48*time.Hour), SweepDelete, nil); len(a) != 0 {
		t.Fatalf("nothing is expired 48h ago, got %v", a)
	}
	// now 时 users/1 到期，清除
	affected, err := p.RetentionSweep(now, SweepDelete, nil)
	if err != nil || len(affected) != 1 || affected[0] != "users/1" {
		t.Fatalf("sweep delete affected=%v err=%v", affected, err)
	}
	if _, ok := ds.Get("users/1"); ok {
		t.Fatal("expired record must be deleted from replicas")
	}
	if len(ds.ExportReplica(1, "s1")) != 1 { // users/2 保留
		t.Fatal("non-expired record must remain in every replica")
	}
	t.Logf("SWEEP delete: affected=%v", affected)

	// 匿名化路径
	rec2, _ := ds.Get("users/2")
	rec2.RetainUntil = &expAt
	ds.Put(rec2)
	affected2, err := p.RetentionSweep(now, SweepAnonymize, []string{"email", "ssn"})
	if err != nil || len(affected2) != 1 || affected2[0] != "users/2" {
		t.Fatalf("sweep anonymize affected=%v err=%v", affected2, err)
	}
	for i := 0; i < 2; i++ {
		got := ds.ExportReplica(i, "s1")[0]
		if got.Data["email"] != "<anonymized>" || got.Data["ssn"] != "<anonymized>" {
			t.Fatalf("replica %d not anonymized: %v", i, got.Data)
		}
	}
	// 再次 sweep：已无到期记录，结果为空且幂等
	again, _ := p.RetentionSweep(now, SweepAnonymize, []string{"email"})
	if len(again) != 0 {
		t.Fatalf("second sweep must be a no-op, got %v", again)
	}
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain bad at %d: %v", seq, err)
	}
	t.Logf("SWEEP anonymize: affected=%v; second sweep no-op; audit entries=%d verified", affected2, lg.Len())
}
