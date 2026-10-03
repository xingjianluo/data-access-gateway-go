package dsr

import (
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

// runConcurrent 用启动栅栏让 n 个 goroutine 同时提交同一请求标识。
func runConcurrent(n int, fn func(i int) (Result, error)) ([]Result, []error) {
	start := make(chan struct{})
	results := make([]Result, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
	return results, errs
}

func countAudit(lg *audit.Log, action string) int {
	n := 0
	for _, e := range lg.Entries() {
		if e.Action == action {
			n++
		}
	}
	return n
}

func TestExport_ConcurrentSameRequestID_SingleExecution(t *testing.T) {
	_, lg, p := setupDSR(t, 3)

	const n = 16
	results, errs := runConcurrent(n, func(i int) (Result, error) {
		return p.Export("exp-concurrent", "s1")
	})

	var first *Result
	fresh := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d got error: %v", i, errs[i])
		}
		if !results[i].Idempotent {
			fresh++
			r := results[i]
			first = &r
		}
	}
	if fresh != 1 {
		t.Fatalf("exactly one goroutine may execute, got %d fresh executions", fresh)
	}
	// 所有重放结果必须与首次执行一致
	for i, r := range results {
		if len(r.Records) != len(first.Records) || r.AuditSeqs[0] != first.AuditSeqs[0] || r.Status != StatusCompleted {
			t.Fatalf("replay %d diverges from first result: %+v vs %+v", i, r, first)
		}
	}
	if got := countAudit(lg, "dsr.export"); got != 1 {
		t.Fatalf("concurrent duplicates must produce exactly 1 export audit, got %d", got)
	}
	t.Logf("CONCURRENT EXPORT n=%d: fresh=1 replays=%d audit_export=1 seqs=%v (single execution, consistent replay)",
		n, n-1, first.AuditSeqs)
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at %d: %v", seq, err)
	}
}

func TestDelete_ConcurrentSameRequestID_SingleExecution(t *testing.T) {
	_, lg, p := setupDSR(t, 3)

	const n = 16
	results, errs := runConcurrent(n, func(i int) (Result, error) {
		return p.Delete("del-concurrent", "s1")
	})

	fresh := 0
	var first *Result
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d got error: %v", i, errs[i])
		}
		if !results[i].Idempotent {
			fresh++
			r := results[i]
			first = &r
		}
	}
	if fresh != 1 {
		t.Fatalf("exactly one goroutine may execute, got %d", fresh)
	}
	// s1 有 2 条记录 -> 恰好 2 条删除审计，不重复
	if got := countAudit(lg, "dsr.delete"); got != 2 {
		t.Fatalf("concurrent duplicates must produce exactly 2 delete audits (one per resource), got %d", got)
	}
	for i, r := range results {
		if len(r.AuditSeqs) != 2 || r.AuditSeqs[0] != first.AuditSeqs[0] || r.AuditSeqs[1] != first.AuditSeqs[1] {
			t.Fatalf("replay %d must carry the same audit seqs as first execution: %+v", i, r)
		}
	}
	t.Logf("CONCURRENT DELETE n=%d: fresh=1 replays=%d audit_delete=2 seqs=%v", n, n-1, first.AuditSeqs)
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at %d: %v", seq, err)
	}
}

func TestDelete_ConcurrentRetryAfterFailure_SingleFinalAudit(t *testing.T) {
	ds, lg, p := setupDSR(t, 3)

	// 第一阶段：副本故障，并发提交全部失败，且不产生任何审计
	ds.SetReplicaHealthy(2, false)
	_, errs := runConcurrent(8, func(i int) (Result, error) {
		return p.Delete("del-retry", "s1")
	})
	for i, err := range errs {
		if err == nil {
			t.Fatalf("goroutine %d must fail while replica 2 is down", i)
		}
	}
	if lg.Len() != 0 {
		t.Fatalf("failed attempts must not write audit, got %d", lg.Len())
	}
	if len(ds.FindBySubject("s1")) != 2 {
		t.Fatal("failed attempts must not partially delete")
	}
	t.Logf("RETRY phase1: 8 concurrent attempts all failed cleanly, audit=0, data intact")

	// 第二阶段：恢复后并发重试同一标识 -> 只有一次真正执行，最终审计不重复
	ds.SetReplicaHealthy(2, true)
	results, errs2 := runConcurrent(8, func(i int) (Result, error) {
		return p.Delete("del-retry", "s1")
	})
	fresh := 0
	for i := range results {
		if errs2[i] != nil {
			t.Fatalf("retry goroutine %d: %v", i, errs2[i])
		}
		if !results[i].Idempotent {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("exactly one retry may execute, got %d", fresh)
	}
	if got := countAudit(lg, "dsr.delete"); got != 2 {
		t.Fatalf("after retry success there must be exactly one final audit set (2 entries), got %d", got)
	}
	for i := 0; i < 3; i++ {
		if left := ds.ExportReplica(i, "s1"); len(left) != 0 {
			t.Fatalf("replica %d still holds s1 data after retry", i)
		}
	}
	t.Logf("RETRY phase2: fresh=1 replays=7 final_audit=2 (no duplicate success records)")
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at %d: %v", seq, err)
	}
}

func TestExport_ConcurrentDistinctIDs_Independent(t *testing.T) {
	_, lg, p := setupDSR(t, 3)

	// 不同请求标识互不影响：每个都真实执行一次
	const n = 8
	results, errs := runConcurrent(n, func(i int) (Result, error) {
		return p.Export(fmt.Sprintf("exp-distinct-%d", i), "s1")
	})
	for i := range results {
		if errs[i] != nil || results[i].Idempotent {
			t.Fatalf("distinct request %d must execute fresh: %+v err=%v", i, results[i], errs[i])
		}
	}
	if got := countAudit(lg, "dsr.export"); got != n {
		t.Fatalf("each distinct request writes its own audit, got %d want %d", got, n)
	}
	t.Logf("DISTINCT IDS: %d requests -> %d fresh executions, %d audits", n, n, n)
}
