package dsr

import (
	"sync"
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

// runConcurrent 用屏障让 n 个 goroutine 同时提交同一请求，收集各自结果。
func runConcurrent(n int, fn func() (Result, error)) ([]Result, []error) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]Result, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx], errs[idx] = fn()
		}(i)
	}
	close(start)
	wg.Wait()
	return results, errs
}

func countAuditAction(lg *audit.Log, action string) int {
	n := 0
	for _, e := range lg.Entries() {
		if e.Action == action {
			n++
		}
	}
	return n
}

// TestExport_ConcurrentSameId_SingleExecution 覆盖：同一请求标识被同时提交多次时，
// 只有一个真正执行，其余显式返回"重放"且拿到与首次一致的结果；审计只写一条。
func TestExport_ConcurrentSameId_SingleExecution(t *testing.T) {
	const n = 32
	_, lg, p := setupDSR(t, 3)

	results, errs := runConcurrent(n, func() (Result, error) { return p.Export("exp-conc", "s1") })

	executed, replayed := 0, 0
	var wantSeqs []int64
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: unexpected error %v", i, errs[i])
		}
		r := results[i]
		t.Logf("goroutine %2d -> Idempotent=%-5t status=%s auditSeqs=%v records=%d",
			i, r.Idempotent, r.Status, r.AuditSeqs, len(r.Records))
		if r.Status != StatusCompleted || len(r.Records) != 2 {
			t.Fatalf("goroutine %d: bad result %+v", i, r)
		}
		if r.Idempotent {
			replayed++
		} else {
			executed++
		}
		if wantSeqs == nil {
			wantSeqs = r.AuditSeqs
		} else if len(r.AuditSeqs) != len(wantSeqs) || r.AuditSeqs[0] != wantSeqs[0] {
			t.Fatalf("goroutine %d: 重放结果与首次不一致: %v vs %v", i, r.AuditSeqs, wantSeqs)
		}
	}
	t.Logf("判定: 并发 %d 次提交 -> 真正执行 %d 次, 显式重放 %d 次", n, executed, replayed)
	if executed != 1 || replayed != n-1 {
		t.Fatalf("应恰有 1 次真正执行、%d 次重放: executed=%d replayed=%d", n-1, executed, replayed)
	}
	if got := countAuditAction(lg, "dsr.export"); got != 1 {
		t.Fatalf("导出审计应恰为 1 条, got %d", got)
	}
	t.Logf("审计条数=%d（恰一条，无重复写审计）", lg.Len())
}

// TestDelete_ConcurrentSameId_SingleExecution 覆盖：删除请求并发同 ID 提交时
// 只执行一次，审计中每个被删资源恰有一条删除记录。
func TestDelete_ConcurrentSameId_SingleExecution(t *testing.T) {
	const n = 32
	ds, lg, p := setupDSR(t, 3)

	results, errs := runConcurrent(n, func() (Result, error) { return p.Delete("del-conc", "s1") })

	executed := 0
	var wantSeqs []int64
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: unexpected error %v", i, errs[i])
		}
		if !results[i].Idempotent {
			executed++
		}
		if wantSeqs == nil {
			wantSeqs = results[i].AuditSeqs
		} else {
			if len(results[i].AuditSeqs) != len(wantSeqs) {
				t.Fatalf("goroutine %d: 重放结果与首次不一致: %v vs %v", i, results[i].AuditSeqs, wantSeqs)
			}
			for j := range wantSeqs {
				if results[i].AuditSeqs[j] != wantSeqs[j] {
					t.Fatalf("goroutine %d: 重放结果与首次不一致: %v vs %v", i, results[i].AuditSeqs, wantSeqs)
				}
			}
		}
	}
	t.Logf("判定: 并发 %d 次删除提交 -> 真正执行 %d 次", n, executed)
	if executed != 1 {
		t.Fatalf("应恰有 1 次真正执行, got %d", executed)
	}
	// s1 有 2 条记录 -> 恰 2 条删除审计，且无重复。
	if got := countAuditAction(lg, "dsr.delete"); got != 2 {
		t.Fatalf("删除审计应恰为 2 条(每资源一条), got %d", got)
	}
	for i := 0; i < ds.ReplicaCount(); i++ {
		if left := ds.ExportReplica(i, "s1"); len(left) != 0 {
			t.Fatalf("副本 %d 仍有 s1 残留", i)
		}
	}
	t.Logf("删除审计条数=%d（users/1、users/2 各一条），全部副本无残留", lg.Len())
}

// TestDelete_ConcurrentRetryAfterFailure_SingleSuccessAudit 覆盖：首次执行因副本
// 故障失败后，凭同一标识并发重试，重试成功后审计里只有一份最终结果。
func TestDelete_ConcurrentRetryAfterFailure_SingleSuccessAudit(t *testing.T) {
	const n = 16
	ds, lg, p := setupDSR(t, 3)

	// 首次：副本 2 故障 -> 失败，可凭同一 ID 重试。
	ds.SetReplicaHealthy(2, false)
	if _, err := p.Delete("del-retry", "s1"); err == nil {
		t.Fatal("副本故障时删除必须失败")
	} else {
		t.Logf("首次执行按预期失败(可重试): %v", err)
	}
	if got := countAuditAction(lg, "dsr.delete"); got != 0 {
		t.Fatalf("失败的删除不应产生成功审计, got %d", got)
	}

	// 恢复后并发重试同一 ID：只有一个真正执行，其余重放同一结果。
	ds.SetReplicaHealthy(2, true)
	results, errs := runConcurrent(n, func() (Result, error) { return p.Delete("del-retry", "s1") })
	executed := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: retry error %v", i, errs[i])
		}
		if results[i].Status != StatusCompleted {
			t.Fatalf("goroutine %d: status=%s", i, results[i].Status)
		}
		if !results[i].Idempotent {
			executed++
		}
	}
	t.Logf("判定: 并发 %d 次重试 -> 真正执行 %d 次", n, executed)
	if executed != 1 {
		t.Fatalf("重试应恰有 1 次真正执行, got %d", executed)
	}
	// 审计里只有一份最终结果：2 条资源删除记录，无重复成功记录。
	if got := countAuditAction(lg, "dsr.delete"); got != 2 {
		t.Fatalf("重试成功后删除审计应恰为 2 条, got %d", got)
	}
	for i := 0; i < ds.ReplicaCount(); i++ {
		if left := ds.ExportReplica(i, "s1"); len(left) != 0 {
			t.Fatalf("副本 %d 仍有 s1 残留", i)
		}
	}
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("审计链应完整: badSeq=%d err=%v", seq, err)
	}
	t.Logf("最终审计条数=%d（一份最终结果），审计链完整", lg.Len())
}

// TestRequestIDConflict_Rejected 同一请求标识被用于不同类型/主体的请求时显式拒绝。
func TestRequestIDConflict_Rejected(t *testing.T) {
	_, _, p := setupDSR(t, 3)
	if _, err := p.Export("req-x", "s1"); err != nil {
		t.Fatalf("first export: %v", err)
	}
	if _, err := p.Export("req-x", "s2"); err == nil {
		t.Fatal("同 ID 不同主体应被拒绝")
	} else {
		t.Logf("同 ID 不同主体被拒绝: %v", err)
	}
	if _, err := p.Delete("req-x", "s1"); err == nil {
		t.Fatal("同 ID 不同类型应被拒绝")
	} else {
		t.Logf("同 ID 不同类型被拒绝: %v", err)
	}
}
