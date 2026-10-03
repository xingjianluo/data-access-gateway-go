package dsr

import (
	"strings"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

func expiredRecord(resource, subject string, retainUntil time.Time, fields map[string]any) data.Record {
	return data.Record{ID: resource, SubjectID: subject, Resource: resource, Data: fields, RetainUntil: &retainUntil}
}

// TestSweepWithPolicy_PerResourceDisposition 覆盖：同一次到期扫描中，不同资源按策略
// 走不同处置（users/* 匿名化指定字段、logs/* 整条清除），未配置策略的资源走兜底，
// 互不影响；审计逐条记录且带策略版本。
func TestSweepWithPolicy_PerResourceDisposition(t *testing.T) {
	ds := data.NewStore(3)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	mustPut := func(rec data.Record) {
		if err := ds.Put(rec); err != nil {
			t.Fatalf("put %s: %v", rec.Resource, err)
		}
	}
	mustPut(expiredRecord("users/1", "subj-1", past, map[string]any{"email": "a@x.com", "name": "ann", "city": "sh"}))
	mustPut(expiredRecord("logs/2026-09", "subj-2", past, map[string]any{"line": "..."}))
	mustPut(expiredRecord("orders/1", "subj-3", past, map[string]any{"total": 42}))

	snap := &policy.Policy{
		Version: 7,
		Retention: []policy.RetentionRule{
			{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
			{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
		},
	}

	affected, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	t.Logf("输入: 3 条到期记录(users/1, logs/2026-09, orders/1)，策略 v7: users/*->anonymize[email], logs/*->delete；orders/* 未配置->兜底 delete")
	t.Logf("扫描结果 affected=%v", affected)
	if len(affected) != 3 {
		t.Fatalf("affected=%v, want 3 resources", affected)
	}

	// users/1：按策略匿名化 email，其余字段与记录本身保留。
	rec, ok := ds.Get("users/1")
	if !ok {
		t.Fatal("users/1 应保留（匿名化而非删除）")
	}
	t.Logf("users/1 处置后数据=%v retainUntil=%v", rec.Data, rec.RetainUntil)
	if rec.Data["email"] != "<anonymized>" || rec.Data["name"] != "ann" || rec.Data["city"] != "sh" {
		t.Fatalf("users/1 anonymize wrong: %v", rec.Data)
	}
	if rec.RetainUntil != nil {
		t.Fatal("users/1 匿名化后保留期标记应清除")
	}
	// logs/2026-09 与 orders/1：整条清除。
	for _, r := range []string{"logs/2026-09", "orders/1"} {
		if _, ok := ds.Get(r); ok {
			t.Fatalf("%s 应被整条清除", r)
		}
	}

	// 审计：每条资源一条处置记录，动作与策略版本正确。
	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("audit entries=%d, want 3", len(entries))
	}
	byRes := map[string]audit.Entry{}
	for _, e := range entries {
		byRes[e.Resource] = e
		t.Logf("audit seq=%d action=%s resource=%s policyVer=%d reason=%q", e.Seq, e.Action, e.Resource, e.PolicyVer, e.Reason)
		if e.PolicyVer != 7 {
			t.Fatalf("seq %d: policy version=%d want 7", e.Seq, e.PolicyVer)
		}
	}
	if byRes["users/1"].Action != "retention.anonymize" || !strings.Contains(byRes["users/1"].Reason, "anon-users") {
		t.Fatalf("users/1 audit wrong: %+v", byRes["users/1"])
	}
	if byRes["logs/2026-09"].Action != "retention.delete" || !strings.Contains(byRes["logs/2026-09"].Reason, "del-logs") {
		t.Fatalf("logs audit wrong: %+v", byRes["logs/2026-09"])
	}
	if byRes["orders/1"].Action != "retention.delete" || !strings.Contains(byRes["orders/1"].Reason, "fallback") {
		t.Fatalf("orders/1 应走兜底 delete: %+v", byRes["orders/1"])
	}

	// 再次扫描：已处置资源不重复处置、不重复写审计。
	again, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("re-sweep: %v", err)
	}
	t.Logf("二次扫描 affected=%v, 审计条数=%d（应仍为 3）", again, log.Len())
	if len(again) != 0 || log.Len() != 3 {
		t.Fatalf("重复处置: again=%v auditLen=%d", again, log.Len())
	}
}

// TestSweepWithPolicy_ReplicaFailureRecovery 覆盖：扫描中途副本不可用 -> 整体报错
// （不报成功）；副本恢复后重跑把残留清干净，且审计只有一份最终处置记录。
func TestSweepWithPolicy_ReplicaFailureRecovery(t *testing.T) {
	ds := data.NewStore(3)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	if err := ds.Put(expiredRecord("users/9", "subj-9", past, map[string]any{"email": "b@x.com"})); err != nil {
		t.Fatalf("put: %v", err)
	}
	snap := &policy.Policy{Version: 1, Retention: []policy.RetentionRule{
		{ID: "del-users", Resources: []string{"users/*"}, Action: policy.RetentionDelete, Priority: 1},
	}}

	// 副本 1 故障：扫描必须失败且明确可重试，绝不能报成功。
	ds.SetReplicaHealthy(1, false)
	affected, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	t.Logf("副本1故障时扫描: affected=%v err=%v", affected, err)
	if err == nil {
		t.Fatal("副本故障时扫描不应报成功")
	}
	if len(affected) != 0 {
		t.Fatalf("失败扫描不应报告已处置资源: %v", affected)
	}
	if !strings.Contains(err.Error(), "retryable") {
		t.Fatalf("错误应明确可重试: %v", err)
	}
	// 故障期间记录仍在（预检阻止了部分写入）。
	if !ds.ReplicaHas(0, "users/9") || !ds.ReplicaHas(2, "users/9") {
		t.Fatal("预检应阻止部分写入，记录应仍在各健康副本")
	}

	// 副本恢复后重跑：残留清干净，全部副本一致。
	ds.SetReplicaHealthy(1, true)
	affected, err = p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("恢复后重跑: %v", err)
	}
	t.Logf("恢复后重跑: affected=%v", affected)
	if len(affected) != 1 || affected[0] != "users/9" {
		t.Fatalf("affected=%v, want [users/9]", affected)
	}
	for i := 0; i < ds.ReplicaCount(); i++ {
		if ds.ReplicaHas(i, "users/9") {
			t.Fatalf("副本 %d 仍有残留 users/9", i)
		}
	}
	t.Logf("全部 %d 个副本均无残留", ds.ReplicaCount())

	// 审计只有一条最终处置记录；再跑不产生新审计。
	delCount := 0
	for _, e := range log.Entries() {
		if e.Resource == "users/9" && e.Action == "retention.delete" {
			delCount++
		}
	}
	if delCount != 1 || log.Len() != 1 {
		t.Fatalf("处置审计应恰为 1 条: delCount=%d total=%d", delCount, log.Len())
	}
	if again, _ := p.SweepWithPolicy(now, snap, SweepDelete, nil); len(again) != 0 || log.Len() != 1 {
		t.Fatalf("重跑重复处置: again=%v auditLen=%d", again, log.Len())
	}
	t.Logf("审计条数=%d（恰一条最终处置记录），重扫无新增", log.Len())
}

// TestSweepWithPolicy_ExpiryBoundary 到期边界口径与既有 RetentionSweep 一致：
// 严格 RetainUntil < now，到期时刻本身不处置，晚 1 纳秒才处置。
func TestSweepWithPolicy_ExpiryBoundary(t *testing.T) {
	ds := data.NewStore(2)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	if err := ds.Put(expiredRecord("users/b", "subj-b", now, map[string]any{"x": 1})); err != nil {
		t.Fatalf("put: %v", err)
	}
	snap := &policy.Policy{Version: 1, Retention: []policy.RetentionRule{
		{ID: "del-users", Resources: []string{"users/*"}, Action: policy.RetentionDelete},
	}}

	affected, _ := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	t.Logf("RetainUntil==now 时扫描: affected=%v（边界口径：到期时刻本身未到期）", affected)
	if len(affected) != 0 {
		t.Fatalf("到期时刻本身不应处置: %v", affected)
	}
	affected, _ = p.SweepWithPolicy(now.Add(time.Nanosecond), snap, SweepDelete, nil)
	t.Logf("now+1ns 时扫描: affected=%v", affected)
	if len(affected) != 1 || affected[0] != "users/b" {
		t.Fatalf("晚 1ns 应处置: %v", affected)
	}
}
