package dsr

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// auditFor 返回某资源某处置动作的审计条数，用于断言"每种处置恰一条记录"。
func auditFor(t *testing.T, log *audit.Log, resource, action string) int {
	t.Helper()
	n := 0
	for _, e := range log.Entries() {
		if e.Resource == resource && e.Action == action {
			n++
		}
	}
	return n
}

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
	var incomplete *SweepIncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("副本故障时扫描应返回 *SweepIncompleteError，got %v", err)
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

// TestSweepWithPolicy_OneResourceFailureDoesNotBlockOthers 覆盖核心语义：
// 同一轮到期扫描里某个资源因其存储副本故障处置失败时，扫描不中断——
// 其余该清除/该匿名化的资源照常完成，且各自留下一条处置审计；
// 本轮整体必须报错（明确可重试、可程序判断），失败资源不写成功审计、不入处置台账。
func TestSweepWithPolicy_OneResourceFailureDoesNotBlockOthers(t *testing.T) {
	ds := data.NewStore(3)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	// 三条到期资源：users/1 按策略匿名化、logs/a 按策略清除、orders/1 走兜底清除。
	mustPut := func(rec data.Record) {
		if err := ds.Put(rec); err != nil {
			t.Fatalf("put %s: %v", rec.Resource, err)
		}
	}
	mustPut(expiredRecord("users/1", "subj-1", past, map[string]any{"email": "a@x.com", "name": "ann"}))
	mustPut(expiredRecord("logs/a", "subj-2", past, map[string]any{"line": "..."}))
	mustPut(expiredRecord("orders/1", "subj-3", past, map[string]any{"total": 42}))
	snap := &policy.Policy{Version: 9, Retention: []policy.RetentionRule{
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
	}}
	t.Logf("输入: 3 条到期资源；策略 v9: users/*->anonymize[email], logs/*->delete；orders/*->兜底 delete")

	// 故障注入：只有 logs/a 的删除失败（其余资源的操作不受影响）。
	ds.SetResourceFault("delete", "logs/a", true)
	t.Logf("故障注入: 仅 logs/a 的 delete 操作失败（单资源副本故障，预检前失败无部分写入）")

	affected, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	t.Logf("第 1 轮扫描: affected=%v err=%v", affected, err)

	// 本轮不能报成功：错误必须是 *SweepIncompleteError 且明确可重试、点名 logs/a。
	var incomplete *SweepIncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("单资源失败时应返回 *SweepIncompleteError，got %v", err)
	}
	if !strings.Contains(err.Error(), "retryable") || !strings.Contains(err.Error(), "logs/a") {
		t.Fatalf("错误应明确可重试并点名失败资源: %v", err)
	}
	if len(incomplete.Failed) != 1 || incomplete.Failed[0].Resource != "logs/a" {
		t.Fatalf("失败清单应只有 logs/a: %+v", incomplete.Failed)
	}

	// 同轮其余资源照常处置：users/1 已匿名化并清保留期、orders/1 已整条清除。
	if rec, ok := ds.Get("users/1"); !ok || rec.Data["email"] != "<anonymized>" || rec.RetainUntil != nil {
		t.Fatalf("users/1 不应被 logs/a 的故障拖累: ok=%v rec=%+v", ok, rec)
	}
	if _, ok := ds.Get("orders/1"); ok {
		t.Fatal("orders/1 不应被 logs/a 的故障拖累，应已整条清除")
	}
	// 失败资源未产生部分写入：三个副本里 logs/a 都还在。
	for i := 0; i < ds.ReplicaCount(); i++ {
		if !ds.ReplicaHas(i, "logs/a") {
			t.Fatalf("logs/a 预检失败不应产生部分写入，副本 %d 中应仍在", i)
		}
	}

	// 成功处置的资源返回在 affected 中（排序），各恰一条审计；失败资源无成功审计。
	if len(affected) != 2 || affected[0] != "orders/1" || affected[1] != "users/1" {
		t.Fatalf("affected=%v, want [orders/1 users/1]", affected)
	}
	if n := auditFor(t, log, "users/1", "retention.anonymize"); n != 1 {
		t.Fatalf("users/1 anonymize 审计=%d 条, want 1", n)
	}
	if n := auditFor(t, log, "orders/1", "retention.delete"); n != 1 {
		t.Fatalf("orders/1 delete 审计=%d 条, want 1", n)
	}
	if n := auditFor(t, log, "logs/a", "retention.delete"); n != 0 {
		t.Fatalf("失败资源 logs/a 不应写成功审计, got %d 条", n)
	}
	t.Logf("第 1 轮后审计: users/1 anonymize=1, orders/1 delete=1, logs/a delete=0, 总数=%d", log.Len())

	// 故障未恢复前重跑：已成功的资源由台账跳过（不重复处置、不重复审计），
	// logs/a 仍失败，本轮仍不能报成功。
	affected, err = p.SweepWithPolicy(now, snap, SweepDelete, nil)
	t.Logf("故障未恢复重跑: affected=%v err=%v, 审计总数=%d", affected, err, log.Len())
	if err == nil {
		t.Fatal("仍有失败资源时重跑不能报成功")
	}
	if len(affected) != 0 {
		t.Fatalf("已处置资源应被台账跳过，affected=%v", affected)
	}
	if rec, ok := ds.Get("users/1"); !ok || rec.Data["name"] != "ann" {
		t.Fatalf("users/1 重跑不应被重复处置: %+v", rec)
	}
	if log.Len() != 2 {
		t.Fatalf("重跑不应重复写审计: total=%d want 2", log.Len())
	}

	// 故障恢复后重跑：只剩 logs/a 被补齐，全部副本无残留；本轮报成功。
	ds.SetResourceFault("delete", "logs/a", false)
	t.Log("故障恢复：解除 logs/a 的 delete 故障注入")
	affected, err = p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("恢复后重跑应收敛报成功: %v", err)
	}
	t.Logf("恢复后重跑: affected=%v", affected)
	if len(affected) != 1 || affected[0] != "logs/a" {
		t.Fatalf("应只补齐 logs/a: %v", affected)
	}
	for i := 0; i < ds.ReplicaCount(); i++ {
		if ds.ReplicaHas(i, "logs/a") {
			t.Fatalf("副本 %d 仍有 logs/a 残留", i)
		}
	}

	// 每种处置最终恰一条审计；再跑完全收敛、无新增审计。
	if n := auditFor(t, log, "logs/a", "retention.delete"); n != 1 {
		t.Fatalf("logs/a 最终 delete 审计=%d 条, want 1", n)
	}
	again, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("全部收敛后重跑不应报错: %v", err)
	}
	if len(again) != 0 || log.Len() != 3 {
		t.Fatalf("收敛后重跑不应再处置/写审计: again=%v auditLen=%d", again, log.Len())
	}
	t.Logf("收敛: 3 条到期资源各 1 条处置审计(总数=%d)，再次扫描无新增、无错误", log.Len())
}

// TestSweepWithPolicy_BadRuleAndAnonymizeFailure 覆盖另一类失败来源——保留期规则
// 内容有误（未知 action）以及匿名化处置的单资源故障：同样不拖累同轮其他资源，
// 规则修好 / 副本恢复后重跑补齐，审计不重复。
func TestSweepWithPolicy_BadRuleAndAnonymizeFailure(t *testing.T) {
	ds := data.NewStore(2)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	if err := ds.Put(expiredRecord("users/a", "s1", past, map[string]any{"email": "a@x.com"})); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ds.Put(expiredRecord("users/b", "s2", past, map[string]any{"email": "b@x.com"})); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ds.Put(expiredRecord("logs/x", "s3", past, map[string]any{"line": "x"})); err != nil {
		t.Fatalf("put: %v", err)
	}

	// 第 1 轮策略：users/a 的规则声明了未知 action（规则内容问题）。
	badSnap := &policy.Policy{Version: 3, Retention: []policy.RetentionRule{
		{ID: "broken-users-a", Resources: []string{"users/a"}, Action: policy.RetentionAction("purge"), Priority: 20},
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
	}}
	t.Logf("输入: users/a 命中规则 broken-users-a 的未知 action=purge；users/b 匿名化；logs/x 清除")

	// 同时让 users/b 的匿名化操作失败：一轮里出现两个不同资源的失败。
	ds.SetResourceFault("anonymize", "users/b", true)

	affected, err := p.SweepWithPolicy(now, badSnap, SweepDelete, nil)
	t.Logf("第 1 轮扫描: affected=%v err=%v", affected, err)
	var incomplete *SweepIncompleteError
	if !errors.As(err, &incomplete) || len(incomplete.Failed) != 2 {
		t.Fatalf("应有 users/a(规则坏) 与 users/b(副本故障) 两条失败, got %v", err)
	}
	// logs/x 与两个失败资源无关，照常清除并留痕。
	if len(affected) != 1 || affected[0] != "logs/x" {
		t.Fatalf("只有 logs/x 应在本轮完成: %v", affected)
	}
	if _, ok := ds.Get("logs/x"); ok {
		t.Fatal("logs/x 不应被其他资源的问题拖累")
	}
	if n := auditFor(t, log, "logs/x", "retention.delete"); n != 1 {
		t.Fatalf("logs/x 审计=%d want 1", n)
	}
	if rec, ok := ds.Get("users/a"); !ok || rec.Data["email"] != "a@x.com" {
		t.Fatalf("规则坏掉的 users/a 不应被处置: %+v", rec)
	}
	t.Logf("第 1 轮后: users/a 未动(规则内容问题)、users/b 未动(副本故障)、logs/x 已清除")

	// 第 2 轮：只修好副本（策略仍是坏的）——users/b 补齐匿名化，users/a 仍失败。
	ds.SetResourceFault("anonymize", "users/b", false)
	affected, err = p.SweepWithPolicy(now, badSnap, SweepDelete, nil)
	t.Logf("第 2 轮(副本恢复、规则未修): affected=%v err=%v", affected, err)
	if err == nil {
		t.Fatal("users/a 的规则仍坏，本轮不能报成功")
	}
	if len(affected) != 1 || affected[0] != "users/b" {
		t.Fatalf("本轮应只补齐 users/b: %v", affected)
	}
	if rec, ok := ds.Get("users/b"); !ok || rec.Data["email"] != "<anonymized>" || rec.RetainUntil != nil {
		t.Fatalf("users/b 应已匿名化并清保留期: %+v", rec)
	}
	if n := auditFor(t, log, "users/b", "retention.anonymize"); n != 1 {
		t.Fatalf("users/b 审计=%d want 1", n)
	}

	// 第 3 轮：规则修好（users/a 也走匿名化）——收敛报成功；审计不重复。
	goodSnap := &policy.Policy{Version: 4, Retention: []policy.RetentionRule{
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
	}}
	affected, err = p.SweepWithPolicy(now, goodSnap, SweepDelete, nil)
	if err != nil {
		t.Fatalf("规则修好后应收敛: %v", err)
	}
	t.Logf("第 3 轮(规则修好 v4): affected=%v", affected)
	if len(affected) != 1 || affected[0] != "users/a" {
		t.Fatalf("应只补齐 users/a: %v", affected)
	}
	if rec, ok := ds.Get("users/a"); !ok || rec.Data["email"] != "<anonymized>" || rec.RetainUntil != nil {
		t.Fatalf("users/a 应已匿名化并清保留期: %+v", rec)
	}

	// 最终每个资源恰一条处置审计；再跑无新增、无错误。
	if n := auditFor(t, log, "users/a", "retention.anonymize"); n != 1 {
		t.Fatalf("users/a 审计=%d want 1", n)
	}
	again, err := p.SweepWithPolicy(now, goodSnap, SweepDelete, nil)
	if err != nil || len(again) != 0 || log.Len() != 3 {
		t.Fatalf("收敛后重跑应完全无操作: again=%v err=%v auditLen=%d", again, err, log.Len())
	}
	t.Logf("分三轮收敛完成: 每个资源恰 1 条审计(总数=%d)，最终重跑无新增", log.Len())
}
