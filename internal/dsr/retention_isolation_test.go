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

// assertPartial 断言一轮扫描返回了 *PartialSweepError，并返回其明细供进一步核对。
func assertPartial(t *testing.T, err error) *PartialSweepError {
	t.Helper()
	if err == nil {
		t.Fatal("本轮存在处置失败的资源，必须返回错误而不是报成功")
	}
	var pe *PartialSweepError
	if !errors.As(err, &pe) {
		t.Fatalf("错误应为 *PartialSweepError（可按资源定位残留并重跑），实际 %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "retryable") {
		t.Fatalf("错误必须明确可重试: %v", err)
	}
	return pe
}

func failedSet(pe *PartialSweepError) map[string]string {
	m := make(map[string]string, len(pe.Failures))
	for _, f := range pe.Failures {
		m[f.Resource] = f.Err.Error()
	}
	return m
}

// countAuditFor 统计审计中某资源的处置记录条数。
func countAuditFor(t *testing.T, log *audit.Log, resource string) int {
	t.Helper()
	n := 0
	for _, e := range log.Entries() {
		if e.Resource == resource {
			n++
		}
	}
	return n
}

// TestSweepWithPolicy_BrokenRuleDoesNotBlockOthers 覆盖核心语义：
// 同一轮扫描中某资源命中的保留期规则内容有误（未知 action），只判该资源失败，
// 其余资源（策略删除、策略匿名化、兜底删除）仍全部处置成功并各写一条审计；
// 规则修好后重跑，失败资源补齐收敛，全程每种处置恰好一条审计、无重复留痕。
func TestSweepWithPolicy_BrokenRuleDoesNotBlockOthers(t *testing.T) {
	ds := data.NewStore(3)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	past := now.Add(-2 * time.Hour)

	put := func(resource string, fields map[string]any) {
		if err := ds.Put(expiredRecord(resource, "subj-"+resource, past, fields)); err != nil {
			t.Fatalf("put %s: %v", resource, err)
		}
	}
	// 4 条到期资源：1 条策略删除、1 条策略匿名化、1 条命中坏规则、1 条无规则走兜底。
	put("logs/2026-09", map[string]any{"line": "login"})
	put("users/1", map[string]any{"email": "a@x.com", "name": "ann"})
	put("events/7", map[string]any{"kind": "click"})
	put("orders/5", map[string]any{"total": 42})

	broken := &policy.Policy{Version: 11, Retention: []policy.RetentionRule{
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
		{ID: "bad-events", Resources: []string{"events/*"}, Action: retentionAction("purge"), Priority: 20},
	}}
	t.Logf("输入: 到期资源=logs/2026-09(策略delete)、users/1(策略anonymize[email])、events/7(命中坏规则 action=purge)、orders/5(无规则->兜底 delete)")
	t.Logf("判定依据: RetainUntil=%s < now=%s 全部到期；events/7 的规则内容有误，只应影响它自己", past.Format(time.RFC3339), now.Format(time.RFC3339))

	// 第一轮：events/7 失败，但其余 3 条必须照常处置；本轮整体不能报成功。
	succeeded, err := p.SweepWithPolicy(now, broken, SweepDelete, nil)
	pe := assertPartial(t, err)
	t.Logf("第1轮: 已处置=%v 失败明细=%v", succeeded, pe.Failures)
	if got := append(append([]string{}, succeeded...), namesOf(pe)...); len(got) != 4 {
		t.Fatalf("本轮应覆盖全部 4 条资源（成功+失败），实际 %v", got)
	}
	want := map[string]bool{"logs/2026-09": true, "users/1": true, "orders/5": true}
	if len(succeeded) != len(want) {
		t.Fatalf("成功资源=%v，应恰好为 %v", succeeded, want)
	}
	for _, r := range succeeded {
		if !want[r] {
			t.Fatalf("资源 %s 不应成功（坏规则资源必须被隔离在失败集合中）", r)
		}
	}
	fails := failedSet(pe)
	if _, ok := fails["events/7"]; !ok {
		t.Fatalf("events/7 必须在失败集合: %+v", pe.Failures)
	}
	if !strings.Contains(fails["events/7"], "unknown action") {
		t.Fatalf("失败原因应点名规则内容问题: %v", fails["events/7"])
	}

	// 其余 3 条已按各自方式处置完成。
	if _, ok := ds.Get("logs/2026-09"); ok {
		t.Fatal("logs/2026-09 应已整条清除，不能被坏规则资源拖累")
	}
	if _, ok := ds.Get("orders/5"); ok {
		t.Fatal("orders/5 应已按兜底整条清除")
	}
	u1, ok := ds.Get("users/1")
	if !ok {
		t.Fatal("users/1 应保留并完成字段匿名化")
	}
	if u1.Data["email"] != "<anonymized>" || u1.Data["name"] != "ann" || u1.RetainUntil != nil {
		t.Fatalf("users/1 匿名化结果错误: %v retain=%v", u1.Data, u1.RetainUntil)
	}
	// 坏规则资源原样保留、等待修好后重跑；它本轮不能写任何处置审计。
	if _, ok := ds.Get("events/7"); !ok {
		t.Fatal("events/7 处置失败，记录必须原样保留待重跑")
	}
	if n := countAuditFor(t, log, "events/7"); n != 0 {
		t.Fatalf("失败资源不得写处置记录，events/7 审计条数=%d", n)
	}
	t.Logf("第1轮后核对: logs/2026-09、orders/5 已删除；users/1 email 已匿名化且保留期标记清除；events/7 原样保留")

	for _, e := range log.Entries() {
		t.Logf("audit seq=%d action=%s resource=%s ver=%d", e.Seq, e.Action, e.Resource, e.PolicyVer)
	}
	if log.Len() != 3 {
		t.Fatalf("第1轮应为 3 个成功资源各写 1 条审计，实际 %d 条", log.Len())
	}

	// 规则未修好就重跑：已成功资源不重复处置/留痕，events/7 仍失败，整轮仍报错。
	succeeded2, err2 := p.SweepWithPolicy(now, broken, SweepDelete, nil)
	pe2 := assertPartial(t, err2)
	t.Logf("第2轮(规则仍坏): 已处置=%v（应为空，成功资源已被台账挡下）失败=%v", succeeded2, namesOf(pe2))
	if len(succeeded2) != 0 || len(pe2.Failures) != 1 || pe2.Failures[0].Resource != "events/7" {
		t.Fatalf("第2轮应只剩 events/7 失败: succeeded=%v failures=%v", succeeded2, pe2.Failures)
	}
	if log.Len() != 3 {
		t.Fatalf("重跑不得新增审计，实际 %d 条", log.Len())
	}

	// 修好规则后重跑：events/7 补齐处置，全部收敛；它只有这一条审计。
	fixed := &policy.Policy{Version: 12, Retention: []policy.RetentionRule{
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
		{ID: "del-events", Resources: []string{"events/*"}, Action: policy.RetentionDelete, Priority: 20},
	}}
	succeeded3, err3 := p.SweepWithPolicy(now, fixed, SweepDelete, nil)
	if err3 != nil {
		t.Fatalf("规则修好后重跑应收敛，实际仍失败: %v", err3)
	}
	t.Logf("第3轮(规则修好 v12): 已处置=%v err=nil，全部到期资源收敛", succeeded3)
	if len(succeeded3) != 1 || succeeded3[0] != "events/7" {
		t.Fatalf("第3轮应只补齐 events/7: %v", succeeded3)
	}
	if _, ok := ds.Get("events/7"); ok {
		t.Fatal("events/7 重跑后应已整条清除")
	}

	// 每种处置恰好一条审计：4 条资源 4 条记录；继续重跑不再新增。
	if log.Len() != 4 {
		t.Fatalf("收敛后审计应恰好 4 条（每资源 1 条），实际 %d", log.Len())
	}
	for _, e := range log.Entries() {
		if n := countAuditFor(t, log, e.Resource); n != 1 {
			t.Fatalf("资源 %s 的处置审计应为 1 条，实际 %d", e.Resource, n)
		}
	}
	again, err4 := p.SweepWithPolicy(now, fixed, SweepDelete, nil)
	if err4 != nil || len(again) != 0 || log.Len() != 4 {
		t.Fatalf("收敛后重跑应无处置无错误无审计: again=%v err=%v auditLen=%d", again, err4, log.Len())
	}
	t.Logf("收敛核对: 审计总条数=%d（每资源恰 1 条），再跑 affected=%v 无新增审计", log.Len(), again)
}

func namesOf(pe *PartialSweepError) []string {
	out := make([]string, 0, len(pe.Failures))
	for _, f := range pe.Failures {
		out = append(out, f.Resource)
	}
	return out
}

// retentionAction 构造一个非法的保留期动作，模拟策略内容损坏。
func retentionAction(s string) policy.RetentionAction { return policy.RetentionAction(s) }

// TestSweepWithPolicy_ReplicaFaultOnOneResource 覆盖：同一轮扫描里只有某个资源的存储
// 副本当时不可用（按资源的故障注入），其他资源不受拖累照常删除/匿名化并留痕；
// 该资源在副本恢复后重跑补齐（匿名化覆盖全部副本），最终各副本无残留、每资源恰一条审计。
func TestSweepWithPolicy_ReplicaFaultOnOneResource(t *testing.T) {
	ds := data.NewStore(3)
	log := audit.NewLog()
	p := New(ds, log)
	now := time.Date(2026, 10, 8, 18, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)

	put := func(resource, subject string, fields map[string]any) {
		if err := ds.Put(expiredRecord(resource, subject, past, fields)); err != nil {
			t.Fatalf("put %s: %v", resource, err)
		}
	}
	// users/a 走策略匿名化；logs/1 走策略删除；orders/9 无规则走兜底删除。
	put("users/a", "subj-a", map[string]any{"email": "a@x.com", "name": "ann"})
	put("logs/1", "subj-l", map[string]any{"line": "login"})
	put("orders/9", "subj-o", map[string]any{"total": 7})

	snap := &policy.Policy{Version: 5, Retention: []policy.RetentionRule{
		{ID: "anon-users", Resources: []string{"users/*"}, Action: policy.RetentionAnonymize, Fields: []string{"email"}, Priority: 10},
		{ID: "del-logs", Resources: []string{"logs/*"}, Action: policy.RetentionDelete, Priority: 10},
	}}
	t.Logf("输入: 到期资源 users/a(anonymize[email])、logs/1(delete)、orders/9(兜底 delete)，均 RetainUntil=%s < now=%s",
		past.Format(time.RFC3339), now.Format(time.RFC3339))

	// users/a 的副本 1 当时不可用：只它处置失败。
	ds.SetResourceFaultForTest("users/a", true)
	succeeded, err := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	pe := assertPartial(t, err)
	t.Logf("第1轮(users/a 副本1故障): 已处置=%v 失败=%v", succeeded, pe.Failures)
	if len(succeeded) != 2 {
		t.Fatalf("应仍有 2 个资源处置成功，实际 %v", succeeded)
	}
	for _, r := range []string{"logs/1", "orders/9"} {
		if !contains(succeeded, r) {
			t.Fatalf("%s 不应被 users/a 的副本故障拖累，应处置成功", r)
		}
		for i := 0; i < ds.ReplicaCount(); i++ {
			if ds.ReplicaHas(i, r) {
				t.Fatalf("%s 应从全部副本清除，副本 %d 仍有残留", r, i)
			}
		}
	}
	if len(pe.Failures) != 1 || pe.Failures[0].Resource != "users/a" {
		t.Fatalf("失败集合应只含 users/a: %+v", pe.Failures)
	}
	// 失败原因可定位到具体副本且可重试。
	var re *data.ReplicaError
	if !errors.As(pe.Failures[0].Err, &re) || len(re.Failed) != 1 || re.Failed[0] != 1 {
		t.Fatalf("users/a 的失败应点名副本 1（*data.ReplicaError），实际 %v", pe.Failures[0].Err)
	}
	// 预检不产生部分写入：users/a 在每个副本都原样保留、未到期数据未变。
	for i := 0; i < ds.ReplicaCount(); i++ {
		got := ds.ExportReplica(i, "subj-a")
		if len(got) != 1 || got[0].Data["email"] != "a@x.com" || got[0].RetainUntil == nil {
			t.Fatalf("副本 %d 中 users/a 应原样保留（无部分写入），实际 %+v", i, got)
		}
	}
	if log.Len() != 2 || countAuditFor(t, log, "users/a") != 0 {
		t.Fatalf("失败资源不得留痕；应只有 logs/1、orders/9 各 1 条审计，总条数=%d", log.Len())
	}
	t.Logf("第1轮后: logs/1、orders/9 全部 3 副本无残留；users/a 各副本原样保留；审计条数=%d（无 users/a）", log.Len())

	// 副本仍未恢复时重跑：成功资源不重复处置，users/a 仍失败，不新增审计。
	succeeded2, err2 := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	pe2 := assertPartial(t, err2)
	t.Logf("第2轮(故障仍在): 已处置=%v 失败=%v（成功资源已被台账挡下）", succeeded2, namesOf(pe2))
	if len(succeeded2) != 0 || len(pe2.Failures) != 1 || pe2.Failures[0].Resource != "users/a" {
		t.Fatalf("第2轮应只剩 users/a 失败: succeeded=%v failures=%v", succeeded2, pe2.Failures)
	}
	if log.Len() != 2 {
		t.Fatalf("重跑不得新增审计，实际 %d 条", log.Len())
	}

	// 副本恢复后重跑：users/a 补齐匿名化，覆盖全部副本，整轮成功。
	ds.SetResourceFaultForTest("users/a", false)
	succeeded3, err3 := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err3 != nil {
		t.Fatalf("副本恢复后重跑应收敛: %v", err3)
	}
	if len(succeeded3) != 1 || succeeded3[0] != "users/a" {
		t.Fatalf("第3轮应只补齐 users/a: %v", succeeded3)
	}
	for i := 0; i < ds.ReplicaCount(); i++ {
		got := ds.ExportReplica(i, "subj-a")
		if len(got) != 1 {
			t.Fatalf("匿名化应保留 users/a 记录，副本 %d 记录数=%d", i, len(got))
		}
		if got[0].Data["email"] != "<anonymized>" || got[0].Data["name"] != "ann" || got[0].RetainUntil != nil {
			t.Fatalf("副本 %d 匿名化结果错误或保留期标记未清除: %+v", i, got[0])
		}
	}
	t.Logf("第3轮(副本恢复): users/a 全部 %d 副本 email 已匿名化、保留期标记清除，记录保留", ds.ReplicaCount())

	// 收敛核对：3 资源各恰 1 条审计；继续重跑无处置、无错误、无新增审计。
	if log.Len() != 3 {
		t.Fatalf("收敛后审计应恰好 3 条，实际 %d", log.Len())
	}
	entriesByRes := map[string]string{}
	for _, e := range log.Entries() {
		entriesByRes[e.Resource] = e.Action
		t.Logf("audit seq=%d resource=%s action=%s", e.Seq, e.Resource, e.Action)
	}
	if entriesByRes["users/a"] != "retention.anonymize" || entriesByRes["logs/1"] != "retention.delete" || entriesByRes["orders/9"] != "retention.delete" {
		t.Fatalf("审计动作与资源对应错误: %v", entriesByRes)
	}
	again, err4 := p.SweepWithPolicy(now, snap, SweepDelete, nil)
	if err4 != nil || len(again) != 0 || log.Len() != 3 {
		t.Fatalf("收敛后重跑应无处置无错误无审计: again=%v err=%v auditLen=%d", again, err4, log.Len())
	}
	t.Logf("收敛核对: 每资源恰 1 条处置记录，再跑 affected=%v、审计仍为 %d 条", again, log.Len())
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
