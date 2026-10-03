package policy

import (
	"strings"
	"testing"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

func publishTestPolicy(version int, ruleIDs ...string) *Policy {
	p := &Policy{Version: version, Name: "test-policy"}
	for _, id := range ruleIDs {
		p.Rules = append(p.Rules, Rule{ID: id, Effect: EffectAllow, Actions: []Action{ActionRead}, Resources: []string{"*"}, Subjects: []string{"*"}})
	}
	return p
}

// TestPublishHistory_RecordedAndVerifiable 覆盖：每次发布/切换都在哈希链审计中
// 留下含"何时、从哪版到哪版、规则摘要"的记录，且 Verify 将其一并纳入完整性校验。
func TestPublishHistory_RecordedAndVerifiable(t *testing.T) {
	log := audit.NewLog()
	store := NewStore()
	hist := NewHistory(log)
	store.AttachHistory(hist)

	if err := store.Publish(publishTestPolicy(1, "r-open")); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if err := store.Publish(publishTestPolicy(2, "r-open", "r-mask")); err != nil {
		t.Fatalf("publish v2: %v", err)
	}

	entries := log.Entries()
	if len(entries) != 2 {
		t.Fatalf("audit entries=%d, want 2 (每次发布一条)", len(entries))
	}
	for _, e := range entries {
		t.Logf("audit seq=%d action=%s resource=%s reason=%q", e.Seq, e.Action, e.Resource, e.Reason)
		if e.Action != PublishAction {
			t.Fatalf("seq %d: action=%q want %q", e.Seq, e.Action, PublishAction)
		}
	}

	rec1, ok := hist.Lookup(1)
	if !ok {
		t.Fatal("lookup v1 failed")
	}
	t.Logf("v1 发布记录: from=%d to=%d time=%s rules=%v hash=%s...", rec1.FromVersion, rec1.ToVersion, rec1.Time, rec1.RuleIDs, rec1.RulesHash[:12])
	if rec1.FromVersion != 0 || rec1.ToVersion != 1 || rec1.RuleCount != 1 {
		t.Fatalf("v1 record wrong: %+v", rec1)
	}
	rec2, ok := hist.Lookup(2)
	if !ok {
		t.Fatal("lookup v2 failed")
	}
	t.Logf("v2 发布记录: from=%d to=%d rules=%v", rec2.FromVersion, rec2.ToVersion, rec2.RuleIDs)
	if rec2.FromVersion != 1 || rec2.ToVersion != 2 || rec2.RuleCount != 2 {
		t.Fatalf("v2 record wrong: %+v", rec2)
	}
	if rec1.RulesHash == rec2.RulesHash {
		t.Fatal("不同规则内容的两个版本 RulesHash 不应相同")
	}
	if rec1.Time.IsZero() {
		t.Fatal("发布记录缺少时间")
	}

	if bad, err := log.Verify(); err != nil {
		t.Fatalf("verify should pass, got seq=%d err=%v", bad, err)
	}
	t.Log("含发布记录的审计链 Verify 通过")
}

// TestPublishHistory_TamperDetected 篡改发布记录内容时，Verify 必须在对应条目检出。
func TestPublishHistory_TamperDetected(t *testing.T) {
	log := audit.NewLog()
	store := NewStore()
	hist := NewHistory(log)
	store.AttachHistory(hist)

	if err := store.Publish(publishTestPolicy(1, "r-open")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rec, _ := hist.Lookup(1)
	t.Logf("篡改前: v1 记录于 seq=%d from=%d", rec.Seq, rec.FromVersion)

	// 模拟事后篡改发布记录（把 from_version 改掉）。
	if !log.TamperForTest(rec.Seq, func(e *audit.Entry) {
		e.Detail = strings.Replace(e.Detail, `"from_version":0`, `"from_version":9`, 1)
	}) {
		t.Fatal("tamper failed")
	}
	bad, err := log.Verify()
	t.Logf("篡改后 Verify: badSeq=%d err=%v", bad, err)
	if err == nil || bad != rec.Seq {
		t.Fatalf("tamper not detected at seq %d: bad=%d err=%v", rec.Seq, bad, err)
	}
}

// TestPublishHistory_TraceByRequest 由一次访问的审计记录顺藤摸瓜找到
// 该次访问所用策略版本的发布记录。
func TestPublishHistory_TraceByRequest(t *testing.T) {
	log := audit.NewLog()
	store := NewStore()
	hist := NewHistory(log)
	store.AttachHistory(hist)

	if err := store.Publish(publishTestPolicy(1, "r-v1")); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if err := store.Publish(publishTestPolicy(2, "r-v2")); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	// 模拟一次使用 v2 策略的访问审计。
	if _, err := log.Append(audit.Entry{RequestID: "req-1", Subject: "alice", Action: "read",
		Resource: "users/1", Decision: "allow", PolicyVer: 2, Reason: "allowed by rule(s): r-v2"}); err != nil {
		t.Fatalf("append access audit: %v", err)
	}

	entry, rec, ok := hist.TraceByRequest("req-1")
	if !ok {
		t.Fatal("trace failed")
	}
	t.Logf("访问 req-1 使用策略 v%d -> 该版本于 %s 由 v%d 切换装入，规则=%v",
		entry.PolicyVer, rec.Time, rec.FromVersion, rec.RuleIDs)
	if entry.PolicyVer != 2 || rec.ToVersion != 2 || rec.FromVersion != 1 {
		t.Fatalf("trace mismatch: entry ver=%d rec=%+v", entry.PolicyVer, rec)
	}

	if _, _, ok := hist.TraceByRequest("no-such-request"); ok {
		t.Fatal("不存在的请求不应追踪成功")
	}
	t.Log("不存在的请求 ID 追踪返回 false，符合预期")
}
