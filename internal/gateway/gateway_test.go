package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

func setup(t *testing.T) (*policy.Store, *data.Store, *audit.Log, *Gateway) {
	t.Helper()
	ps := policy.NewStore()
	ds := data.NewStore(2)
	lg := audit.NewLog()
	ds.Put(data.Record{
		ID: "users/1", SubjectID: "subj-1", Resource: "users/1",
		Data: map[string]any{"name": "alice", "email": "alice@example.com", "ssn": "123"},
	})
	ps.Publish(&policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "p1-read", Effect: policy.EffectAllow,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})
	return ps, ds, lg, New(ps, ds, lg)
}

func TestAccess_AllowMaskDeny(t *testing.T) {
	ps, _, lg, gw := setup(t)

	// allow: 明文
	out := accessLog(t, gw, "req-allow", "user:1", "read", "users/1", nil)
	if out.Decision != policy.DecisionAllow || out.Data["ssn"] != "123" {
		t.Fatalf("allow must return plaintext, got %s %v", out.Decision, out.Data)
	}

	// 热更新到 v2：ssn/email 脱敏
	ps.Publish(&policy.Policy{Version: 2, Rules: []policy.Rule{
		{ID: "p2-mask", Effect: policy.EffectMask,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			Mask: []policy.MaskRule{{Field: "ssn", Method: "redact"}, {Field: "email", Method: "partial", Keep: 1}}},
	}})
	out2 := accessLog(t, gw, "req-mask", "user:1", "read", "users/1", nil)
	if out2.Decision != policy.DecisionMask || out2.Version != 2 {
		t.Fatalf("want mask on v2, got %s v%d", out2.Decision, out2.Version)
	}
	if out2.Data["ssn"] != "***" || out2.Data["name"] != "alice" {
		t.Fatalf("mask output wrong: %v", out2.Data)
	}

	// 热更新到 v3：显式 deny。Data 必须为 nil，审计记录版本为 v3
	ps.Publish(&policy.Policy{Version: 3, Rules: []policy.Rule{
		{ID: "p3-deny", Effect: policy.EffectDeny,
			Actions: []policy.Action{policy.ActionRead}, Subjects: []string{"user:*"}, Resources: []string{"users/*"}},
	}})
	out3 := accessLog(t, gw, "req-deny", "user:1", "read", "users/1", nil)
	if out3.Decision != policy.DecisionDeny || out3.Data != nil {
		t.Fatalf("deny must return no data, got %s %v", out3.Decision, out3.Data)
	}
	ae, _ := lg.EntryByRequest("req-deny")
	if ae.PolicyVer != 3 || ae.Decision != "deny" {
		t.Fatalf("audit must pin v3 deny, got ver=%d decision=%s", ae.PolicyVer, ae.Decision)
	}

	// 越权主体：即使策略 allow，作用域不匹配 -> 默认拒绝，无明文
	out4 := accessLog(t, gw, "req-cross", "attacker:9", "read", "users/1", nil)
	if out4.Decision != policy.DecisionDeny || out4.Data != nil {
		t.Fatalf("cross-subject access must be denied with no data, got %v", out4.Data)
	}
	t.Logf("audit chain verify: %v", func() string { seq, err := lg.Verify(); return fmt.Sprintf("badSeq=%d err=%v", seq, err) }())
}

func TestAccess_HotReloadRace_PinsOneVersionPerRequest(t *testing.T) {
	ps, _, lg, gw := setup(t)

	// 后台持续发布新版本，奇偶版本分别 allow / deny，且均不修改规则作用域
	stop := make(chan struct{})
	var pubWG sync.WaitGroup
	pubWG.Add(1)
	go func() {
		defer pubWG.Done()
		v := 1
		for {
			select {
			case <-stop:
				return
			default:
			}
			v++
			var effect policy.Effect
			if v%2 == 0 {
				effect = policy.EffectDeny
			} else {
				effect = policy.EffectAllow
			}
			_ = ps.Publish(&policy.Policy{Version: v, Rules: []policy.Rule{{
				ID: fmt.Sprintf("r-v%d", v), Effect: effect,
				Actions:  []policy.Action{policy.ActionRead},
				Subjects: []string{"user:*"}, Resources: []string{"users/*"},
			}}})
		}
	}()

	// 并发请求：每个请求的审计版本必须与实际输出严格一致——
	// allow 输出来自 allow 版本；deny 输出来自 deny 版本，不得出现版本/结果错配。
	const n = 300
	var wg sync.WaitGroup
	var mismatch int64
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("race-%d", i)
			out, err := gw.Access(AccessInput{RequestID: id, Request: policy.Request{
				Subject: "user:1", Action: policy.ActionRead, Resource: "users/1",
			}})
			if err != nil {
				t.Errorf("access error: %v", err)
				return
			}
			ae, ok := lg.EntryByRequest(id)
			if !ok {
				t.Errorf("audit missing for %s", id)
				return
			}
			mu.Lock()
			// 版本必须一致
			if ae.PolicyVer != out.Version {
				mismatch++
			}
			// deny 版本必须无数据；allow 版本必须有明文
			if out.Version%2 == 0 {
				if out.Decision != policy.DecisionDeny || out.Data != nil {
					mismatch++
				}
			} else {
				if out.Decision != policy.DecisionAllow || out.Data == nil || out.Data["ssn"] != "123" {
					mismatch++
				}
			}
			// 审计中的决策必须与返回一致
			if string(out.Decision) != ae.Decision {
				mismatch++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(stop)
	pubWG.Wait()

	if mismatch != 0 {
		t.Fatalf("hot-reload race produced %d version/result mismatches", mismatch)
	}
	// 每个请求一条审计，无丢失无重复
	if count := lg.Len(); count != n {
		t.Fatalf("audit count=%d want %d", count, n)
	}
	if seq, err := lg.Verify(); seq != -1 {
		t.Fatalf("audit chain broken at seq %d: %v", seq, err)
	}
	t.Logf("HOT-RELOAD RACE: %d concurrent requests across continuous republish, all pinned to one version; final policy v%d",
		n, ps.CurrentVersion())
}

func accessLog(t *testing.T, gw *Gateway, id, subject, action, resource string, env map[string]any) AccessOutput {
	t.Helper()
	out, err := gw.Access(AccessInput{RequestID: id, Request: policy.Request{
		Subject: subject, Action: policy.Action(action), Resource: resource, Env: env,
	}})
	if err != nil {
		t.Fatalf("access %s: %v", id, err)
	}
	t.Logf("ACCESS id=%s subject=%s resource=%s => decision=%s version=%d reason=%q masked=%v data=%v",
		id, subject, resource, out.Decision, out.Version, out.Reason, out.Masked, out.Data)
	// 打印该请求命中的策略与依据（取自审计）
	if ae, ok := gw.audit.EntryByRequest(id); ok {
		for _, h := range ae.Hits {
			t.Logf("  HIT: %s", h)
		}
	}
	return out
}

var _ = time.Now
