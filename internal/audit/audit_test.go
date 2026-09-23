package audit

import (
	"fmt"
	"sync"
	"testing"
)

func TestAppendHashChainAndVerify(t *testing.T) {
	l := NewLog()
	for i := 0; i < 5; i++ {
		e, err := l.Append(Entry{
			RequestID: fmt.Sprintf("req-%d", i),
			Subject:   "user:1", Action: "read", Resource: "users/1",
			Decision: "allow", PolicyVer: 1, Reason: "ok",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("APPEND seq=%d request=%s prev=%s hash=%s", e.Seq, e.RequestID, e.PrevHash, e.Hash[:12])
	}
	if seq, err := l.Verify(); seq != -1 {
		t.Fatalf("clean chain must verify, got badSeq=%d err=%v", seq, err)
	}

	// 篡改 seq=3 的判定结论，但不更新哈希 -> 必须在 seq=3 被检出
	if !l.TamperForTest(3, func(e *Entry) { e.Decision = "deny" }) {
		t.Fatal("tamper failed")
	}
	seq, err := l.Verify()
	if seq != 3 {
		t.Fatalf("tampering must be detected at seq 3, got seq=%d err=%v", seq, err)
	}
	t.Logf("TAMPER DETECTED at seq=%d: %v", seq, err)

	// 篡改 prev_hash（删除/重排场景）也要被检出
	l2 := NewLog()
	l2.Append(Entry{RequestID: "a", Decision: "allow"})
	l2.Append(Entry{RequestID: "b", Decision: "deny"})
	l2.TamperForTest(2, func(e *Entry) { e.PrevHash = "deadbeef" })
	if seq, _ := l2.Verify(); seq != 2 {
		t.Fatalf("broken chain must be detected at seq 2, got %d", seq)
	}
}

func TestAppendConcurrentNoLossNoDuplicate(t *testing.T) {
	l := NewLog()
	const goroutines = 50
	const perG = 40
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				_, err := l.Append(Entry{
					RequestID: fmt.Sprintf("g%d-%d", g, i),
					Subject:   "u", Action: "read", Resource: "r",
					Decision: "allow", Reason: "concurrent",
				})
				if err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	want := goroutines * perG
	if l.Len() != want {
		t.Fatalf("lost or duplicated entries: got %d want %d", l.Len(), want)
	}
	seenSeq := map[int64]bool{}
	seenReq := map[string]bool{}
	for _, e := range l.Entries() {
		if seenSeq[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seenSeq[e.Seq] = true
		if seenReq[e.RequestID] {
			t.Fatalf("duplicate request %s", e.RequestID)
		}
		seenReq[e.RequestID] = true
	}
	if seq, err := l.Verify(); seq != -1 {
		t.Fatalf("chain integrity under concurrency: badSeq=%d err=%v", seq, err)
	}
	t.Logf("CONCURRENCY: %d entries, seq 1..%d contiguous, chain intact", want, l.Len())
}
