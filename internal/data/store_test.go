package data

import (
	"testing"
	"time"
)

func sampleRec(resource, subject string) Record {
	return Record{
		ID: resource, SubjectID: subject, Resource: resource,
		Data: map[string]any{"email": "a@x.com", "ssn": "1"},
	}
}

func TestMultiReplicaPutGetDelete(t *testing.T) {
	s := NewStore(3)
	if err := s.Put(sampleRec("users/1", "subj-1")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got := s.ExportReplica(i, "subj-1")
		if len(got) != 1 || got[0].Resource != "users/1" {
			t.Fatalf("replica %d not written", i)
		}
	}
	if err := s.Put(sampleRec("users/2", "subj-2")); err != nil {
		t.Fatal(err)
	}
	if len(s.FindBySubject("subj-1")) != 1 || len(s.FindBySubject("subj-2")) != 1 {
		t.Fatal("FindBySubject mismatch")
	}
	existed, err := s.Delete("users/1")
	if err != nil || !existed {
		t.Fatalf("delete existed=%v err=%v", existed, err)
	}
	for i := 0; i < 3; i++ {
		if len(s.ExportReplica(i, "subj-1")) != 0 {
			t.Fatalf("replica %d still has deleted record", i)
		}
	}
	if ok, _ := s.Delete("users/1"); ok {
		t.Fatal("second delete of missing record must report not-existed")
	}
	t.Log("MULTI-REPLICA: write/read/delete consistent across 3 replicas")
}

func TestUnhealthyReplicaFailsRetryable(t *testing.T) {
	s := NewStore(2)
	s.SetReplicaHealthy(1, false)
	err := s.Put(sampleRec("users/9", "subj-9"))
	if err == nil {
		t.Fatal("put with unhealthy replica must fail, not silently succeed")
	}
	re, ok := err.(*ReplicaError)
	if !ok || len(re.Failed) != 1 || re.Failed[0] != 1 {
		t.Fatalf("want ReplicaError naming replica 1, got %v", err)
	}
	t.Logf("EXPECTED FAILURE (retryable): %v", err)
	// 恢复副本后重试应成功
	s.SetReplicaHealthy(1, true)
	if err := s.Put(sampleRec("users/9", "subj-9")); err != nil {
		t.Fatalf("retry after recovery must succeed: %v", err)
	}
}

func TestExpiredAndAnonymize(t *testing.T) {
	s := NewStore(2)
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	old := sampleRec("users/old", "subj-old")
	old.RetainUntil = &past
	fresh := sampleRec("users/fresh", "subj-fresh")
	fresh.RetainUntil = &future
	forever := sampleRec("users/forever", "subj-forever")
	s.Put(old)
	s.Put(fresh)
	s.Put(forever)

	exp := s.Expired(now)
	if len(exp) != 1 || exp[0].Resource != "users/old" {
		t.Fatalf("exactly one record must be expired at boundary, got %v", exp)
	}
	// 边界：RetainUntil == now 不算到期（严格 Before），晚 1 纳秒才算
	if len(s.Expired(past)) != 0 {
		t.Fatal("at exactly RetainUntil, record is not yet expired")
	}
	if len(s.Expired(past.Add(time.Nanosecond))) != 1 {
		t.Fatal("one nanosecond after RetainUntil, record must be expired")
	}

	if _, err := s.Anonymize("users/old", []string{"ssn", "email"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got := s.ExportReplica(i, "subj-old")[0]
		if got.Data["ssn"] != "<anonymized>" || got.Data["email"] != "<anonymized>" {
			t.Fatalf("replica %d not anonymized: %v", i, got.Data)
		}
	}
	t.Log("RETENTION BOUNDARY: only past-due records selected; anonymization hit all replicas")
}

// TestResourceFaultIsolation 验证按资源的故障注入只影响目标资源：
// 对 users/bad 的写操作失败且无部分写入，其他资源的写操作不受影响；解除后恢复。
func TestResourceFaultIsolation(t *testing.T) {
	s := NewStore(3)
	if err := s.Put(sampleRec("users/ok", "subj-ok")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(sampleRec("users/bad", "subj-bad")); err != nil {
		t.Fatal(err)
	}

	s.SetResourceFaultForTest("users/bad", true)

	// 故障资源：Delete/Anonymize/Put 均以可重试的副本错误失败，且不产生部分写入。
	if _, err := s.Delete("users/bad"); err == nil {
		t.Fatal("faulty resource delete must fail")
	} else if re, ok := err.(*ReplicaError); !ok {
		t.Fatalf("faulty resource delete must return *ReplicaError, got %v", err)
	} else if len(re.Failed) != 1 {
		t.Fatalf("应点名单个故障副本: %v", re.Failed)
	}
	if _, err := s.Anonymize("users/bad", []string{"email"}); err == nil {
		t.Fatal("faulty resource anonymize must fail")
	}
	for i := 0; i < 3; i++ {
		got := s.ExportReplica(i, "subj-bad")
		if len(got) != 1 || got[0].Data["email"] != "a@x.com" {
			t.Fatalf("故障资源不得产生部分写入，副本 %d 实际 %+v", i, got)
		}
	}

	// 其他资源完全不受影响。
	if _, err := s.Anonymize("users/ok", []string{"email"}); err != nil {
		t.Fatalf("健康资源不应被故障资源拖累: %v", err)
	}
	for i := 0; i < 3; i++ {
		got := s.ExportReplica(i, "subj-ok")
		if len(got) != 1 || got[0].Data["email"] != "<anonymized>" {
			t.Fatalf("健康资源副本 %d 应正常匿名化: %+v", i, got)
		}
	}
	t.Log("RESOURCE FAULT: users/bad writes fail retryable with no partial write; users/ok unaffected")

	// 解除注入后恢复正常。
	s.SetResourceFaultForTest("users/bad", false)
	existed, err := s.Delete("users/bad")
	if err != nil || !existed {
		t.Fatalf("解除故障后删除应成功: existed=%v err=%v", existed, err)
	}
}
