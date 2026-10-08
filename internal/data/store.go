package data

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ReplicaError 表示部分副本操作失败；失败原因可定位副本，调用方可安全重试。
type ReplicaError struct {
	Op     string
	Failed []int
}

func (e *ReplicaError) Error() string {
	return fmt.Sprintf("data store: op=%s failed on replicas %v; operation is retryable", e.Op, e.Failed)
}

// Record 是一条受管数据记录，包含数据主体归属与保留期元数据。
type Record struct {
	ID          string
	SubjectID   string // 数据主体标识，用于数据主体请求(DSR)
	Resource    string // 资源标识，如 users/1
	Data        map[string]any
	RetainUntil *time.Time // nil 表示长期保留
	UpdatedAt   time.Time
}

// replica 是一份独立存储副本。写入/删除/匿名化必须覆盖全部健康副本。
type replica struct {
	mu      sync.RWMutex
	records map[string]*Record
	healthy bool
}

// Store 为内存多副本存储，并发安全，模拟本地受管数据源。
// 副本 0 作为读取与枚举的基准副本；任何变更都要求所有健康副本一致成功，
// 否则返回 *ReplicaError（可重试），绝不静默成功。
type Store struct {
	replicas []*replica

	injMu        sync.RWMutex
	failResource map[string]struct{} // 故障注入：命中这些资源的写操作按"副本不可用"失败
}

// NewStore 创建具有 n 个副本的存储（n>=1）。
func NewStore(n int) *Store {
	if n < 1 {
		n = 1
	}
	s := &Store{}
	for i := 0; i < n; i++ {
		s.replicas = append(s.replicas, &replica{records: make(map[string]*Record), healthy: true})
	}
	return s
}

// Put 写入或更新一条记录到全部健康副本。任一健康副本不可用时整体失败
// （变更前预检，不产生部分写入），返回 *ReplicaError，可重试。
func (s *Store) Put(rec Record) error {
	if err := s.preflight("put"); err != nil {
		return err
	}
	if err := s.preflightResource("put", rec.Resource); err != nil {
		return err
	}
	stored := cloneRecord(rec)
	for _, r := range s.replicas {
		r.mu.Lock()
		r.records[stored.Resource] = ptrRecord(cloneRecord(stored))
		r.mu.Unlock()
	}
	return nil
}

// Get 从副本 0 读取记录，返回深拷贝。
func (s *Store) Get(resource string) (Record, bool) {
	r0 := s.replicas[0]
	r0.mu.RLock()
	defer r0.mu.RUnlock()
	rec, ok := r0.records[resource]
	if !ok {
		return Record{}, false
	}
	return cloneRecordPtr(rec), true
}

// Delete 删除全部健康副本中的记录；返回副本 0 中删除前是否存在。
func (s *Store) Delete(resource string) (bool, error) {
	if err := s.preflight("delete"); err != nil {
		return false, err
	}
	if err := s.preflightResource("delete", resource); err != nil {
		return false, err
	}
	r0 := s.replicas[0]
	r0.mu.Lock()
	_, existed := r0.records[resource]
	delete(r0.records, resource)
	r0.mu.Unlock()
	for i := 1; i < len(s.replicas); i++ {
		r := s.replicas[i]
		r.mu.Lock()
		delete(r.records, resource)
		r.mu.Unlock()
	}
	return existed, nil
}

// Anonymize 将全部健康副本中指定字段替换为匿名值 "<anonymized>"。
// 返回副本 0 中记录是否存在。
func (s *Store) Anonymize(resource string, fields []string) (bool, error) {
	if err := s.preflight("anonymize"); err != nil {
		return false, err
	}
	if err := s.preflightResource("anonymize", resource); err != nil {
		return false, err
	}
	for _, r := range s.replicas {
		r.mu.Lock()
		rec, ok := r.records[resource]
		if ok {
			if rec.Data == nil {
				rec.Data = map[string]any{}
			}
			for _, f := range fields {
				if _, present := rec.Data[f]; present {
					rec.Data[f] = "<anonymized>"
				}
			}
		}
		r.mu.Unlock()
	}
	_, ok := s.Get(resource)
	return ok, nil
}

// FindBySubject 返回归属于某数据主体的全部记录（以副本 0 为准），按资源排序。
func (s *Store) FindBySubject(subjectID string) []Record {
	r0 := s.replicas[0]
	r0.mu.RLock()
	var out []Record
	for _, rec := range r0.records {
		if rec.SubjectID == subjectID {
			out = append(out, cloneRecordPtr(rec))
		}
	}
	r0.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// Expired 返回在 now 时刻已过保留期（RetainUntil < now）的记录，按资源排序。
func (s *Store) Expired(now time.Time) []Record {
	r0 := s.replicas[0]
	r0.mu.RLock()
	var out []Record
	for _, rec := range r0.records {
		if rec.RetainUntil != nil && rec.RetainUntil.Before(now) {
			out = append(out, cloneRecordPtr(rec))
		}
	}
	r0.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// ReplicaCount 返回副本总数。
func (s *Store) ReplicaCount() int { return len(s.replicas) }

// ReplicaHas 报告指定副本中是否存在某资源，供上层逐副本校验处置无残留。
func (s *Store) ReplicaHas(idx int, resource string) bool {
	if idx < 0 || idx >= len(s.replicas) {
		return false
	}
	r := s.replicas[idx]
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.records[resource]
	return ok
}

// ExportReplica 导出指定副本中匹配 subjectID 的记录（深拷贝，按资源排序），
// 供上层交叉校验导出确实覆盖了每一个副本。
func (s *Store) ExportReplica(idx int, subjectID string) []Record {
	if idx < 0 || idx >= len(s.replicas) {
		return nil
	}
	r := s.replicas[idx]
	r.mu.RLock()
	var out []Record
	for _, rec := range r.records {
		if rec.SubjectID == subjectID {
			out = append(out, cloneRecordPtr(rec))
		}
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

// SetReplicaHealthy 用于故障注入：标记某副本是否健康。
func (s *Store) SetReplicaHealthy(idx int, healthy bool) {
	if idx < 0 || idx >= len(s.replicas) {
		return
	}
	r := s.replicas[idx]
	r.mu.Lock()
	r.healthy = healthy
	r.mu.Unlock()
}

// SetResourceFaultForTest 用于故障注入：让针对某资源的写操作（Put/Delete/Anonymize）
// 以"该资源所在副本暂时不可用"的形式失败（返回 *ReplicaError，不产生部分写入），
// 模拟同一轮扫描里仅个别资源的存储副本当时不可用、而其他资源可正常处置。
// 传 healthy=true（或换一个资源）解除注入。
func (s *Store) SetResourceFaultForTest(resource string, faulty bool) {
	s.injMu.Lock()
	defer s.injMu.Unlock()
	if s.failResource == nil {
		s.failResource = make(map[string]struct{})
	}
	if faulty {
		s.failResource[resource] = struct{}{}
	} else {
		delete(s.failResource, resource)
	}
}

// preflight 检查全部副本健康；不健康则返回失败副本列表，不执行任何变更。
func (s *Store) preflight(op string) error {
	var bad []int
	for i, r := range s.replicas {
		r.mu.RLock()
		if !r.healthy {
			bad = append(bad, i)
		}
		r.mu.RUnlock()
	}
	if len(bad) > 0 {
		return &ReplicaError{Op: op, Failed: bad}
	}
	return nil
}

// preflightResource 在全副本预检之外，再做按资源的故障注入检查。
func (s *Store) preflightResource(op, resource string) error {
	s.injMu.RLock()
	_, bad := s.failResource[resource]
	s.injMu.RUnlock()
	if bad {
		idx := 1 // 模拟该资源在副本 1 上当时不可用；单副本时退回副本 0
		if len(s.replicas) <= idx {
			idx = 0
		}
		return &ReplicaError{Op: op, Failed: []int{idx}}
	}
	return nil
}

func cloneRecord(rec Record) Record {
	cp := rec
	if rec.Data != nil {
		cp.Data = make(map[string]any, len(rec.Data))
		for k, v := range rec.Data {
			cp.Data[k] = v
		}
	}
	if rec.RetainUntil != nil {
		t := *rec.RetainUntil
		cp.RetainUntil = &t
	}
	return cp
}

func cloneRecordPtr(rec *Record) Record {
	return cloneRecord(*rec)
}

func ptrRecord(rec Record) *Record { return &rec }
