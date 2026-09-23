package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Entry 是一条不可变审计记录。
type Entry struct {
	Seq       int64     `json:"seq"`
	RequestID string    `json:"request_id"`
	Time      time.Time `json:"time"`
	Subject   string    `json:"subject"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Decision  string    `json:"decision"`
	PolicyVer int       `json:"policy_version"`
	Reason    string    `json:"reason"`
	Hits      []string  `json:"hits,omitempty"` // 命中规则摘要
	Detail    string    `json:"detail,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// hashPayload 是参与哈希计算的字段集合（不含 Hash 自身）。
type hashPayload struct {
	Seq       int64     `json:"seq"`
	RequestID string    `json:"request_id"`
	Time      time.Time `json:"time"`
	Subject   string    `json:"subject"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Decision  string    `json:"decision"`
	PolicyVer int       `json:"policy_version"`
	Reason    string    `json:"reason"`
	Hits      []string  `json:"hits,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	PrevHash  string    `json:"prev_hash"`
}

// Log 是追加式哈希链审计日志，并发安全。
// 每条记录包含前一条记录的哈希，形成链式完整性保护：
// 任一条目被篡改，Verify 会在该条目处断链检出。
type Log struct {
	mu      sync.Mutex
	entries []*Entry
}

// NewLog 创建空审计日志。
func NewLog() *Log {
	return &Log{}
}

// Append 追加一条审计记录：在互斥区内分配连续 seq、链接前一条哈希并计算本条目哈希。
// 调用方只需提供业务内容；Seq/Time/PrevHash/Hash 由日志统一赋值。
// 高并发下 seq 单调连续，不丢失、不重复、不错配。
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Seq = int64(len(l.entries)) + 1
	e.PrevHash = ""
	if n := len(l.entries); n > 0 {
		e.PrevHash = l.entries[n-1].Hash
	}
	h, err := computeHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: compute hash: %w", err)
	}
	e.Hash = h
	stored := e
	l.entries = append(l.entries, &stored)
	return e, nil
}

// Entries 返回全部审计记录的只读拷贝（按 seq 升序）。
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	for i, e := range l.entries {
		out[i] = *e
	}
	return out
}

// EntryByRequest 按请求 ID 查找审计记录。
func (l *Log) EntryByRequest(requestID string) (Entry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.RequestID == requestID {
			return *e, true
		}
	}
	return Entry{}, false
}

// Len 返回审计记录数。
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Verify 从链首逐条重算哈希并校验序号连续与链接关系。
// 返回首个被篡改（或断链）的条目 seq；返回 -1 表示完整无篡改。
func (l *Log) Verify() (badSeq int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for i, e := range l.entries {
		if e.Seq != int64(i+1) {
			return e.Seq, fmt.Errorf("audit verify: seq gap at index %d: got %d want %d", i, e.Seq, i+1)
		}
		if e.PrevHash != prev {
			return e.Seq, fmt.Errorf("audit verify: prev_hash mismatch at seq %d", e.Seq)
		}
		want, err := computeHash(*e)
		if err != nil {
			return e.Seq, fmt.Errorf("audit verify: recompute hash at seq %d: %w", e.Seq, err)
		}
		if want != e.Hash {
			return e.Seq, fmt.Errorf("audit verify: hash mismatch at seq %d (entry tampered)", e.Seq)
		}
		prev = e.Hash
	}
	return -1, nil
}

// TamperForTest 仅用于测试：直接替换某序号条目内容且不更新哈希，模拟篡改。
func (l *Log) TamperForTest(seq int64, mutate func(*Entry)) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.Seq == seq {
			mutate(e)
			return true
		}
	}
	return false
}

// computeHash 对条目的业务字段与链接字段做规范化 JSON 后取 SHA-256。
func computeHash(e Entry) (string, error) {
	p := hashPayload{
		Seq: e.Seq, RequestID: e.RequestID, Time: e.Time,
		Subject: e.Subject, Action: e.Action, Resource: e.Resource,
		Decision: e.Decision, PolicyVer: e.PolicyVer, Reason: e.Reason,
		Hits: e.Hits, Detail: e.Detail, PrevHash: e.PrevHash,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
