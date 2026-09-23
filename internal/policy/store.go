package policy

import (
	"fmt"
	"sync"
)

// Store 保存策略的多个不可变版本，支持热更新与按版本取快照。
// 已发布的策略永不被原地修改：热更新即新增一个版本并原子切换 current 指针，
// 因此已经在处理中的请求仍可继续使用旧版本快照，保证单请求生命周期内一致。
type Store struct {
	mu       sync.RWMutex
	versions map[int]*Policy
	current  int
}

// NewStore 创建空策略存储。
func NewStore() *Store {
	return &Store{versions: make(map[int]*Policy)}
}

// Publish 发布一个新版本（必须单调递增），并将其置为当前版本。
// 传入的策略会被深拷贝后保存，调用方之后修改原对象不影响已发布版本。
func (s *Store) Publish(p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy store: cannot publish nil policy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.versions[p.Version]; exists {
		return fmt.Errorf("policy store: version %d already exists", p.Version)
	}
	if len(s.versions) > 0 && p.Version <= s.current {
		return fmt.Errorf("policy store: new version %d must be greater than current %d", p.Version, s.current)
	}
	s.versions[p.Version] = clonePolicy(p)
	s.current = p.Version
	return nil
}

// CurrentVersion 返回当前版本号；无策略时返回 0。
func (s *Store) CurrentVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Snapshot 取指定版本的只读快照；version<=0 表示取当前版本。
// 返回的 *Policy 为内部不可变对象，调用方不得修改。
func (s *Store) Snapshot(version int) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if version <= 0 {
		version = s.current
	}
	p, ok := s.versions[version]
	if !ok {
		return nil, fmt.Errorf("policy store: version %d not found (current=%d)", version, s.current)
	}
	return p, nil
}

// clonePolicy 深拷贝策略，使存储版本与调用方对象完全隔离。
func clonePolicy(p *Policy) *Policy {
	cp := &Policy{Version: p.Version, Name: p.Name, Rules: make([]Rule, len(p.Rules))}
	for i, r := range p.Rules {
		nr := Rule{
			ID: r.ID, Effect: r.Effect, Priority: r.Priority,
			Actions:   append([]Action(nil), r.Actions...),
			Resources: append([]string(nil), r.Resources...),
			Subjects:  append([]string(nil), r.Subjects...),
		}
		for _, c := range r.Conditions {
			nr.Conditions = append(nr.Conditions, Condition{Key: c.Key, Op: c.Op, Val: c.Val})
		}
		for _, m := range r.Mask {
			nr.Mask = append(nr.Mask, MaskRule{Field: m.Field, Method: m.Method, Keep: m.Keep})
		}
		cp.Rules[i] = nr
	}
	return cp
}
