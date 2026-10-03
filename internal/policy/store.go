package policy

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
)

// ChangeRecord 记录一次策略发布/切换：时间、从哪个版本换到哪个版本、
// 这批规则的大致内容。历史随 Store 保存，同时在挂接审计日志时
// 追加一条不可篡改的审计条目（纳入哈希链完整性校验）。
type ChangeRecord struct {
	Seq            int       // 变更序号，从 1 单调递增
	Time           time.Time // 发布发生时间（UTC）
	FromVersion    int       // 0 表示首次发布
	ToVersion      int
	PolicyName     string
	RuleIDs        []string // 本版规则 ID 摘要
	RetentionIDs   []string // 本版保留期规则 ID 摘要
	Summary        string   // 人读摘要
}

// Store 保存策略的多个不可变版本，支持热更新与按版本取快照。
// 已发布的策略永不被原地修改：热更新即新增一个版本并原子切换 current 指针，
// 因此已经在处理中的请求仍可继续使用旧版本快照，保证单请求生命周期内一致。
type Store struct {
	mu       sync.RWMutex
	versions map[int]*Policy
	current  int
	changes  []ChangeRecord
	audit    *audit.Log // 可选；挂接后每次发布追加不可篡改审计
}

// NewStore 创建空策略存储。
func NewStore() *Store {
	return &Store{versions: make(map[int]*Policy)}
}

// AttachAudit 挂接审计日志：此后每次 Publish 先向审计链追加一条
// policy.publish 条目（含 from/to 版本与规则摘要），审计写入失败则发布失败，
// 保证"每次发布/切换都有不可篡改记录"不被静默跳过。
func (s *Store) AttachAudit(log *audit.Log) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = log
}

// Publish 发布一个新版本（必须单调递增），并将其置为当前版本。
// 传入的策略会被深拷贝后保存，调用方之后修改原对象不影响已发布版本。
// 每次发布都会留下一条 ChangeRecord（内存历史 + 可选的审计链条目）。
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

	rec := ChangeRecord{
		Seq:          len(s.changes) + 1,
		Time:         time.Now().UTC(),
		FromVersion:  s.current,
		ToVersion:    p.Version,
		PolicyName:   p.Name,
		RuleIDs:      make([]string, 0, len(p.Rules)),
		RetentionIDs: make([]string, 0, len(p.Retention)),
	}
	for _, r := range p.Rules {
		rec.RuleIDs = append(rec.RuleIDs, r.ID)
	}
	for _, r := range p.Retention {
		rec.RetentionIDs = append(rec.RetentionIDs, r.ID)
	}
	rec.Summary = fmt.Sprintf("policy %q v%d -> v%d: rules=[%s] retention=[%s]",
		p.Name, rec.FromVersion, rec.ToVersion,
		strings.Join(rec.RuleIDs, ","), strings.Join(rec.RetentionIDs, ","))
	if rec.FromVersion == 0 {
		rec.Summary = fmt.Sprintf("policy %q installed as v%d: rules=[%s] retention=[%s]",
			p.Name, rec.ToVersion,
			strings.Join(rec.RuleIDs, ","), strings.Join(rec.RetentionIDs, ","))
	}

	// 先写不可篡改审计，再提交切换：审计失败则发布整体失败。
	if s.audit != nil {
		if _, err := s.audit.Append(audit.Entry{
			RequestID: fmt.Sprintf("policy-change:%d", rec.Seq),
			Action:    "policy.publish",
			Resource:  fmt.Sprintf("policy/%s", p.Name),
			Decision:  "published",
			PolicyVer: rec.ToVersion,
			Reason:    rec.Summary,
			Detail:    fmt.Sprintf("from_version=%d to_version=%d at %s", rec.FromVersion, rec.ToVersion, rec.Time.Format(time.RFC3339Nano)),
		}); err != nil {
			return fmt.Errorf("policy store: record policy change audit: %w", err)
		}
	}

	s.versions[p.Version] = clonePolicy(p)
	s.current = p.Version
	s.changes = append(s.changes, rec)
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

// Changes 返回全部策略变更历史（按发生顺序，只读拷贝）。
func (s *Store) Changes() []ChangeRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChangeRecord, len(s.changes))
	copy(out, s.changes)
	return out
}

// ChangeForVersion 查找"某个版本是怎么装进来的"那条变更记录，
// 供审计追溯：从一次访问的 policy_version 顺藤摸瓜到该版本的安装时间与内容摘要。
func (s *Store) ChangeForVersion(version int) (ChangeRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.changes {
		if c.ToVersion == version {
			return c, true
		}
	}
	return ChangeRecord{}, false
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
	for _, r := range p.Retention {
		cp.Retention = append(cp.Retention, RetentionRule{
			ID: r.ID, Action: r.Action, Priority: r.Priority,
			Resources:       append([]string(nil), r.Resources...),
			AnonymizeFields: append([]string(nil), r.AnonymizeFields...),
		})
	}
	return cp
}
