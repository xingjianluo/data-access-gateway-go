package dsr

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// Kind 是数据主体请求类型。
type Kind string

const (
	KindExport Kind = "export"
	KindDelete Kind = "delete"
)

// Status 是请求处理状态。
type Status string

const (
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// SweepAction 是保留期到期后的处置方式。
type SweepAction string

const (
	// SweepDelete 到期清除。
	SweepDelete SweepAction = "delete"
	// SweepAnonymize 到期匿名化指定字段。
	SweepAnonymize SweepAction = "anonymize"
)

// RequestRecord 记录一个数据主体请求的幂等状态与结果。
type RequestRecord struct {
	ID        string
	Kind      Kind
	SubjectID string
	Status    Status
	Error     string
	Replicas  int // 覆盖到的副本数
	AuditSeqs []int64
	CreatedAt time.Time
}

// ExportRecord 是导出结果中的一条记录。
type ExportRecord struct {
	Resource string
	Data     map[string]any
}

// Result 是 DSR 请求处理结果；重复请求返回首次结果且 Idempotent=true
// （调用方可显式识别为重放，而非静默成功）；失败的请求可凭同一 ID 重试。
type Result struct {
	// Idempotent 为 true 表示本次未重新执行，直接返回首次完成时的结果。
	Idempotent bool
	RequestRecord
	Records []ExportRecord
}

// state 是某个请求 ID 的内部状态（含首次导出的数据快照，用于幂等重放）。
// mu 串行化同一请求 ID 的并发执行：同一时刻最多一个执行体，
// 并发提交的重复请求会阻塞到首次执行完成后按重放返回。
type state struct {
	mu      sync.Mutex
	rec     RequestRecord
	records []ExportRecord
	// audited 记录删除类请求中每个资源已写入的审计 seq，
	// 失败重试时已审计的资源不重复写审计（最终只有一份成功记录）。
	audited map[string]int64
}

// Processor 处理数据主体请求：覆盖全部存储副本、保持审计不可变、
// 失败可重试并给出原因、重复请求幂等可识别。
type Processor struct {
	store *data.Store
	audit *audit.Log

	mu       sync.Mutex
	requests map[string]*state

	dispMu    sync.Mutex
	disposals map[string]*disposition // 按资源跟踪到期处置进度
}

// New 创建处理器。
func New(ds *data.Store, log *audit.Log) *Processor {
	return &Processor{store: ds, audit: log, requests: make(map[string]*state), disposals: make(map[string]*disposition)}
}

// stateFor 取（或创建）某请求 ID 的执行状态。
func (p *Processor) stateFor(requestID string, kind Kind, subjectID string, replicas int) *state {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.requests[requestID]
	if !ok {
		st = &state{
			rec: RequestRecord{
				ID: requestID, Kind: kind, SubjectID: subjectID,
				Replicas: replicas, CreatedAt: time.Now().UTC(),
			},
			audited: make(map[string]int64),
		}
		p.requests[requestID] = st
	}
	return st
}

// Export 执行（或幂等重放）数据主体导出请求。
// 必须从每一个副本读取并交叉比对一致，才算覆盖全部副本；副本间不一致或
// 未覆盖全部副本时失败并给出原因，可凭同一请求 ID 重试。
// 同一请求 ID 并发提交时只有一个真正执行，其余按重放返回首次结果。
func (p *Processor) Export(requestID, subjectID string) (Result, error) {
	st := p.stateFor(requestID, KindExport, subjectID, p.store.ReplicaCount())
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rec.Status == StatusCompleted {
		return replay(st), nil
	}

	n := p.store.ReplicaCount()
	perReplica := make([][]data.Record, n)
	for i := 0; i < n; i++ {
		perReplica[i] = p.store.ExportReplica(i, subjectID)
	}
	// 交叉校验：每个副本的资源集合与数据必须完全一致。
	if err := compareReplicas(perReplica); err != nil {
		failed := fmt.Errorf("export request %s failed: %w; retryable", requestID, err)
		p.recordFailureLocked(st, failed.Error())
		return Result{}, failed
	}

	records := make([]ExportRecord, 0, len(perReplica[0]))
	for _, r := range perReplica[0] {
		d := make(map[string]any, len(r.Data))
		for k, v := range r.Data {
			d[k] = v
		}
		records = append(records, ExportRecord{Resource: r.Resource, Data: d})
	}

	seq, err := p.appendAudit(requestID, "dsr.export", fmt.Sprintf("subject:%s", subjectID),
		fmt.Sprintf("exported %d records across %d replicas", len(records), n))
	if err != nil {
		failed := fmt.Errorf("export request %s failed: %w; retryable", requestID, err)
		p.recordFailureLocked(st, failed.Error())
		return Result{}, failed
	}

	st.rec.Status = StatusCompleted
	st.rec.Error = ""
	st.rec.Replicas = n
	st.rec.AuditSeqs = []int64{seq}
	st.records = records
	return firstResult(st), nil
}

// Delete 执行（或幂等重放）数据主体删除请求。
// 仅在全部健康副本可写时才执行删除（存储层预检，不产生部分写入）；
// 删除后再次读取每个副本校验数据主体记录已不存在。
// 目标集合取全部副本的并集：曾故障的副本里残留的记录在恢复后重试时也会被清掉。
// 同一请求 ID 并发提交时只有一个真正执行；失败重试不会重复写已成功的审计。
func (p *Processor) Delete(requestID, subjectID string) (Result, error) {
	st := p.stateFor(requestID, KindDelete, subjectID, p.store.ReplicaCount())
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rec.Status == StatusCompleted {
		return replay(st), nil
	}

	n := p.store.ReplicaCount()
	// 目标 = 全部副本中该主体记录的并集（含残留副本），按资源名排序保证稳定。
	targetSet := map[string]bool{}
	for i := 0; i < n; i++ {
		for _, rec := range p.store.ExportReplica(i, subjectID) {
			targetSet[rec.Resource] = true
		}
	}
	targets := make([]string, 0, len(targetSet))
	for res := range targetSet {
		targets = append(targets, res)
	}
	sort.Strings(targets)

	for _, resource := range targets {
		existed, err := p.store.Delete(resource)
		if err != nil {
			failed := fmt.Errorf("delete request %s failed at resource %s: %w; retryable", requestID, resource, err)
			p.recordFailureLocked(st, failed.Error())
			return Result{}, failed
		}
		if _, done := st.audited[resource]; done {
			continue // 本资源在此前的尝试中已写审计，重试不重复写
		}
		seq, aerr := p.appendAudit(requestID, "dsr.delete", resource,
			fmt.Sprintf("deleted for subject %s (existed=%t) across %d replicas", subjectID, existed, n))
		if aerr != nil {
			failed := fmt.Errorf("delete request %s failed: %w; retryable", requestID, aerr)
			p.recordFailureLocked(st, failed.Error())
			return Result{}, failed
		}
		st.audited[resource] = seq
	}

	// 删除后校验：每个副本都不应再包含该主体的记录。
	for i := 0; i < n; i++ {
		if left := p.store.ExportReplica(i, subjectID); len(left) != 0 {
			err := fmt.Errorf("replica %d still contains %d records of subject %s", i, len(left), subjectID)
			failed := fmt.Errorf("delete request %s failed: %w; retryable", requestID, err)
			p.recordFailureLocked(st, failed.Error())
			return Result{}, failed
		}
	}

	seqs := make([]int64, 0, len(st.audited))
	for _, resource := range targets {
		if seq, ok := st.audited[resource]; ok {
			seqs = append(seqs, seq)
		}
	}
	st.rec.Status = StatusCompleted
	st.rec.Error = ""
	st.rec.Replicas = n
	st.rec.AuditSeqs = seqs
	st.records = nil
	return firstResult(st), nil
}

// disposition 记录一个资源一次到期处置的进度，跨多次扫描保留：
//   - 已完成的处置再次扫描时直接跳过（不重复处置、不重复写审计）；
//   - 部分副本故障导致的未完成处置，在副本恢复后的重跑中继续收敛；
//   - 审计只在处置真正覆盖全部副本后写一次。
type disposition struct {
	action    SweepAction
	fields    []string
	ruleID    string    // 决定本次处置的保留期规则 ID；"fallback" 表示走调用方兜底
	expiredAt time.Time // 首次处置时记录的到期时刻，审计口径跨重试保持一致
	auditSeq  int64     // 已写审计的 seq；0 表示尚未写
	done      bool      // 数据已在全部副本收敛且审计已写
}

// RetentionSweep 按调用方指定的统一处置方式扫描到期数据（兼容旧行为）。
// 等价于 RetentionSweepByPolicy(now, nil, action, fields)。
func (p *Processor) RetentionSweep(now time.Time, action SweepAction, fields []string) ([]string, error) {
	return p.RetentionSweepByPolicy(now, nil, action, fields)
}

// RetentionSweepByPolicy 对 now 时刻已过保留期的数据按策略执行处置：
// 每个资源先查策略中的保留期规则（RetentionFor），命中则按规则声明的方式
// （整条清除 / 匿名化策略指定字段）处置；未命中的资源走 fallback 兜底（兼容旧行为）。
// 同一次扫描里不同资源可走不同处置，单个资源失败不影响其他资源。
//
// 收敛语义：
//   - 处置覆盖全部副本并逐副本核验后才写审计、标记完成，绝不"报成功但没处置完"；
//   - 副本不可用导致失败的资源被记为待完成，恢复后重跑会继续清理残留；
//   - 已完成的资源再次扫描直接跳过，不重复处置、不重复写审计；
//   - 到期边界沿用 RetainUntil.Before(now)（到期时刻本身未到期）。
//
// 返回本次扫描中完成处置的资源（按名称排序）与聚合错误（若有资源未能收敛）。
func (p *Processor) RetentionSweepByPolicy(now time.Time, snap *policy.Policy, fallback SweepAction, fallbackFields []string) ([]string, error) {
	// 候选 = 当前到期的记录 + 此前未完成的处置（故障恢复后的残留收敛）。
	type candidate struct {
		resource  string
		expiredAt time.Time
	}
	seen := map[string]bool{}
	var cands []candidate
	for _, rec := range p.store.Expired(now) {
		seen[rec.Resource] = true
		cands = append(cands, candidate{resource: rec.Resource, expiredAt: *rec.RetainUntil})
	}
	p.dispMu.Lock()
	for res, d := range p.disposals {
		if !d.done && !seen[res] {
			cands = append(cands, candidate{resource: res, expiredAt: d.expiredAt})
		}
	}
	p.dispMu.Unlock()
	sort.Slice(cands, func(i, j int) bool { return cands[i].resource < cands[j].resource })

	var affected []string
	var errs []error
	for _, c := range cands {
		done, err := p.disposeOne(c.resource, c.expiredAt, snap, fallback, fallbackFields)
		if err != nil {
			errs = append(errs, err)
			continue // 单资源失败不影响其他资源的处置
		}
		if done {
			affected = append(affected, c.resource)
		}
	}
	return affected, errors.Join(errs...)
}

// disposeOne 处置单个到期资源；返回是否在本次调用中完成收敛。
// 已完成（done）的处置直接跳过；同名资源若带有新的到期时刻则视为新一轮处置。
func (p *Processor) disposeOne(resource string, expiredAt time.Time, snap *policy.Policy, fallback SweepAction, fields []string) (bool, error) {
	p.dispMu.Lock()
	d, exists := p.disposals[resource]
	if exists && d.done && d.expiredAt.Equal(expiredAt) {
		p.dispMu.Unlock()
		return false, nil // 已处置过，不重复处置、不重复写审计
	}
	if !exists || (d.done && !d.expiredAt.Equal(expiredAt)) {
		// 首次处置（或同名资源的新一轮到期）：按策略解析处置方式。
		action, flds, ruleID := fallback, fields, "fallback"
		if rule, ok := snap.RetentionFor(resource); ok {
			action = SweepAction(rule.Action)
			flds = rule.AnonymizeFields
			ruleID = rule.ID
		}
		d = &disposition{action: action, fields: flds, ruleID: ruleID, expiredAt: expiredAt}
		p.disposals[resource] = d
	}
	p.dispMu.Unlock()

	// 数据操作：全部副本预检，任一副本不可用则整体失败（可重试），不产生部分写入。
	switch d.action {
	case SweepDelete:
		if _, err := p.store.Delete(resource); err != nil {
			return false, fmt.Errorf("retention sweep: delete %s: %w", resource, err)
		}
	case SweepAnonymize:
		if _, err := p.store.Anonymize(resource, d.fields); err != nil {
			return false, fmt.Errorf("retention sweep: anonymize %s: %w", resource, err)
		}
		// 处置完成即清除保留期标记，避免后续扫描重复选中。
		if rec, ok := p.store.Get(resource); ok {
			rec.RetainUntil = nil
			if err := p.store.Put(rec); err != nil {
				return false, fmt.Errorf("retention sweep: clear retention %s: %w", resource, err)
			}
		}
	default:
		return false, fmt.Errorf("retention sweep: unknown action %q for %s", d.action, resource)
	}

	// 逐副本核验处置真正收敛，杜绝"报成功但其实没处置完"。
	if err := p.verifyDisposed(resource, d); err != nil {
		return false, err
	}

	// 审计只写一次（重试时若已写则跳过）。
	p.dispMu.Lock()
	alreadyAudited := d.auditSeq != 0
	p.dispMu.Unlock()
	if !alreadyAudited {
		var action, reason string
		switch d.action {
		case SweepDelete:
			action = "retention.delete"
			reason = fmt.Sprintf("retention expired at %s; deleted at sweep by rule %s", d.expiredAt.Format(time.RFC3339), d.ruleID)
		case SweepAnonymize:
			action = "retention.anonymize"
			reason = fmt.Sprintf("retention expired at %s; anonymized fields %v at sweep by rule %s", d.expiredAt.Format(time.RFC3339), d.fields, d.ruleID)
		}
		seq, err := p.appendAudit(fmt.Sprintf("retention:%s", resource), action, resource, reason)
		if err != nil {
			return false, fmt.Errorf("retention sweep audit %s: %w", resource, err)
		}
		p.dispMu.Lock()
		d.auditSeq = seq
		p.dispMu.Unlock()
	}

	p.dispMu.Lock()
	d.done = true
	p.dispMu.Unlock()
	return true, nil
}

// verifyDisposed 逐副本核验处置结果：delete 要求所有副本均无此资源；
// anonymize 要求所有副本中目标字段已匿名化且保留期标记已清除。
func (p *Processor) verifyDisposed(resource string, d *disposition) error {
	n := p.store.ReplicaCount()
	for i := 0; i < n; i++ {
		rec, ok := p.store.GetReplica(i, resource)
		switch d.action {
		case SweepDelete:
			if ok {
				return fmt.Errorf("retention sweep: %s still present in replica %d after delete; retryable", resource, i)
			}
		case SweepAnonymize:
			if !ok {
				continue // 副本中本就没有该记录，视为已收敛
			}
			if rec.RetainUntil != nil {
				return fmt.Errorf("retention sweep: %s in replica %d still has retention marker; retryable", resource, i)
			}
			for _, f := range d.fields {
				if v, present := rec.Data[f]; present && v != "<anonymized>" {
					return fmt.Errorf("retention sweep: %s field %q in replica %d not anonymized; retryable", resource, f, i)
				}
			}
		}
	}
	return nil
}

// compareReplicas 校验各副本导出的记录集合完全一致（资源顺序与数据）。
func compareReplicas(replicas [][]data.Record) error {
	if len(replicas) == 0 {
		return fmt.Errorf("no replicas")
	}
	base := replicaFingerprint(replicas[0])
	for i := 1; i < len(replicas); i++ {
		fp := replicaFingerprint(replicas[i])
		if !reflect.DeepEqual(fp, base) {
			return fmt.Errorf("replica %d diverges from replica 0 for the subject", i)
		}
	}
	return nil
}

// replicaFingerprint 生成副本中记录的稳定指纹（资源 + 排序后的字段键值）。
func replicaFingerprint(records []data.Record) []map[string]any {
	fp := make([]map[string]any, 0, len(records))
	for _, r := range records {
		keys := make([]string, 0, len(r.Data))
		for k := range r.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m := map[string]any{"__resource": r.Resource}
		for _, k := range keys {
			m[k] = r.Data[k]
		}
		fp = append(fp, m)
	}
	return fp
}

func (p *Processor) appendAudit(requestID, action, resource, reason string) (int64, error) {
	e, err := p.audit.Append(audit.Entry{
		RequestID: requestID,
		Action:    action,
		Resource:  resource,
		Decision:  "completed",
		Reason:    reason,
	})
	if err != nil {
		return 0, err
	}
	return e.Seq, nil
}

// recordFailureLocked 在 st.mu 持锁状态下把请求标记为失败（可凭同一 ID 重试）。
func (p *Processor) recordFailureLocked(st *state, msg string) {
	st.rec.Status = StatusFailed
	st.rec.Error = msg
}

func replay(st *state) Result {
	r := firstResult(st)
	r.Idempotent = true
	return r
}

func firstResult(st *state) Result {
	return Result{
		Idempotent:    false,
		RequestRecord: st.rec,
		Records:       st.records,
	}
}
