package dsr

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
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
type state struct {
	rec     RequestRecord
	records []ExportRecord
}

// Processor 处理数据主体请求：覆盖全部存储副本、保持审计不可变、
// 失败可重试并给出原因、重复请求幂等可识别。
type Processor struct {
	store *data.Store
	audit *audit.Log

	mu       sync.Mutex
	requests map[string]*state
}

// New 创建处理器。
func New(ds *data.Store, log *audit.Log) *Processor {
	return &Processor{store: ds, audit: log, requests: make(map[string]*state)}
}

// Export 执行（或幂等重放）数据主体导出请求。
// 必须从每一个副本读取并交叉比对一致，才算覆盖全部副本；副本间不一致或
// 未覆盖全部副本时失败并给出原因，可凭同一请求 ID 重试。
func (p *Processor) Export(requestID, subjectID string) (Result, error) {
	p.mu.Lock()
	if st, ok := p.requests[requestID]; ok && st.rec.Status == StatusCompleted {
		p.mu.Unlock()
		return replay(st), nil
	}
	p.mu.Unlock()

	n := p.store.ReplicaCount()
	perReplica := make([][]data.Record, n)
	for i := 0; i < n; i++ {
		perReplica[i] = p.store.ExportReplica(i, subjectID)
	}
	// 交叉校验：每个副本的资源集合与数据必须完全一致。
	if err := compareReplicas(perReplica); err != nil {
		failed := fmt.Errorf("export request %s failed: %w; retryable", requestID, err)
		p.recordFailure(requestID, KindExport, subjectID, n, failed.Error())
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
		p.recordFailure(requestID, KindExport, subjectID, n, failed.Error())
		return Result{}, failed
	}

	st := p.recordSuccess(requestID, KindExport, subjectID, n, []int64{seq}, records)
	return firstResult(st), nil
}

// Delete 执行（或幂等重放）数据主体删除请求。
// 仅在全部健康副本可写时才执行删除（存储层预检，不产生部分写入）；
// 删除后再次读取每个副本校验数据主体记录已不存在。
func (p *Processor) Delete(requestID, subjectID string) (Result, error) {
	p.mu.Lock()
	if st, ok := p.requests[requestID]; ok && st.rec.Status == StatusCompleted {
		p.mu.Unlock()
		return replay(st), nil
	}
	p.mu.Unlock()

	n := p.store.ReplicaCount()
	targets := p.store.FindBySubject(subjectID)

	var seqs []int64
	for _, rec := range targets {
		existed, err := p.store.Delete(rec.Resource)
		if err != nil {
			failed := fmt.Errorf("delete request %s failed at resource %s: %w; retryable", requestID, rec.Resource, err)
			p.recordFailure(requestID, KindDelete, subjectID, n, failed.Error())
			return Result{}, failed
		}
		seq, aerr := p.appendAudit(requestID, "dsr.delete", rec.Resource,
			fmt.Sprintf("deleted for subject %s (existed=%t) across %d replicas", subjectID, existed, n))
		if aerr != nil {
			failed := fmt.Errorf("delete request %s failed: %w; retryable", requestID, aerr)
			p.recordFailure(requestID, KindDelete, subjectID, n, failed.Error())
			return Result{}, failed
		}
		seqs = append(seqs, seq)
	}

	// 删除后校验：每个副本都不应再包含该主体的记录。
	for i := 0; i < n; i++ {
		if left := p.store.ExportReplica(i, subjectID); len(left) != 0 {
			err := fmt.Errorf("replica %d still contains %d records of subject %s", i, len(left), subjectID)
			failed := fmt.Errorf("delete request %s failed: %w; retryable", requestID, err)
			p.recordFailure(requestID, KindDelete, subjectID, n, failed.Error())
			return Result{}, failed
		}
	}

	st := p.recordSuccess(requestID, KindDelete, subjectID, n, seqs, nil)
	return firstResult(st), nil
}

// RetentionSweep 对 now 时刻已过保留期的数据执行处置：
// SweepDelete 清除，SweepAnonymize 将 fields 匿名化。每条处置写一条不可变审计。
// 返回受影响的资源（按名称排序）。
func (p *Processor) RetentionSweep(now time.Time, action SweepAction, fields []string) ([]string, error) {
	expired := p.store.Expired(now)
	affected := make([]string, 0, len(expired))
	for _, rec := range expired {
		switch action {
		case SweepDelete:
			if _, err := p.store.Delete(rec.Resource); err != nil {
				return affected, fmt.Errorf("retention sweep: delete %s: %w; retryable", rec.Resource, err)
			}
			if _, err := p.appendAudit(fmt.Sprintf("retention:%s", rec.Resource), "retention.delete", rec.Resource,
				fmt.Sprintf("retention expired at %s; deleted at %s", rec.RetainUntil.Format(time.RFC3339), now.Format(time.RFC3339))); err != nil {
				return affected, fmt.Errorf("retention sweep audit: %w", err)
			}
		case SweepAnonymize:
			if _, err := p.store.Anonymize(rec.Resource, fields); err != nil {
				return affected, fmt.Errorf("retention sweep: anonymize %s: %w; retryable", rec.Resource, err)
			}
			// 处置完成即标记为已处理：清除保留期，避免后续扫描重复匿名化。
			updated, ok := p.store.Get(rec.Resource)
			if ok {
				updated.RetainUntil = nil
				if err := p.store.Put(updated); err != nil {
					return affected, fmt.Errorf("retention sweep: clear retention %s: %w; retryable", rec.Resource, err)
				}
			}
			if _, err := p.appendAudit(fmt.Sprintf("retention:%s", rec.Resource), "retention.anonymize", rec.Resource,
				fmt.Sprintf("retention expired at %s; anonymized fields %v at %s", rec.RetainUntil.Format(time.RFC3339), fields, now.Format(time.RFC3339))); err != nil {
				return affected, fmt.Errorf("retention sweep audit: %w", err)
			}
		default:
			return affected, fmt.Errorf("retention sweep: unknown action %q", action)
		}
		affected = append(affected, rec.Resource)
	}
	sort.Strings(affected)
	return affected, nil
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

func (p *Processor) recordFailure(requestID string, kind Kind, subjectID string, replicas int, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests[requestID] = &state{rec: RequestRecord{
		ID: requestID, Kind: kind, SubjectID: subjectID,
		Status: StatusFailed, Error: msg, Replicas: replicas, CreatedAt: time.Now().UTC(),
	}}
}

func (p *Processor) recordSuccess(requestID string, kind Kind, subjectID string, replicas int, seqs []int64, records []ExportRecord) *state {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := &state{
		rec: RequestRecord{
			ID: requestID, Kind: kind, SubjectID: subjectID,
			Status: StatusCompleted, Replicas: replicas, AuditSeqs: append([]int64(nil), seqs...),
			CreatedAt: time.Now().UTC(),
		},
		records: records,
	}
	p.requests[requestID] = st
	return st
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
