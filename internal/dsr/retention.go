package dsr

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xingjianluo/data-access-gateway-go/internal/audit"
	"github.com/xingjianluo/data-access-gateway-go/internal/data"
	"github.com/xingjianluo/data-access-gateway-go/internal/policy"
)

// SweepFailure 记录一轮扫描中某个资源处置失败的明细，供调用方定位残留、决定重跑。
type SweepFailure struct {
	Resource string
	Err      error
}

// PartialSweepError 表示一轮扫描未全部完成：Succeeded 为本轮已成功处置的资源，
// Failures 为处置失败、仍有残留需重跑的资源。错误明确可重试——只要它非空，
// 调用方就绝不能把这轮当作成功；待失败原因消除（副本恢复、规则修好）后重跑即可收敛。
//
// 单个资源处置失败只记录在 Failures 中，绝不影响同轮其他资源：
// 其他该删除/匿名化的资源照常完成并各写一条处置审计。
type PartialSweepError struct {
	Succeeded []string
	Failures  []SweepFailure
}

func (e *PartialSweepError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf("%s: %v", f.Resource, f.Err))
	}
	return fmt.Sprintf("retention sweep incomplete: %d resource(s) failed and are retryable after the cause is fixed [%s]; succeeded=%v",
		len(e.Failures), strings.Join(parts, "; "), e.Succeeded)
}

// SweepWithPolicy 按策略对 now 时刻已过保留期的数据逐资源处置：
//   - 资源命中策略中的保留期规则时，按规则声明的方式处置（整条清除 / 匿名化指定字段）；
//   - 未命中任何规则的资源沿用 fallbackAction/fallbackFields（兼容未配置策略的旧行为）。
//
// 单轮扫描内各资源处置互不影响：某个资源因保留期规则内容有误或存储副本不可用而
// 处置失败时，只把它记入返回的 *PartialSweepError，同轮其他资源仍继续处置并各写
// 一条不可变审计（记录所用策略版本）。只要本轮存在失败资源就返回该错误（明确
// 可重试），绝不"报成功但没处置完"；失败资源不标记台账，待原因消除（副本恢复、
// 规则修好）后重跑即把残留补齐，成功资源则由处置台账挡下、不会重复处置或重复写
// 审计，最终每种处置恰好一条审计。到期边界与 RetentionSweep 一致：严格
// RetainUntil < now。
//
// 全部成功时返回 (受影响资源, nil)；存在失败时返回 (本轮已成功资源, *PartialSweepError)。
func (p *Processor) SweepWithPolicy(now time.Time, snap *policy.Policy, fallbackAction SweepAction, fallbackFields []string) ([]string, error) {
	version := 0
	if snap != nil {
		version = snap.Version
	}
	expired := p.store.Expired(now)
	succeeded := make([]string, 0, len(expired))
	var failures []SweepFailure
	// fail 记录本资源的处置失败并继续处理下一个资源——资源之间互不拖累。
	fail := func(resource string, err error) {
		failures = append(failures, SweepFailure{Resource: resource, Err: err})
	}
	for _, rec := range expired {
		if rec.RetainUntil == nil {
			continue
		}
		// 处置台账：同一 (资源, 到期时刻) 已处置过则跳过，避免重复处置与重复审计。
		marker := disposeMarker(rec.Resource, *rec.RetainUntil)
		if p.isDisposed(marker) {
			continue
		}

		action, fields := fallbackAction, fallbackFields
		source := "fallback"
		if rule, ok := snap.RetentionFor(rec.Resource); ok {
			switch rule.Action {
			case policy.RetentionDelete:
				action, fields = SweepDelete, nil
			case policy.RetentionAnonymize:
				action, fields = SweepAnonymize, rule.Fields
			default:
				// 规则内容问题只影响该资源自身，绝不中断同轮其他资源。
				fail(rec.Resource, fmt.Errorf("policy rule %s has unknown action %q", rule.ID, rule.Action))
				continue
			}
			source = fmt.Sprintf("policy rule %s (v%d)", rule.ID, version)
		}

		var err error
		switch action {
		case SweepDelete:
			err = p.sweepDelete(rec, now, version, source)
		case SweepAnonymize:
			err = p.sweepAnonymize(rec, now, fields, version, source)
		default:
			err = fmt.Errorf("unknown sweep action %q", action)
		}
		if err != nil {
			fail(rec.Resource, err)
			continue
		}
		p.markDisposed(marker)
		succeeded = append(succeeded, rec.Resource)
	}
	sort.Strings(succeeded)
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Resource < failures[j].Resource })
	if len(failures) > 0 {
		return succeeded, &PartialSweepError{Succeeded: succeeded, Failures: failures}
	}
	return succeeded, nil
}

// sweepDelete 从全部健康副本删除记录并写审计（存储层预检，不产生部分写入）。
func (p *Processor) sweepDelete(rec data.Record, now time.Time, version int, source string) error {
	if _, err := p.store.Delete(rec.Resource); err != nil {
		return err
	}
	return p.sweepAudit(rec.Resource, "retention.delete", version,
		fmt.Sprintf("retention expired at %s; deleted at %s via %s",
			rec.RetainUntil.Format(time.RFC3339), now.Format(time.RFC3339), source))
}

// sweepAnonymize 将全部健康副本中策略指定的字段匿名化，并清除保留期标记，
// 使后续扫描不会重复命中该记录。
func (p *Processor) sweepAnonymize(rec data.Record, now time.Time, fields []string, version int, source string) error {
	if _, err := p.store.Anonymize(rec.Resource, fields); err != nil {
		return err
	}
	updated, ok := p.store.Get(rec.Resource)
	if ok {
		updated.RetainUntil = nil
		if err := p.store.Put(updated); err != nil {
			return fmt.Errorf("clear retention marker: %w", err)
		}
	}
	return p.sweepAudit(rec.Resource, "retention.anonymize", version,
		fmt.Sprintf("retention expired at %s; anonymized fields %v at %s via %s",
			rec.RetainUntil.Format(time.RFC3339), fields, now.Format(time.RFC3339), source))
}

// sweepAudit 写一条保留期处置审计；审计写入失败视为处置失败（可重试），
// 不允许"处置了但没留痕"。
func (p *Processor) sweepAudit(resource, action string, version int, reason string) error {
	_, err := p.audit.Append(audit.Entry{
		RequestID: fmt.Sprintf("retention:%s", resource),
		Action:    action,
		Resource:  resource,
		Decision:  "completed",
		PolicyVer: version,
		Reason:    reason,
	})
	return err
}

func disposeMarker(resource string, retainUntil time.Time) string {
	return resource + "|" + retainUntil.UTC().Format(time.RFC3339Nano)
}

func (p *Processor) isDisposed(marker string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.disposed[marker]
	return ok
}

func (p *Processor) markDisposed(marker string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disposed[marker] = struct{}{}
}
