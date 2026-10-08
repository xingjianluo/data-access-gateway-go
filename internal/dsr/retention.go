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

// SweepWithPolicy 按策略对 now 时刻已过保留期的数据逐资源处置：
//   - 资源命中策略中的保留期规则时，按规则声明的方式处置（整条清除 / 匿名化指定字段）；
//   - 未命中任何规则的资源沿用 fallbackAction/fallbackFields（兼容未配置策略的旧行为）。
//
// 单轮扫描内各资源的处置互不影响：某个资源处置失败（命中的规则内容有误、
// 其存储副本暂不可用、审计写入失败等）只记录该资源的失败原因并继续处置其余资源，
// 绝不中断同轮其他资源。成功处置的资源返回在 affected 中（按名称排序）并各写一条
// 不可变审计（记录本次使用的策略版本）。
//
// 只要本轮有资源未处置完，就返回 *SweepIncompleteError（错误文案明确可重试），
// 绝不"报成功但没处置完"；调用方重跑同一轮扫描即可：已成功的资源由处置台账
// （资源+到期时刻）跳过，不再重复处置、不再重复写审计；此前失败的资源恢复后
// （副本回来、规则修好）在重跑中补齐，直到全部到期资源收敛。
// 到期边界与 RetentionSweep 一致：严格 RetainUntil < now。
func (p *Processor) SweepWithPolicy(now time.Time, snap *policy.Policy, fallbackAction SweepAction, fallbackFields []string) ([]string, error) {
	version := 0
	if snap != nil {
		version = snap.Version
	}
	expired := p.store.Expired(now)
	affected := make([]string, 0, len(expired))
	var failures []*ResourceFailure
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
				// 规则内容问题只影响命中该规则的资源，不拖累同轮其他资源。
				failures = append(failures, &ResourceFailure{
					Resource: rec.Resource,
					Err:      fmt.Errorf("policy rule %s has unknown action %q; retryable after rule fixed", rule.ID, rule.Action),
				})
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
			err = fmt.Errorf("unknown sweep action %q; retryable after caller configuration fixed", action)
		}
		if err != nil {
			// 单资源失败不中断扫描：记录原因（可重试），其余到期资源照常处置。
			failures = append(failures, &ResourceFailure{Resource: rec.Resource, Err: err})
			continue
		}
		p.markDisposed(marker)
		affected = append(affected, rec.Resource)
	}
	sort.Strings(affected)
	if len(failures) > 0 {
		return affected, &SweepIncompleteError{Failed: failures}
	}
	return affected, nil
}

// ResourceFailure 记录单轮扫描中某个资源处置失败的原因；该资源未进入处置台账，
// 下轮重跑会重试，且不会为其写成功处置审计。
type ResourceFailure struct {
	Resource string
	Err      error
}

func (f *ResourceFailure) Error() string {
	return fmt.Sprintf("resource %s: %v", f.Resource, f.Err)
}

// SweepIncompleteError 表示一轮扫描未全部完成：本轮有资源处置失败，
// 调用方应修复故障后重跑同一轮扫描以收敛。错误按资源名稳定排序，可程序判断。
type SweepIncompleteError struct {
	Failed []*ResourceFailure
}

func (e *SweepIncompleteError) Error() string {
	fails := append([]*ResourceFailure(nil), e.Failed...)
	sort.Slice(fails, func(i, j int) bool { return fails[i].Resource < fails[j].Resource })
	var b strings.Builder
	fmt.Fprintf(&b, "retention sweep incomplete: %d resource(s) not disposed (retryable):", len(fails))
	for _, f := range fails {
		fmt.Fprintf(&b, "\n  - %s", f.Error())
	}
	return b.String()
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
