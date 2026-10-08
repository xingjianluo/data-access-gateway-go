# 本地数据访问网关与策略执行（Go）

用本地内存存储模拟受管数据，实现一套可预期、可追溯的数据访问网关：

- 基于 **主体 / 资源 / 动作 / 环境属性** 的访问决策：放行、拒绝、字段级脱敏，各有稳定可区分的判定原因；
- **策略热更新**与高并发访问：单个请求在其生命周期内固定使用同一版本策略；
- **策略变更追溯**：每次发布/切换（何时、从哪版到哪版、规则摘要）写入哈希链审计，不可篡改、可按版本/按访问请求回溯；
- **哈希链审计日志**：追加不可变，支持完整性校验，高并发下不丢失 / 不重复 / 不错配；
- **策略化保留期处置**：到期后"整条清除还是匿名化哪些字段"由策略按资源/资源类型声明；单轮扫描各资源处置互不影响，个别失败只计入失败集合，其余照常处置留痕；部分失败即报错可重跑，修复后重跑收敛且审计不重复；
- **数据主体请求（DSR）**：导出 / 删除覆盖全部存储副本；失败可重试；并发下同标识请求 single-flight，只有一个真正执行，其余显式重放。

## 目录结构

```
internal/
  policy/   策略模型、版本化快照存储、判定引擎（deny 优先）、保留期规则解析、发布追溯
  data/     内存多副本存储（写入预检、保留期元数据、故障注入）
  mask/     字段脱敏（redact / partial / hash）
  audit/    追加式哈希链审计日志（SHA-256）
  gateway/  编排：取快照 -> 判定 -> 取数/脱敏 -> 写审计
  dsr/      数据主体导出/删除、single-flight 幂等状态、策略化保留期扫描
cmd/demo/   端到端可运行演示
```

## 策略模型

一条策略（`policy.Policy`）是一个**不可变版本**（`Version` 单调递增），由若干规则组成：

```go
Rule{
  ID:         "mask-pii",
  Effect:     "allow" | "deny" | "mask",
  Subjects:   []string{"user:*"},            // 精确匹配或以 * 结尾的通配
  Actions:    []string{"read"|"export"|"delete"},
  Resources:  []string{"users/*"},
  Conditions: []Condition{{Key: "env.mfa", Op: "eq", Val: true}},
  Mask:       []MaskRule{{Field: "email", Method: "partial", Keep: 1}},
  Priority:   20,
}
```

- 条件运算符：`eq` / `ne` / `in` / `notin` / `exists`。
- 属性键前缀定位属性集：`subject.` / `resource.` / `env.`；不带前缀依次在主体、资源、环境中查找。
- **属性缺失时条件失败（安全失败 fail-closed）**，绝不会因属性缺失而放行明文。

### 冲突解决（稳定且可区分）

引擎对规则按 `Priority` 降序、`ID` 升序做稳定排序后逐条评估，最终决策：

1. 任意规则命中 `deny` → **拒绝**（拒绝永远优先于放行与脱敏，即便优先级更低）；
2. 否则存在 `mask` 命中 → 脱敏放行，合并所有命中规则的字段（同字段以高优先级规则为准）；
3. 否则存在 `allow` 命中 → 明文放行；
4. 都不满足 → **默认拒绝**。

每条规则是否命中、未命中原因（作用域不匹配 / 哪个条件失败）都会进入 `DecisionResult.Hits` 与审计记录，
最终 `Reason` 形如：

- `denied by rule(s): deny-finance`
- `masked by rule(s): mask-pii; masked fields: email,ssn`
- `allowed by rule(s): open-read`
- `denied by default: no rule matched subject="x" action="read" resource="y"`

## 脱敏规则

| Method  | 行为 |
|---------|------|
| `redact` | 整体替换为 `***` |
| `partial` | 字符串保留首尾各 `Keep` 个字符，中间以 `*` 替代；过短则整体抹除 |
| `hash` | 值的字符串形式取 `SHA-256`，稳定不可逆 |

未知方法安全降级为 `redact`；脱敏返回数据副本，不改原始数据；规则中不存在的字段跳过。
拒绝路径在读数据之前短路，**任何情况下 deny 都不返回数据**。

## 策略热更新与请求一致性

- `policy.Store.Publish` 发布新版本（深拷贝保存、拒绝重复/回退版本）并原子切换当前指针；已发布版本永不被原地修改。
- `Gateway.Access` 在请求开始时取**一次**当前快照并构造 `policy.Engine`，整个请求（判定、取数、审计）复用该引擎。
  因此处理期间即使发生热更新，本次请求的决策与审计中的 `policy_version` 始终一致。
- 网关测试 `TestAccess_HotReloadRace_PinsOneVersionPerRequest` 在后台持续发布新版本（奇偶版本 allow/deny）
  的同时发起 300 个并发请求，并在 `-race` 下校验：返回决策、审计版本、数据有无严格一致，无错配。

## 策略变更追溯

- `policy.NewHistory(auditLog)` + `Store.AttachHistory(hist)` 后，每次 `Publish` 都会把一条
  **发布记录**（`policy.PublishRecord`：发布时间、从哪版到哪版、策略名、规则 ID 列表、规则内容 SHA-256 摘要、
  保留期规则数）作为普通条目追加到哈希链审计日志（`Action=policy.publish`，`RequestID=policy-publish:<版本>`）。
- 因为发布记录就在哈希链上，**现有 `Log.Verify()` 自动将其纳入完整性校验**：事后篡改发布记录同样会在对应 seq 检出。
- 回溯方式：
  - `hist.Lookup(version)`：查某版本是什么时候、从哪个版本、以什么规则内容装入的；
  - `hist.TraceByRequest(requestID)`：由一次访问的审计记录（含 `policy_version`）顺藤摸瓜定位该版本的发布记录。
- 发布记录写入失败时 `Publish` 整体报错，不会出现"策略上线了但无追溯记录"。

## 保留期策略模型

- 记录带 `RetainUntil *time.Time`；`nil` 表示长期保留。
- 到期判定为严格 `RetainUntil.Before(now)`：到期时刻本身尚未到期，晚 1 纳秒才到期（边界在测试中固定，
  新旧两种扫描口径一致）。
- **处置方式收进策略**：策略版本可携带 `Retention []RetentionRule`：

  ```go
  RetentionRule{
    ID:        "anon-users",
    Resources: []string{"users/*"},            // 与访问规则同一口径：精确或前缀 * 通配
    Action:    "delete" | "anonymize",
    Fields:    []string{"email", "ssn"},       // 仅 anonymize：匿名化哪些字段由策略决定
    Priority:  20,                             // 多规则命中时按优先级降序、ID 升序稳定裁决
  }
  ```

- `Processor.SweepWithPolicy(now, snap, fallbackAction, fallbackFields)`：
  - 每条到期资源独立用 `Policy.RetentionFor(resource)` 解析处置方式——**同一次扫描里不同资源
    可以一个整条清除、另一个只匿名化指定字段**；
  - **单轮扫描内各资源处置互不影响**：某条资源命中的规则内容有误（如未知 action）或它的存储
    副本当时不可用时，只把它计入失败集合，同轮其他资源仍继续处置（该删除的删除、该匿名化指定
    字段的匿名化）并各写一条不可变审计（记录所用策略版本与命中规则，或 `via fallback`）；
  - **部分失败即整轮报错、明确可重跑**：只要本轮有资源没处置完，就返回
    `*dsr.PartialSweepError{ Succeeded, Failures }`（错误文本含 `retryable`，每个失败资源
    点名原因；副本故障可解包到 `*data.ReplicaError` 定位到具体副本），调用方绝不能把这轮当成功；
    失败资源不写审计、不进处置台账，待副本恢复/规则修好后**用相同参数重跑**即可把残留补齐，
    直到全部到期资源处置干净、各副本无残留；
  - 已成功处置的资源由**处置台账**（资源+到期时刻）标记，且匿名化后清除保留期标记：
    无论重跑多少次都不会重复处置、不会重复写审计，最终每种处置恰好对应一条审计记录；
  - 存储层全副本预检保证单次处置不产生部分写入。
- **兼容范围**：未配置保留期策略的资源沿用旧行为——由调用方通过 `fallbackAction/fallbackFields`
  指定处置；旧的 `RetentionSweep(now, action, fields)` 接口原样保留。

## 数据主体请求（导出 / 删除）

- 存储默认 3 个副本。所有变更（Put/Delete/Anonymize）先做**全副本健康预检**：
  存在不健康副本时返回 `data.ReplicaError`（点名失败副本，明确可重试），不产生部分写入，绝不静默成功。
- **导出**：从每个副本分别读取，交叉比对资源集合与字段指纹完全一致才算覆盖全部副本；不一致即失败可重试。
- **删除**：逐资源删除全部副本，随后再次逐副本校验该主体记录已不存在。
- **并发幂等（single-flight）**：以请求 ID 仲裁执行权——同一 ID 被同时提交多次时，只有一个真正执行，
  其余在首个执行结束后以 `Idempotent=true` 重放**同一份结果**（显式可识别，而非静默成功），不重复执行、不重复写审计。
- **失败重试**：`failed` 状态允许凭同一 ID 重试；重试成功后审计中只有一份最终结果，不会出现重复的成功记录。
- 同一 ID 被用于不同类型或不同数据主体的请求时显式报错，防止标识串用。

## 审计完整性校验

审计为追加式哈希链：

```
Hash(entry_i) = SHA256( canonicalJSON(业务字段..., prev_hash) )
prev_hash     = Hash(entry_{i-1})        // 首条为空
```

- 追加在互斥区内完成，`seq` 从 1 连续分配；并发 2000 条的测试验证无丢失、无重复、链完整。
- `Log.Verify()` 从链首重算哈希并校验序号连续与 `prev_hash` 链接；任一条目被篡改（改结论、删条、断链）
  都会在该 `seq` 处检出。测试中对 seq=3 的判定字段做篡改即被定位。

## 本地验证

```bash
# 全量单测（含竞态检测）
go test ./... -race -v

# 仅跑竞态热更新测试
go test ./internal/gateway/ -race -run HotReload -v

# 保留期策略化处置（按资源区分处置 / 单轮部分失败互不影响 / 修复后重跑收敛 / 到期边界）
go test ./internal/dsr/ -race -run SweepWithPolicy -v

# 策略变更追溯（发布记录入链、篡改检出、按请求回溯）
go test ./internal/policy/ -run PublishHistory -v

# DSR 并发幂等（同标识并发提交、失败后并发重试）
go test ./internal/dsr/ -race -run "Concurrent|RequestIDConflict" -v

# 端到端演示：放行/拒绝/脱敏、热更新、变更追溯、导出/删除、策略化保留期、审计篡改检出
go run ./cmd/demo
```

单测日志会打印每个用例的**输入**与**判定依据**（哪些资源到期、各命中哪条规则或走兜底、
故障注入点）、每条资源的**处置结果**（成功/失败及点名原因）以及**逐副本残留核对**；
保留期用例还会打印单轮内部分失败时"其余资源照常处置留痕"的明细、修复（规则修正/副本恢复）
后重跑的补齐与收敛过程，以及每轮的审计条数（证明每种处置恰好一条记录、重跑不重复）；
变更追溯用例打印发布记录内容与篡改检出位置；DSR 并发用例打印每个 goroutine 的
`Idempotent` 标记、真正执行次数与最终审计条数。
