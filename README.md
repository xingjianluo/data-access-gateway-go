# 本地数据访问网关与策略执行（Go）

用本地内存存储模拟受管数据，实现一套可预期、可追溯的数据访问网关：

- 基于 **主体 / 资源 / 动作 / 环境属性** 的访问决策：放行、拒绝、字段级脱敏，各有稳定可区分的判定原因；
- **策略热更新**与高并发访问：单个请求在其生命周期内固定使用同一版本策略；
- **策略变更追溯**：每次发布/切换留下不可篡改记录（进同一条审计哈希链），可按版本溯源安装时间与规则摘要；
- **哈希链审计日志**：追加不可变，支持完整性校验，高并发下不丢失 / 不重复 / 不错配；
- **策略驱动的数据保留期**：到期后整条清除还是匿名化（匿名化哪些字段）按资源/资源类型由策略声明；
  扫描覆盖全部副本，副本故障恢复后重跑收敛，已处置资源不重复处置；
- **数据主体请求（DSR）**：导出 / 删除覆盖全部存储副本；失败可重试；并发下同标识请求真正幂等且显式可识别。

## 目录结构

```
internal/
  policy/   策略模型（访问规则 + 保留期规则）、版本化快照存储、变更追溯、判定引擎（deny 优先）
  data/     内存多副本存储（写入预检、保留期元数据、故障注入）
  mask/     字段脱敏（redact / partial / hash）
  audit/    追加式哈希链审计日志（SHA-256）
  gateway/  编排：取快照 -> 判定 -> 取数/脱敏 -> 写审计；按请求溯源策略版本
  dsr/      数据主体导出/删除（并发幂等）、策略驱动的保留期扫描（故障收敛）
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

## 保留期策略（处置方式收敛在策略里）

到期之后"整条清除还是匿名化、匿名化哪些字段"由**策略**声明，而不是每次扫描时由调用方临时决定：

```go
Policy{
  Version: 2,
  Rules: []Rule{ ... },
  Retention: []RetentionRule{
    // 具体资源：users/1 到期整条清除
    {ID: "rt-users1-delete", Resources: []string{"users/1"}, Action: "delete", Priority: 20},
    // 资源类型：其余 users/* 到期只匿名化 email/ssn，记录保留
    {ID: "rt-users-anon", Resources: []string{"users/*"}, Action: "anonymize",
     AnonymizeFields: []string{"email", "ssn"}, Priority: 10},
  },
}
```

- `RetentionFor(resource)` 按资源模式（精确 / 前缀 `*` 通配）解析处置方式；多条命中时
  `Priority` 降序、`ID` 升序取第一条，结果稳定可复现。
- `Processor.RetentionSweepByPolicy(now, snapshot, fallbackAction, fallbackFields)`：
  同一次扫描里不同资源可走不同处置，互不影响；**未配保留期规则的资源走调用方兜底**（兼容旧行为），
  旧接口 `RetentionSweep(now, action, fields)` 等价于"无策略 + 全部走兜底"，继续可用。
- 记录带 `RetainUntil *time.Time`；`nil` 表示长期保留。
  到期判定为严格 `RetainUntil.Before(now)`：到期时刻本身尚未到期，晚 1 纳秒才到期（边界在测试中固定）。

### 扫描的收敛语义

- 处置覆盖**全部副本**（存储层预检，任一副本不可用则该资源本次处置整体失败，不产生部分写入），
  并**逐副本核验**（delete：各副本均无此资源；anonymize：各副本目标字段已匿名化且保留期标记已清）
  后才写审计、标记完成——绝不"报成功但其实没处置完"。
- 单个资源失败不阻塞其他资源；扫描返回聚合错误并点名未收敛的资源。
- 副本故障期间失败的资源被记为**待完成**，副本恢复后重跑会继续清理残留直至收敛。
- 已完成的资源再次扫描直接跳过：**不重复处置、不重复写审计**；
  同名资源若被重新写入并带**新的到期时刻**，则视为新一轮处置（测试覆盖）。
- 每条处置的审计 `reason` 里带决定本次处置的保留期规则 ID（`fallback` 表示走兜底），可回溯依据。

## 策略变更追溯

- `policy.Store.AttachAudit(log)` 挂接审计后，每次 `Publish` 先向同一条哈希链追加一条
  `policy.publish` 条目（含 from/to 版本、规则 ID 摘要、时间），**审计写失败则发布整体失败**，
  保证"每次发布/切换都有不可篡改记录"不被静默跳过；这些条目与访问审计一起被 `Log.Verify()` 覆盖。
- 内存中同时保留 `ChangeRecord` 历史：`Store.Changes()` 列出全部变更，
  `Store.ChangeForVersion(v)` 回答"v 是何时、从哪个版本、带着哪些规则装进来的"。
- `Gateway.TracePolicy(requestID)` 把两者串起来：由某次访问的审计条目取得 `policy_version`，
  再顺藤摸瓜找到该版本的安装/切换记录（时间、来源版本、规则摘要）。
- 测试 `TestPublish_RecordsChangeHistoryAndAudit` 验证：篡改策略变更条目会被完整性校验在对应 seq 检出。

## 数据主体请求（导出 / 删除）

- 存储默认 3 个副本。所有变更（Put/Delete/Anonymize）先做**全副本健康预检**：
  存在不健康副本时返回 `data.ReplicaError`（点名失败副本，明确可重试），不产生部分写入，绝不静默成功。
- **导出**：从每个副本分别读取，交叉比对资源集合与字段指纹完全一致才算覆盖全部副本；不一致即失败可重试。
- **删除**：目标集合取**全部副本的并集**（曾故障副本里的残留也会在重试时被清掉），逐资源删除全部副本，
  随后再次逐副本校验该主体记录已不存在。
- **幂等（含并发）**：每个请求 ID 有独立执行状态与互斥锁——同一标识被**并发**提交多次时，
  只有一个真正执行，其余阻塞到首次完成后按重放返回（`Idempotent=true`，显式可识别而非静默成功），
  结果与首次完全一致，不重复写审计；`failed` 的请求允许凭同一 ID 重试，
  重试只补写尚未写入的审计，最终只有一份成功记录（并发 16 路同 ID、故障后并发重试均有测试覆盖）。

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

# 保留期：策略驱动处置 / 副本故障恢复收敛 / 同名资源新一轮到期
go test ./internal/dsr/ -run 'RetentionSweep' -v

# DSR 并发幂等：同一请求标识并发提交、故障后并发重试
go test ./internal/dsr/ -race -run 'Concurrent|Distinct' -v

# 策略变更追溯：发布记录进哈希链、篡改检出、按版本溯源
go test ./internal/policy/ -run 'Retention|Publish' -v
go test ./internal/gateway/ -run 'TracePolicy' -v

# 端到端演示：放行/拒绝/脱敏、热更新、版本溯源、导出/删除、
# 策略驱动保留期扫描、副本故障恢复收敛、审计篡改检出
go run ./cmd/demo
```

单测日志会打印每个用例的**输入**、每条**命中的规则及命中/未命中依据**、最终**判定与原因**，
DSR 用例打印副本覆盖、幂等标记与重试结果，保留期用例打印每个资源的处置方式与依据规则、
故障/恢复各阶段的扫描结果，审计用例打印哈希链与篡改检出位置。
