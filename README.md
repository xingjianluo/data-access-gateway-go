# 本地数据访问网关与策略执行（Go）

一个完全本地运行（内存存储、无外部依赖）的数据访问网关演示，覆盖：

- 基于 **主体 / 资源 / 动作 / 环境属性（ABAC）** 的访问决策：放行 `allow`、拒绝 `deny`、字段级脱敏 `mask`
- **拒绝优先**：冲突策略下 deny 永远压过 allow/mask；属性缺失按“不匹配”处理，缺省一律拒绝，绝不返回未授权明文
- **策略热更新**：单请求生命周期内绑定同一版本策略快照，热更新不会造成同一请求前后判定不一致
- **追加写哈希链审计**：防丢失、防重复、防错配，任何篡改都可被检出
- **保留期**与**数据主体请求（DSR：导出 / 删除）**：到期删除或匿名化，操作覆盖全部存储副本；失败可重试、重复请求幂等且不静默成功

## 目录结构

```
internal/
  policy/     策略模型 + 版本化、不可变快照的策略存储（热更新）
  eval/       判定引擎：属性匹配、优先级、deny 优先、稳定原因码
  store/      多副本本地存储：变更扇出到全部副本，支持故障注入
  audit/      追加写 SHA-256 哈希链审计日志与完整性校验
  gateway/    编排层：取快照 → 判定 → 取数 → 脱敏 → 审计（单请求单版本）
  retention/  保留期任务：到期 hard delete / 匿名化，逐条审计，失败可重试
  dsr/        数据主体请求：导出/删除覆盖全部副本，幂等键 RequestID
cmd/gateway/  端到端可运行演示
```

## 策略模型

一条策略 `Policy` 是带 `Version` 的不可变规则集合；版本一旦安装即冻结，热更新安装新版本而不是原地修改（`policy.Store`）。

规则 `Rule`：

| 字段 | 说明 |
|---|---|
| `ID` / `Name` | 稳定标识，审计与原因码直接引用 |
| `Effect` | `deny` / `allow` / `mask` |
| `Resource` + `Actions` | 规则适用的资源类型与动作（`read`/`export`/`delete`） |
| `When` | 属性匹配子句（AND 语义），键带命名空间前缀：`subject.*`、`resource.*`、`env.*` |
| `Fields` | 仅 `mask` 生效：字段名 + 脱敏算子 |
| `Priority` | 数值越大越优先；同优先级以规则在策略中的位置稳定破平 |

### 判定算法（`eval.Engine`）

1. 收集所有资源、动作、`When` 全部命中的规则；
2. **没有任何规则命中 → `deny / default_deny:no_matching_rule`**。属性缺失视为子句不成立，因此“缺少属性”永远不可能产生放行；
3. 命中集合中只要存在 deny 规则，**deny 无条件获胜**（即使 allow/mask 优先级更高），原因 `denied_by_rule=<id>`（多 deny 取最高优先级）；
4. 否则按 `Priority`（再按位置）选出胜出的 allow/mask：
   - allow → `allowed_by_rule=<id>`，返回明文；
   - mask → `masked_by_rule=<id>`，仅按规则列出的字段脱敏，其余字段原样返回。

原因码是稳定的机器可读字符串，三种结论可区分、可断言。网关层另有一道兜底：取出的记录若归属其他主体，返回 `default_deny:record_owner_mismatch`。

## 脱敏规则

| 算子 | 效果 |
|---|---|
| `redact` | 整体替换为 `[REDACTED]` |
| `hash` | `sha256:` + SHA-256 前 16 个十六进制字符（确定性，可做关联比对但不可逆） |
| `partial` | 保留首末字符，中间打码（如 `123-45-6789 → 1*********9`）；过短值整体打码 |

非标量值一律整体 redact，避免嵌套结构泄漏明文。**deny 结论在任何数据读取之前返回，响应中不含记录与明文。**

## 单请求单版本（热更新一致性）

- `gateway.Access` 入口处只调用一次 `Store.Current()` 捕获 `*Policy` 指针，整个请求（判定 + 审计）都用它；
- `Store.Update` 安装的是新拷贝，旧指针指向的旧版本内容不会改变。因此热更新只影响“之后进入”的请求，进行中的请求前后必然一致；
- 历史版本仍可通过 `Store.Get(version)` 取回，用于审计追溯。

## 存储副本与故障重试

`store.Store` 维护 `replica-0..replica-N`。所有变更（Put / 删除 / 匿名化 / 按主体清除）扇出到每个副本，并返回逐副本结果 `ReplicaResults`：

- 部分副本失败时返回错误 + 失败副本明细，**绝不静默成功**；故障恢复后以同一操作重试即可收敛（重写幂等）。
- 到期扫描对 **全部副本取并集**，保证“健康副本已删、故障副本仍有残留”的数据在重试时仍能被扫到，不会被永久遗留。
- `SetReplicaFault(name, err)` 用于在测试中注入磁盘/网络故障。

## 保留期规则

`policy.RetentionRule{Resource, TTLSeconds, OnExpiry, AnonymizeWith}`：

- `OnExpiry: "delete"` → 到期在所有副本硬删除；
- `OnExpiry: "anonymize"` → 到期把 `AnonymizeWith` 列出的字段在所有副本改写为固定标记 `[REDACTED-ANON]`，其余字段保留；
- 边界语义：`now >= ExpiresAt` 即到期（临界点到期）；
- 每条记录的处理结果（`deleted` / `anonymized` / `failed` + 原因）独立写审计；作业整体返回失败计数，可直接重跑，重跑幂等收敛。

## 数据主体请求（DSR）

`dsr.Processor.Submit(Request{RequestID, Type, SubjectID})`：

- `export`：从每个副本取该主体全部记录，并校验各副本 ID+版本集合一致（不一致报 `replicas_disagree`）；
- `delete`：在所有副本清除该主体数据，随后再读一次验证“零残留”，否则报失败；
- **幂等**：相同 `RequestID` 的完成态重放返回 `status=duplicate` 与原因 `duplicate_request:replayed_result_of_request=<id>`，并单独写一条 `duplicate` 审计，绝不伪装成一次新的成功；
- 失败态（如部分副本故障）保留为 `failed`，同 ID 再提交会重试，`Attempts` 递增；成功后再重放即为 duplicate。

## 审计与完整性校验

审计日志（`audit.Log`）只追加、不可修改/删除。每条事件包含：

`Seq, Time, Kind(access/policy_update/retention/dsr), SubjectID, Resource, Action, Decision, Reason, PolicyVer, Detail, RequestHash, PrevHash, Hash`

- `Hash = SHA256(规范化字段 + PrevHash)`，`PrevHash` 指向前一条事件的哈希，构成哈希链；首条前置哈希为 64 个 `0`；
- `Verify()` 重放全链：检查序号连续、前向指针、内容哈希；任何字段被篡改（含调换事件顺序）都会在**第一条被篡改的序号**处检出；
- `RequestHash` 把审计行绑定到具体请求输入（主体/资源/记录/动作/环境属性 + 策略版本）；
- 高并发下 `Seq` 在锁内分配，单测已验证 27 万+ 并发访问与批量 DSR 下无丢失、无重复序号、链完整（并通过 `-race`）。

## 本地验证

需要 Go 1.25+（仓库在 Go 1.26 下验证）。

```bash
# 构建
go build ./...

# 全部单元测试（日志会打印输入、命中的策略规则与判定依据）
go test -v -count=1 ./...

# 并发竞态检测
go test -race -count=1 ./...

# 端到端演示：决策 / 脱敏 / 热更新 / 保留期 / DSR / 审计校验
go run ./cmd/gateway
```

测试覆盖对应需求：

| 场景 | 测试 |
|---|---|
| 越权访问、冲突策略、deny 优先、属性缺失默认拒绝 | `internal/eval/engine_test.go` |
| deny 不触明文、脱敏字段、跨主体访问、热更新竞态（8 并发访问 × 持续热切换）、审计不丢不重不错配 | `internal/gateway/gateway_test.go` |
| 审计哈希链校验与篡改检出（篡改 seq=3 在 seq=3 被检出） | `internal/audit/audit_test.go` |
| 热更新快照隔离、非法/重复版本拒绝 | `internal/policy/store_test.go` |
| 保留期边界（临界到期/未到期）、匿名化/删除、部分副本失败重试 | `internal/retention/retention_test.go` |
| DSR 导出/删除全副本覆盖、幂等 duplicate、失败可重试、副本一致性 | `internal/dsr/dsr_test.go` |
| 多副本扇出、故障写入与恢复收敛 | `internal/store/store_test.go` |

所有测试的日志均打印 **输入属性、命中规则列表（`matched_rules`）、策略版本与原因码**，便于人工追溯判定依据。
