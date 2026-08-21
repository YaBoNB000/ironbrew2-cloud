# 基于 Luraph v15 复核的 IronBrew2 VM 加强计划（重审后最终版）

日期：2026-08-21

## 0. 范围、证据和边界

本计划依据以下仓库材料：

- `luraph15.txt`：Luraph Obfuscator v15.0 样本，171,753 bytes，SHA-256 `3d528decf216d85566b637a24cf990d11f8f795e0b689431a8c6373786073e1a`；
- `docs/luraph-v15-static-analysis.md`：对该样本的离线词法、根表、dispatcher 和 replay 复核；
- `docs/static-attack-baseline.md`、`tests/static_attack_baseline.py`、`tests/static_decompiler.py`：当前 IronBrew2 最终文件攻击器和已确认弱点；
- 当前 VM 的 authenticated payload、prototype/block ABI、Flow state、materializer replay、CALL trampoline、两阶段 call-inclusive fusion、constant capsules 和 20-build 随机矩阵。

不把任何客户端机制描述为密码学不可逆。所有 VM、reader、token、验证和派生逻辑都随最终客户端交付；完整静态模拟和动态 hook 始终是边界。

## 1. Luraph v15 VM 的已确认结构

### 1.1 同一构建内存在四种执行模式

样本的四个 dispatcher 都位于数字字段 `[18]` 内，由模式状态 `S` 选择，而不是“每次构建只选一种 dispatcher 外形”：

| 模式状态 | selector | opcode column | 静态 slots |
|---:|---|---|---:|
| 251 | `O` | `J[Q]` | 39 |
| 99 | `q` | `J[Q]` | 78 |
| 8 | `q` | `y[Q]` | 99 |
| 140 | `q` | `R[Q]` | 95 |

总计 311 个静态 handler slots。selector 来源随模式改变，分析者不能恢复一张 opcode 表后直接覆盖完整 VM。

### 1.2 指令列是运行时可写状态

确认存在 21 个 `Q -= 1` replay 点。相关 handler 会从 stateful reader 获取新字段，改写 opcode/operand columns，回退同一 PC，再用新字段重跑。

因此有效分析状态不是 `PC`，而是近似：

```text
(mode, PC, opcode-column generation, operand columns, reader state)
```

一次性 dump 初始列不等于稳定 IR。

### 1.3 helper 使用 continuation-return ABI

大型根对象包含 145 个 function 字段；127 个函数至少有一个以数字状态开头的 return。helper 往往返回下一状态及更新后的状态 tuple，而不是按“读取函数、运算函数、写回函数”直接调用后结束。

这会迫使静态工具联合恢复：

- helper role；
- 返回状态；
- tuple 各槽意义；
- 调用者 continuation；
- 模式切换。

### 1.4 helper、reader、环境引用混在异构稀疏 bank

根对象有 227 个字段，数字 bank 稀疏，数字键和命名 method 混用。它削弱了“局部 function declaration 就是独立语义 fragment”“数字表就是常量池”的简单分类器。

### 1.5 Luraph 仍有可利用稳定点

以下不是应复制的优点：

- 固定 `LPH:` magic 和固定字符替换 loader 很容易形成 fingerprint；
- 四棵连续整数判定树可通过区间传播完整枚举；
- terminal leaf 仍直接操作寄存器、PC、宿主库，分类仍可自动化；
- 大量 MBA 可先常量折叠；
- 当前样本不能证明存在强于 IronBrew2 的 authenticated tamper boundary；
- 巨型单 root table 本身只是工作量放大，不是安全边界。

## 2. 当前 IronBrew2 相对弱点

### 2.1 每个 build 主要仍是一套全局 handler 语义映射

当前有 prototype-local opcode bank、aliases、三种 continuation dispatcher 模板和 block-local ABI，但适配后的攻击器仍能：

1. 恢复一次全局 canonical handler map；
2. 对每个 prototype 恢复 local-to-canonical permutation；
3. 将所有物理记录重新映射到同一语义分类。

这比 Luraph 的“同一文件四种模式、不同 selector columns”更容易归一化。

### 2.2 replay 主要集中在固定 materializer 生命周期

当前四阶段 materializer replay 能延迟 operand proxy 和常量打开，但攻击器知道它属于取指前的固定生命周期。语义执行期间，当前 record 通常不再经历多代 opcode/operand 改写。

Luraph 的多个 replay 点分布在不同模式和 handler 中，静态工具必须把列作为长期可写状态。

### 2.3 fragment 角色仍能按函数体独立分类

当前 minified VM 虽然名称随机，但最终文件攻击器仍能通过函数体识别：

- stack reader / writer；
- environment reader；
- table writer；
- CALL trampoline；
- result forwarding；
- fused select/execute phases。

函数名随机化和 token 化没有消除“一个函数体对应一个较稳定角色”的事实。

### 2.4 selector 的语义来源仍较集中

continuation selector 最终仍以一个恢复后的 `Enum` 为核心。融合内部虽然有 select/execute token 和 operand slot shuffle，但适配工具可以跟随 token successor 并对齐物理 operand slot。

### 2.5 常量仍可被最终文件完整模拟

shards、cross-capsule chain、per-use handles 和 handler-use decode 提高成本，但最终工具仍可静态恢复完整字符串。当前没有服务端密钥，不能把这一点“修复”为真正保密；只能继续把常量恢复和 VM generation/mode state 耦合。

## 3. 值得吸收且不会倒退的 Luraph 思路

| Luraph 思路 | IronBrew2 采用方式 | 必须保留的现有优势 |
|---|---|---|
| 同文件多执行模式 | block/edge-local 3–5 dialect mode lattice | prototype/block authenticated ABI、Lua 5.1 语义 |
| 不同 selector columns | mode-dependent selector lane，lane 可在 replay 后迁移 | column framing、exact consumption、opcode state seal |
| 多点自修改/replay | invocation-local authenticated overlay generations | immutable payload、tamper rejection、reentrancy隔离 |
| continuation-return helper | capability graph 返回 next token + state delta | CALL B/C/Top、TAILCALL、RETURN 词法语义 |
| 异构 helper bank | 2–4 个 build-random capability compartments | 不引入固定巨型 root/magic |
| reader/state 联合 | constant fragment graph 绑定 mode/generation/transcript | per-use handles、capsule auth、使用后释放 |

## 4. 重审后的最终实施路线

### P0：攻击器和状态模型先行（批准，所有后续阶段的前置条件）

先扩展 `tests/static_decompiler.py` 的状态模型：

```text
(prototype, block, predecessor, mode, PC, generation, selector lane, column state)
```

要求攻击器能够表示但尚不必恢复不存在的 mode/generation。每个后续阶段必须先让攻击器适配公开 runtime，再衡量额外恢复步骤；禁止以旧 parser 报错作为成功指标。

验收：

- 当前 final-output baseline、loader chain、fused operand slot 恢复不退化；
- report 新增 mode/generation/replay/selector-lane 统计；
- `UNKNOWN` 不得被猜成已恢复语义；
- 保留用户上传样本的完整恢复基线。

#### P0 完成记录与重读审查（2026-08-21）

状态：**已完成**。

已加入 `AttackExecutionState`，当前每个恢复状态明确携带：

```text
prototype / block_start / predecessors / mode / physical_pc /
generation / replay_depth / selector_lane / column_state
```

`DecompilerReport` 现输出 state-model version、execution-state 数、predecessor edges、dialect modes、mode transitions、generations、max generation、replay transitions、selector lanes 和显式 UNKNOWN 数。新增 `tests/static_state_model.py` 同时验证当前生成样本与用户上传的 loader 样本；后者必须继续完整恢复 11/11 逻辑操作、四个 CALL、SELF、SETTABLE、discarded CALL 和真实 RETURN。

按本 MD 重新逐项检查后，P0 没有遗漏以下前置维度：prototype、block、predecessor、mode、PC、generation、selector lane、column state。当前 VM 尚未实现 P1/P2，因此 baseline 必须如实报告单 mode `[0]`、单 generation `[0]`、零 replay transition，而不是伪造动态性。P0 只扩展攻击与度量工具，没有改变 VM、认证边界、明文生命周期或 Lua 语义，不存在需要删除的倒退设计。

下一步仍是 P1；在 P1 完成前不得提前实施 P2/P4。

### P1：block/edge-local 多 dialect mode lattice（批准，最高优先级）

每个 build 生成 3–5 个同时存在的 VM dialect，而不是仅在 build 时选择一个 dispatcher 模板。

设计：

1. 每个 block manifest 带经过认证和包装的 entry mode；
2. 每条 CFG edge 同时包装目标 entry state 与目标 mode；
3. mode 决定 selector lane、opcode bank family、字段读取 ABI 和 continuation grammar；
4. 同一 canonical 语义在不同 mode 下映射到不同 microprogram recipe；
5. 模式迁移吸收 predecessor、source chunk state、instruction/opcode seal；
6. mode 只存于 invocation-local `Flow/FlowCache`，不写入共享 prototype 明文表；
7. RETURN/TAILCALL 继续直接终止当前 Wrap，不穿过会改变多返回值的通用包装器。

不采用四个固定模式数字，也不复制 Luraph 的连续 selector 范围。

验收：

- 每 build 至少 3 个 live modes，20-build aggregate 覆盖 3/4/5；
- 至少一个多前驱 fixture 从不同 predecessor 以不同 wrapped mode 进入同一目标 block；
- final-output attacker 必须恢复 mode 才能解释 selector；
- 删除/替换 mode transition、交换 edge mode 或用错误 mode 解码均触发现有 silent rejection；
- Lua 5.1 CALL/TAILCALL、closure、vararg、SETLIST C=0 全部保持。

#### P1 完成记录与重读审查（2026-08-21）

状态：**已完成**。

已实现：

1. 每个 build 生成 3–5 个独立随机 32-bit dialect mode tokens；
2. prototype 初始入口携带 wrapped initial mode；
3. 每条 successor record 携带绑定 source/target entry state、chunk state、from/to PC 和 prototype keys 的 wrapped edge mode；
4. 每个 target block manifest 保存并认证 `AcceptedModes`，运行时同时验证全局合法 token 和目标 block 接受集合；
5. mode 与 mode seal 只保存在 invocation-local FlowCache 派生槽，递归调用不共享；
6. dispatcher 执行前立即重验 mode seal，防止 GetInstruction 与 handler selector 之间被替换；
7. 每个 mode 使用独立 affine selector family、独立 continuation paths 和重新 lowering 的 handler recipe；
8. continuation loop 再按当前 mode 分区，不扫描或执行其他 mode 的 node family；
9. Chunk runtime ABI 从 16 槽扩展为 17 槽并继续执行 build-wide + prototype-local permutation；
10. 最终文件攻击器已适配 mode selector、edge mode、target manifest、mode-specific handler，并把 reachable modes 和 transitions 写入 execution-state report。

新增专项：

```text
tests/dialect_modes.lua
tests/dialect_modes.py
```

专项确认同一 target block 从两个 predecessor 接收不同 authenticated modes；模式数、used modes、path 数、handler recipe 差异和最终 attacker mode recovery 全部自动验证。tamper suite 新增：

```text
initial-dialect-mode
successor-dialect-mode
block-dialect-manifest
```

三种变体都在重算外层、prototype 和相应 block tag 后仍被运行时拒绝。

重读本 MD 后作出一项必要澄清：VM 始终生成 3–5 个完整且可执行的 mode families；拥有足够 block/edge entry sites 的 material fixture 与 20-build semantic matrix 必须实际使用至少 3 个。极小脚本若只有一至两个真实入口，不为凑计数注入伪 CFG block，因此 payload-reachable mode 数可以小于 3；生成日志分别报告 `modes` 和 `used`，攻击报告只计算真实 reachable modes。这避免违反 R5/R6/R8，也不降低 material P1 验收。

P1 未引入共享 mutable instruction array、固定四模式、连续 opcode 区间、巨型 root table或 Luau-only 语法；CALL/TAILCALL/Top、synthetic micro-block、10-member fusion、manifest authentication 和 reentrancy 生命周期均保留。wire 字段 generation 和 selector lane migration 没有提前混入，仍属于 P2/P3。

完整 `IB2_RANDOM_RUNS=20` 已通过；aggregate mode counts 覆盖 3/4/5，20 个 dialect programs 全部唯一。下一步是 P2，并在 P2 完成后再次完整重读本 MD。

### P2：invocation-local authenticated writable column generations（批准，第二优先级）

吸收 Luraph 的“可写 instruction columns + same-PC replay”，但不允许修改 authenticated payload 或共享 instruction table。

设计：

1. opaque record 认证后只创建 invocation-local generation-0 overlay；
2. 每个 mode 提供 2–4 种 rewrite family，可改写 selector lane、opcode、A/B/C、descriptor role 或 fused operand-slot view；
3. rewrite 完成后同 PC replay，generation 递增；
4. generation seal 吸收：前代 seal、mode、PC、rewrite token、全部改写字段、block entry/chunk state；
5. 每条 record 有 build-random 且有界的 generation program；不得使用固定“四次前置 replay”作为唯一形状；
6. semantic 与 synthetic rewrite 混合，但只有经过认证的 successor generation 能执行；
7. overlay 生命周期保持 invocation-local，离开 record/block 后释放；递归调用拥有独立 overlay；
8. 原始 payload 和 block manifest 继续 immutable，不能为了“自修改”削弱完整性检查。

验收：

- 选定 fixture 至少出现 3 种 rewrite family、2–5 generations；
- 初始列一次性 dump 无法直接得到最终执行 IR；
- attacker report 必须重放 generation chain 后才分类；
- 修改 rewrite token/字段、跳过一代、重复一代或跨 invocation 复用 overlay 全部拒绝；
- Phase 4 动态 observer 验证 overlay、常量和 record 均不逃逸生命周期。

#### P2 完成记录与重读审查（2026-08-21）

状态：**已完成**。

每个普通 physical instruction record 现在在 authenticated descriptor column 中携带 2–5 代 generation program。wire 中保存的是 generation-0 opcode/A，而不是 handler 最终消费值；四种可逆 rewrite families 分别改变 opcode、A、opcode+A 和交叉 mask 组合。每个 mode 都通过 mode-bound materializer selector 使用这些 families，family/mask/program framing 同时受 instruction digest、block manifest 和 prototype/outer layers 保护。

运行时只在当前 invocation 的 FlowCache 派生槽保存：

```text
generation program / stage / seal / guard /
opcode / A / B / C / lazy constant resolver / fused view
```

每代执行前验证上一代 guard，执行后把前代 seal、mode、PC、generation index、family、mask、改写后的全部字段、entry/chunk state 吸收到新 seal，并 same-PC replay。最终一代完成后才绑定 lazy constant proxy 和进入真实 handler，随后清除 generation program/seal/guard。Closure inline binding 等非顶层 fetch 在 invocation 内同步重放完整 program，不暴露 generation-0 字段给 closure ABI。

P2 二次审查又补强了 overlay commitment：初始化时对 generation count、每代顺序、family、mask、mode、PC、entry/chunk state 计算独立 program seal；每次 replay 前重新计算并与 FlowCache 中的 commitment 比较。field digest 不再只吸收 opcode/A，还覆盖 B/C、完整 fused supplemental A/B/C view、fused count 和 fresh-table flag。program seal 同时进入 begin/advance/guard 链，最终与其余 generation overlay 一起释放。这样在 commitment 建立后修改 mask 或交换 generation 顺序，不能再形成自洽 overlay。

攻击器已同步解析 generation framing、重放四种 rewrite、恢复最终 opcode/A，并将每代 column-state fingerprint 写入 `AttackExecutionState.generation_trace`。当前 material fixture 报告 generation range `[0..5]`，不再把 parser stale 当收益。

新增或升级验证：

```text
tests/materializer_replay.py
tests/generation_replay_tamper.py
tests/static_state_model.py
generation-program payload tamper
```

覆盖随机 2–5 generations、四 families、generation-0 wire fields、same-PC replay、mode/state-bound seal、跳过一代、重复一代、commitment 后改写 mask、交换 generation 顺序以及 payload generation-program 重封装。Phase 4 与递归语义测试确认 overlay 仍为 invocation-local，没有共享 mutable instruction array 或扩大 plaintext lifetime。

重读本 MD 后确认：P2 没有弱化 block/prototype/capsule authentication，没有把 payload 改成共享可写状态，没有恢复固定四阶段 replay，也没有提前实施 selector lane migration或 capability graph。为避免 Lua 5.1 signed/AsBx、RK handle 和 NaN 精度倒退，本阶段只改写共同安全的 16-bit opcode/A carrier；B/C、descriptor-role 与 fused-view rewrite 保留为后续可选 family，只有建立对应宽度/类型证明后才能加入。四种 family 都进入真实 generation seal/data dependency，不是纯 MBA decoy。

P2 收尾稳定性复核还定位并删除了一条会破坏上述 immutable payload 边界的既有全局重写：payload carrier 注入后，最终 `OP_A/OP_B/OP_C/OP_ENUM` lowering 曾对整份 Lua source 执行字符串替换；随机 Base91 carrier 一旦自然包含同名字节序列，payload 会在 outer tag 检查前被改坏。现统一使用只改写 Lua executable spans 的词法扫描器，单/双引号、转义字符串、long string、行注释和 long comment 均原样保留，并加入确定性 collision 回归。该修复只消除生成器自损坏路径，不把随机 build failure 当防护收益，也没有增加新 magic、共享状态或 plaintext lifetime。

完整 `IB2_RANDOM_RUNS=20` 已通过；20 个 generation programs 全部唯一，所有 build 覆盖 2–5 generations 和 families 0/1/2/3。下一步是 P3；完成后再次重读本 MD。

### P3：mode-dependent selector lane migration（批准，与 P2 同一里程碑交付）

不再保证一个稳定 `Enum` 字段贯穿 record 生命周期。

设计：

- generation-0 selector 可来自 opcode lane；
- rewrite 后可迁移到 descriptor-derived lane、supplemental lane 或 mode-local synthetic lane；
- selector 使用前必须通过 generation seal；
- handler recipe token与 selector lane 分离，避免“恢复 selector 即恢复语义”；
- 各 mode selector tree/graph 使用不同比较和 continuation 组织，但共用认证状态协议。

验收：

- 每 build 至少三个 selector lane families；
- 同一 physical record 在不同 generation 使用不同 selector lane；
- attacker 不能只解析一棵 selector tree；
- 不得把常量值当 selector，避免 Lua number 精度和 NaN 语义风险。

#### P3 完成记录与重读审查（2026-08-21）

状态：**已完成**。

每条 authenticated generation record 现同时携带 `family / mask / logical selector lane / independent recipe token`。generation-0 固定从 opcode carrier 开始；每个 build 随机排列 1–3 的 logical lane program，每次 rewrite 后必须迁移到不同的非零 logical lane，当前 dialect mode 再对 1–3 做置换，因此同一 physical record 在不同 mode 下也不共享固定物理 lane。三种 post-rewrite carrier 分别吸收完整 descriptor/field digest、B/C 与 fused/fresh supplemental view、以及 mode + entry/chunk state；selector 不读取 constant value。

selector value、有效 lane、recipe、completed generation、final 标志和 seal 只存在于 invocation-local FlowCache 派生槽。`ResolveDialectMode` 在 dialect selector tree 使用 `Enum` 前同时复核：mode seal、generation program commitment、当前 generation guard、lane/recipe 与 program 的对应关系、mode-dependent lane permutation、carrier source、selector seal 和解码结果。最终 selector 通过后立即释放 generation/selector overlay；中间 materializer selector 只释放本代 selector proof，随后 same-PC replay。这样没有为 P3 新增另一个顶层 validator local，避免 Lua 5.1 的 200-local 上限倒退。

最终 semantic selector 不再走稳定的 `Enum == nil → opcode bank` fallback。Closure inline binding 也消费同步重放后返回的 migrated selector，而不是重新从 opcode field 推导。handler continuation entry token 仍由 mode-specific continuation graph 独立生成；generation recipe 只参与 selector carrier 和 synthetic materializer recipe，恢复 lane 不等于恢复 terminal handler recipe。

攻击器状态模型升级为 v2，`AttackExecutionState` 新增逐代 `selector_lane_trace`，report 新增 `selector_lane_transitions`。适配攻击器会先重放 generation，再按 mode 恢复 effective lane，当前 material fixture 明确恢复：

```text
opcode-carrier / descriptor-digest / supplemental-operands / mode-synthetic
```

新增 `tests/selector_lane_migration.py`，并把 post-commit lane/recipe mutation 加入 runtime tamper suite。skip、duplicate、mask、reorder、lane 和 recipe 六种变体均在 protected semantics 前拒绝。Phase 4 observer 继续确认 raw fields、lazy constant proxy、selector proof 和 generation overlay 不逃逸 invocation/record 生命周期。

按本 MD 重新执行删除审查后确认：P3 没有引入常量 selector、共享 `Enum` cache、固定 mode 数、共享 mutable instruction array、额外巨型 root table或 P4 capability graph；也没有扩大 fusion 宽度。为保持 P2 的 signed/RK/NaN 边界，B/C 仍只作为 selector carrier 的已认证输入，不被 generation rewrite 改写。所有新增算术都进入 lane source、seal 或实际 dispatch 数据依赖，不是纯 MBA decoy。

完整 `IB2_RANDOM_RUNS=20` 已通过；每个 build 都覆盖 lanes 0/1/2/3，20 个 selector-lane recipe programs 全部唯一，dialect counts 继续覆盖 3/4/5。下一步是 P4；完成后再次完整重读本 MD。

### P4：continuation-return capability graph（批准，但在 P1–P3 稳定后实施）

将当前容易单函数分类的 shared fragments 改成 2–4 个 build-random capability compartments。

设计：

1. stack/env/member/table/call fragments 不再全部以独立 `local function Role(...)` 形式出现；
2. capability slot 混合 closure、token route、reader 和 commit leaf；
3. capability 返回 `(next token, state-delta token, value/count)`，由 mode scheduler 应用；
4. acquire、transform、validate、invoke、forward、commit 分布到不同 compartments；
5. 同一 capability slot 在不同 mode 下承担不同但类型兼容的角色；
6. 保留少量 decoy slots，但 decoy 不得访问宿主环境、分配无界内存或改变 payload 语义；
7. CALL validator 捕获的同一 callee 必须一直传递到 invoke，不能重新读取以引入 TOCTOU；
8. TAILCALL/RETURN 使用专用 terminal capability，确保 Lua 5.1 尾调用和多返回值不被 table capture 破坏。

验收：

- final attacker 不能仅按一个函数体把 role 一对一分类，必须恢复 capability slot + caller mode；
- helper graph 至少出现 many-to-many role/slot 关系；
- loadstring hook rejection、SELF、NEWTABLE/SETTABLE、CALL 全模式专项测试保持；
- 不采用一个固定 200+ 字段巨型 root object。

### P5：mode/generation-bound constant fragment graph（有条件批准）

只有在 P1–P4 完成后，攻击报告仍显示常量恢复是调用链恢复的主导捷径时才实施。

设计候选：

- 每个 string use 由多个独立 authenticated fragment capsules 组成；
- fragment successor 由 mode/generation microprogram 决定，不在一个 capsule 内直接保存完整 shard order；
- 后续 fragment state 吸收前序 ciphertext、generation seal、selector lane 和 use handle；
- plaintext 只在真实 handler/host-call use point 组装，使用后立即释放；
- 重复逻辑字符串继续使用独立 graph/handles。

验收：

- 单 capsule、无 mode/generation transcript 时不能独立重组字符串；
- attacker 适配后仍可恢复，报告必须显示 fragment graph traversal；
- 不能通过把完整字符串换成一组明文数字常量来伪装成功；
- 不引入共享 plaintext string cache。

### P6：predecessor-sensitive block dialect（条件批准，不复制完整 block）

当前目标 block 的 entry state 会被不同 edge 包装，但最终恢复到同一状态。候选改为不同 predecessor 恢复不同 mode/generation entry，并在 block 内通过认证 state merge 保持同一语义。

只允许复制小型 mode metadata/recipe，不复制整段 Lua 指令或常量图。完整 block cloning 会显著增加稳定重复结构，反而帮助语义聚类，因此不批准。

## 5. 已删除或明确拒绝的计划

以下方案在重审后被移出实施路线，因为会让现有系统倒退或只造成表面复杂度。

### R1：复制 `LPH:`、固定 alphabet 或固定 loader AST（拒绝）

固定 magic 是稳定 fingerprint。IronBrew2 现有随机 carrier/envelope 更强，不回退。

### R2：复制一个固定巨型 `setmetatable({...},{})` 根对象（拒绝）

它会产生新的稳定根边界和批量字段分类目标。只采用多 compartment、build-random capability topology。

### R3：改成四个固定 dispatcher 和连续 opcode 区间（拒绝）

Luraph 的 39/78/99/95 槽可静态枚举。采用每 build 3–5 modes、稀疏 token recipe 和非连续 selector grammar。

### R4：为自修改取消 block/prototype/capsule 认证（拒绝）

这是明确倒退。所有修改只能发生在 invocation-local overlay，并由 generation seal 认证。

### R5：使用共享全局可写指令数组（拒绝）

会破坏递归/reentrancy 隔离，给动态 dumper 一个稳定全量 IR。overlay 必须 invocation-local、单 record/block 生命周期。

### R6：只堆叠 MBA、垃圾分支和算术噪声（拒绝）

Luraph 样本的大量 32-bit MBA 可被常量折叠。只有进入 mode/generation/reader 真实数据依赖的运算才允许加入。

### R7：将全部 handler 放进一个普通 Lua function table（拒绝）

这会让攻击器直接枚举、调用和 fingerprint 每个 handler。capability graph 必须是 fragment 级 many-to-many，而非 opcode→function map。

### R8：继续无限提高 fusion 宽度（拒绝）

当前 10-member call-inclusive fusion 已覆盖高价值 loader chain。继续扩大将吞掉 synthetic micro-block/route 边界、放大 reentrant observer 复杂度，并减少动态 CFI 检查点。宽度冻结为 10，后续收益由 mode/generation 提供。

### R9：切换为 Luau-only conditional expression、`+=`、`continue`（拒绝）

当前必须保持 Lua 5.1 和 Luau 双解析。只吸收架构，不复制语法。

### R10：恢复破坏性全局 hook、后台扫描、时间炸弹或无界 sink（拒绝）

保留现有 O(1) silent sink 和明确的 `print/error/warn` 全局策略，不扩大副作用。

### R11：以体积或速度为目标调整安全结构（拒绝）

体积/性能优化不在目标内。仅保留 timeout、语义和生命周期观测，不设置性能硬门槛。

### R12：宣称客户端字符串不可恢复（拒绝）

无服务端密钥时不成立。计划目标是提高完整模拟和批量恢复成本。

## 6. 实施顺序和依赖

```text
P0 attacker state model
  └─ P1 multi-dialect mode lattice
       └─ P2 authenticated writable generations
            ├─ P3 selector lane migration
            └─ P4 capability graph
                 └─ P5 constant fragment graph（条件）
       └─ P6 predecessor-sensitive dialect（条件，可与 P4 后并行评估）
```

不得同时首次引入 P1、P2、P4。每次只引入一个新的状态维度，避免语义错误无法归因。

## 7. 每阶段重审流程

### 7.1 设计前审查

每个 phase 必须回答：

1. 它迫使适配攻击器新增什么真实状态？
2. 它是否只改变名字、常量拼写或旧 regex？
3. 认证边界是否保持或增强？
4. 是否引入共享 plaintext/IR？
5. CALL B/C、Top、多返回值、TAILCALL、vararg、closure/upvalue 如何保持？
6. reentrant VM 调用是否拥有独立状态？
7. 失败是否继续 silent reject，而非泄漏稳定诊断？

任何一项没有明确答案则不进入编码。

### 7.2 攻击器同步审查

- 先保存旧攻击报告；
- 更新最终文件攻击器以适配新公开 runtime；
- 对同一 fixture 比较恢复阶段、状态空间和分类步骤；
- 旧 parser 失败但新 parser 立即一行修复，不计为收益；
- 只有必须联合恢复 mode/generation/selector/rewrite/capability graph 才计入结构性收益。

### 7.3 语义与安全审查

每次核心 C# 修改后必须运行：

```bash
bash obfuscate.bat test.lua
luac5.1 -p test_obf.lua
luau-compile --only-parse test_obf.lua
lua5.1 test.lua
lua5.1 tests/executor_runner.lua trusted test_obf.lua
python3 tests/verify_v4_payload.py test_obf.lua
```

并增加对应专项测试，最后运行：

```bash
IB2_RANDOM_RUNS=20 bash tests/run_linux_tests.sh
```

必须保留：

- 原始/混淆语义一致；
- Lua 5.1/Luau 双语法；
- tamper rejection；
- loadstring 动态校验；
- global `print/error/warn` policy；
- synthetic micro-block 与 call-inclusive fusion 同时存在；
- Phase 4 invocation-local 生命周期；
- 20-build graph/layout/domain/token 唯一性。

### 7.4 回退条件

出现以下任一情况，phase 直接回退而不是降低测试要求：

- 需要取消或弱化 authenticated manifest/tag；
- 需要共享全局 mutable instruction/constant state；
- Lua 5.1 CALL/TAILCALL/Top/vararg 任一差分失败；
- recursive/reentrant invocation 状态串扰；
- 真正 RETURN 被变成 result capture；
- dynamic observer 发现 plaintext instruction/constant 生命周期扩大；
- synthetic micro-block 被普通 fusion 吞掉；
- 最终 attacker 只因 parser stale 而失败；
- 产生稳定 mode 数、magic、root table 或 rewrite opcode fingerprint；
- 真实 executor 兼容性只能通过放宽 hard-AND gate 获得；
- 需要新增破坏性宿主副作用。

### 7.5 阶段完成后的反向重审

每个 phase 合并前进行一次“删除审查”：

- 删除没有进入真实 data/state dependency 的 decoy/MBA；
- 删除与现有 continuation/materializer 重复但没有新增状态的层；
- 删除固定模式编号、固定 selector lane 和固定 rewrite 次数；
- 删除任何扩大 plaintext lifetime 的缓存；
- 删除只提升文件体积、未提升适配攻击成本的模板；
- 保留最小、可验证、可攻击器复现的状态协议。

## 8. 最终优先级结论

最终保留的前三项工作：

1. **P1：同一构建内 block/edge-local 多 dialect modes**；
2. **P2 + P3：invocation-local authenticated writable generations 和 selector lane migration**；
3. **P4：continuation-return capability graph，消除 fragment role 的一函数一语义分类捷径**。

P5 常量 fragment graph 和 P6 predecessor-sensitive dialect 只在前三项完成、攻击报告证明仍有明确收益时实施。

这比继续增加外层加密、固定 dispatcher 数量、巨型 root table或 MBA 更符合当前弱点，也不会牺牲 IronBrew2 已有的完整性、CFG、调用语义和生命周期防线。
