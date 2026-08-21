# IronBrew2 加固计划（参考 Luraph 的架构思路）

> 目标不是复制 Luraph 私有实现，而是吸收已观察到的架构特征：多层数据恢复、按原型变化、状态相关 opcode、常量延迟恢复、VM 多态和完整性耦合。
>
> 2026-08-21 对 Luraph v15 与当前最终文件攻击基线完成重新审查后的后续路线，见 [`docs/vm-hardening-plan-luraph-v15.md`](docs/vm-hardening-plan-luraph-v15.md)。该文档已删除会弱化认证、Lua 5.1 语义、micro-block、reentrancy 或只增加固定 fingerprint 的候选方案，应作为下一阶段实施依据。

## 2026-08-19 静态攻击路线（进行中）

- [x] M0：建立只接收最终 Lua 的攻击基线，恢复 carrier、binding keys、完整 body、prototype/block、常量 capsule 和 canonical opcode IDs；当前 `test.lua` 的 `"print"`/`"idk"` 可完整恢复。
- [x] M1：最终 token literal、集中式 equality 与长生命周期 `GuardAttestation` 已删除；行为 transcript 仅在局部作用域经 Build-local offset 形成一次性 compatibility value，立即扩展为 `GuardEvidenceA..D` 后清零。payload KDF 再结合 salt 将四字 evidence 折叠为独立 envelope seed、outer-integrity key 与 `GuardPayloadBinding`；chunk/instruction/opcode/flow state 只使用后者。全部逻辑仍在客户端，静态模拟器仍可重算 evidence。
- [x] M2（当前范围）：已完成递归增量 Base91 segment 消费、禁止大型 segment 直接拼接，并将 decoded ciphertext 改为 2 KiB chunks + chunk-aware byte accessor；page 消费后立即释放全部早期 ciphertext chunks 属于内存/性能优化，按当前要求不实施。
- [x] M3：已完成 4 套 prototype-key-derived instruction-column decoder family（XOR、reverse/add、nibble/XOR、reverse/rotate/add）；Chunk 与 Block 现在都是 prototype-local proxy，build-wide ABI 之下再叠加 K1/K2/K3、prototype length 或 block start/verifier 派生的独立 storage permutation。同一构建内父子 prototype 与不同 blocks 不再共享单一实际槽位布局。
- [x] M4：invocation-local overlay 已拆为独立 opcode/A/B/C、lazy constant metadata 与 fused operand 槽位；四阶段 synthetic materializer/四次 PC replay 后才建立 operand proxy，constant capsule 仅在实际 handler 字段读取时恢复，并用显式 decoded flag 正确缓存 nil。
- [x] M5：6 种 register write lowering、RawGet/RawSet stack/global access、共享 operand/operation/writeback/PC fragments 与 IR-native physical fusion 已完成；fusion 使用 combined descriptor 与跨成员 register proxy/dataflow，且不再逐成员调用 `GetInstruction`。
- [x] M6：constant capsule、完整 prototype-slice、block manifest 与 instruction record digest 已全部从 `hash*31+byte` 迁移为 keyed two-lane cross-coupled authenticator；各层分别绑定 prototype keys、entry/chunk state、PC/manifest metadata。wire tag 目前仍压缩为 32-bit，本阶段完成算法迁移，后续可独立扩展 tag 宽度。

攻击基线与阶段验收见 [`docs/static-attack-baseline.md`](docs/static-attack-baseline.md)。该测试当前预期攻击成功；后续每个 milestone 必须先更新攻击器以适应公开 runtime，再以恢复率下降作为验收，而不是把 parser 失效误报成防护成功。

## 基线问题

当前版本的主要薄弱点：

1. K1/K2 明文位于固定 9 字节头部，所有原型共用同一线性 opcode mask。
2. 解开外层 XOR + DEFLATE 后，字符串常量和原型结构直接可读。
3. 只有一套全局 opcode bank 和固定反序列化骨架。
4. `EnvironmentLock` 是运行 gate，不是秘密；attestation token 与派生逻辑随客户端代码交付。
5. 没有 payload 完整性检查；`VMIntegrityCheck.cs` 为空。
6. `ControlFlow=true` 对无 marker 的普通输入几乎没有通用 CFG 变换。
7. line-info 错误处理读取 `Chunk[7]`，实际行表位于 `Chunk[4]`。

## 分阶段路线

### Phase 1：低风险数据层加固（本轮实施）

- [x] K1/K2 从明文头部移入每个 prototype 的加密正文。
- [x] 每个 prototype 使用独立 K1/K2/K3。
- [x] opcode mask 从全局线性公式改为每原型、PC 相关的非线性 16 位公式。
- [x] A/B/C/Bx 操作数字段在序列化层分别加掩码。
- [x] 字符串常量增加第二层、按 prototype + 常量索引变化的字节流编码。
- [x] 常量 tag 在 Phase 1 先按 prototype 旋转；Phase 2 已升级为完整 permutation。
- [x] 增加绑定 seed 的 payload 完整性 tag，解密前验证。
- [x] 修复 line-info 的 `Chunk[7]` 索引错误。
- [x] 关键序列化密钥、盐和 shuffle 改用系统安全随机源。
- [x] 增加格式版本标记，未知版本立即拒绝。

验收（已完成）：

- [x] 同一源码连续构建的 prototype keys、tag、payload 与 VM 名称不同。
- [x] 头部不再出现可直接使用的 K1/K2。
- [x] 外层解密/解压后字符串常量仍有 prototype/索引相关的内层编码。
- [x] 修改加密 payload 字节会在反序列化前失败。
- [x] Lua 5.1 差分测试覆盖闭包、循环、vararg、多返回值、表和错误路径。
- [x] Linux 自动化脚本覆盖固定配置差分、随机构建、line info、有符号 bit、旧档位参数拒绝及篡改失败。

### Phase 2：原型与 VM 多态（已完成）

- [x] 每 prototype 独立字段布局，不再全局共享 `ChunkSteps`。
- [x] 每 prototype 独立常量类型映射，而不只是旋转。
- [x] 多 opcode bank：canonical VIndex 经每 prototype 的独立 permutation 映射为 local VIndex，dispatch 时才恢复。
- [x] handler 拆分、双 handler leaf 合并和等价模板；使用小型 Lua 词法扫描器识别安全 statement 边界，不依赖纯正则拼接。
- [x] 子 prototype 使用长度 framing 保留为 opaque slice，在 `OP_CLOSURE` 首次需要时才反序列化并缓存。
- [x] basic block 按需解码：按 CFG leader 分块，长直线块最多 24 条指令；块顺序随机，PC 进入时才认证并恢复整块。
- [x] v4 将常量值改为独立认证的 opaque capsule；prototype 启动反序列化不恢复常量。只有某个 block 的完整 manifest 认证通过后，才把该块引用的 capsule 恢复到本次 block decode 的局部缓存。
- [x] string capsule 改为 build/prototype-keyed 物理 shard：列式分配原字节、随机 shard order、每 shard 独立 rolling mask；outer unmask 后仍只有 inner ciphertext，并在 handler-use 时才重组。
- [x] block-local constant chain：后续 string shard state 吸收 ordered reference manifest 中全部前序 capsule ciphertext；单独提取 later capsule + constant index 已不能独立解码。
- [x] per-use constant handle：每个 constant operand occurrence 分配独立随机 uint16 handle 与 capsule；相同逻辑常量不再共享稳定 prototype index/identity。
- [x] SETTABLE key/value 分离 materialization：4 种 RK 组合映射到 build-random operation token；target/key/value 分别获取、key/value 顺序随机、最终统一 commit。
- [x] safe fresh-table write-order randomization：只对 NEWTABLE 后、同 target、不同 constant key、无 CFG back-reference 的连续 SETTABLE 组做物理 shuffle；其他写入保持原顺序。
- [x] table setter trampoline：shared commit 再经独立 4-token dialect 路由到 4 个一次赋值的等价 leaf shapes；write-mode token 与 setter token 分离。
- [x] fresh-table temporary decoy：安全 constructor-group SETTABLE 用 descriptor bit 标记；写入前以 table-object key 临时插入 decoy，真实 commit 后经同一 setter trampoline 删除，且禁止参与 IR fusion。
- [x] 主循环、closure upvalue 伪指令和可选 superoperator 的直接取指统一经过 `GetInstruction`；`SetList C==0` data word 仍按 Lua 5.1 skip 语义处理。

当前验收状态：字段 schema、常量 tag 和 opcode bank 均由各 prototype 的 K1/K2/K3 加独立 domain 派生，通用解析器不能只恢复一次全局 schema/opcode 表后解析所有 prototype。handler 会按安全顶层 statement 边界选择 raw、`do` scope、恒真 guard 或 prefix/suffix 嵌套模板；dispatch 的双 handler leaf 也会在 `>`、`==`、`~=` 和嵌套 guard 形式间变化。prototype、basic block 和 block-local constant capsule 三层延迟恢复均已启用；默认 AntiDump 模式下共享 instruction table 保持为空，明文常量与指令只存在于当前 invocation 的单块解码/执行窗口。

### Phase 3：真实 CFG 与执行状态耦合（核心状态协议已完成）

- [x] 在 serializer 侧建立稳定 basic-block leader 与有界分区，供按需解码使用。
- [x] 每 Build 随机选择 3–6 条 synthetic micro-block limit；无分支直线代码也拆为多个独立 route token / entry state / manifest blocks。
- [x] 在 IR 上补全显式 CFG edge / predecessor 模型，并实际用于 wire successor records 与状态变换。
- [x] 自动选择安全 prototype 做 route-state dispatcher flattening，不要求源码 marker；跨 basic-block 转移先变为随机状态 token，再由 invocation-local dispatcher 恢复目标入口。
- [x] descriptor、opcode 与 operand mask 绑定每个基本块的独立随机入口状态；opcode 只在带当前状态的 dispatch 中恢复。
- [x] 每条合法 edge 包装目标块状态；每次 closure invocation 使用独立 `Flow`，块内只允许顺序取指，跨块只允许已认证的目标块入口。
- [x] 正确建模循环、自环、多前驱、comparison/Test/TForLoop companion JMP、`FORPREP` 优化、`LOADBOOL` skip、`SETLIST C==0` data word、Closure 伪指令和终止路径。
- [x] 每个 opaque block 从 body 解码前以入口状态、块范围、prototype keys 和 body 内容做完整性认证；AntiDump 模式下重入会再次认证。
- [x] superoperator 在 IR instruction sequence 上规划并由 serializer 物理降为单一 record；supplemental member operands/constants 使用 combined descriptor，handler 不再拼接逐 PC 取指。
- [x] fused member operation token：每个融合成员分配全 Build 唯一 32-bit token，branch order shuffle，通过有界 token state machine 执行语义链，不再线性拼接 member handler。

当前验收：v4 指令不能只按 PC 独立解码；缺失 edge、被修改的初始/边状态、dispatcher state、错误目标入口、block body 或完整 block manifest 篡改都会以 `invalid protected payload` 拒绝。CFG 结构测试覆盖循环/自环、comparison companion、FORPREP/FORLOOP、skip-next、data word 和 24 条分页；运行测试覆盖无 marker 自动命中、单块及畸形 prototype 安全回退、递归 invocation、跨块 Closure 伪指令与合法多分支执行。自动 dispatcher flattening 与 IR-native superoperator 均已完成；随机矩阵会比较 physical/logical instruction 数并验证语义。

### Phase 3.25：认证且状态耦合的高熵 envelope（已完成）

- [x] 在真实 body 完成 DEFLATE 后、外层 streaming XOR 前加入 feature bit 3 的 entropy envelope；该 envelope 现由 v4 格式承载，固定配置 feature 值为 `15`。
- [x] 每次输出使用操作系统 CSPRNG 生成独立的 64–96 KiB entropy，并随机切分为 12–20 个 records；真实压缩流切分为 4–8 个 data records，两类 record 强制交错后再随机物理排序。
- [x] entropy digest 绑定 seed、nonce、总长度、logical ordinal、record 长度与每个 entropy byte，并参与真实 body 的内层流状态派生；随机区不是可删除的尾部 padding。
- [x] 独立 envelope tag 覆盖固定头、全部 record framing、物理顺序与 record bytes；VM 在 inflate 前严格验证版本/features、长度上限、record 数量、kind、ordinal 唯一性、总长度、终止位置、digest 和 tag。
- [x] envelope runtime 的新增局部标识符全部进入每次构建的 identifier map。
- [x] verifier 会完整恢复 envelope 和真实 DEFLATE body，检查熵值与跨次独立性；测试在重新计算外层 tag 后分别修改、删除和重排 entropy record，三种情况均被 VM 拒绝。

当前验收：每次生成的随机区严格位于 65,536–98,304 bytes，测试样本 Shannon entropy 不低于 7.95 bits/byte；record 删除、修改或重排不能作为无影响 padding 操作。该机制提高静态载荷分析和直接裁剪成本，但全部派生与验证代码仍交付客户端，不宣称服务端密码学信任根。

### Phase 3.4：v4 延迟常量、完整 manifest 与运行时 ABI 随机化（已完成）

- [x] 格式版本升至 v4；每个 prototype 写入覆盖其完整字节切片的独立 tag，VM 在解析 schema、block、常量或子 prototype framing 前先验证。
- [x] 每个常量写成绑定 prototype keys、常量索引、类型、长度和 encoded bytes 的独立 capsule；prototype 初始解析只保留不透明 capsule，不生成共享明文常量表。
- [x] 每个 block 的完整 manifest 绑定 block range、route token、有序常量引用及完整 capsule bytes、flow verifier、有序 successor/wrapped-state records、body 长度与 body bytes，并加入 prototype keys/state。
- [x] block body 与引用常量只在完整 manifest 通过后恢复；capsule 明文缓存是本次 `DecodeInstructionBlock` 调用的局部变量，不写回 prototype 或跨 invocation 共享。
- [x] 每次生成一次 build-wide permutation，覆盖 15 个 Chunk、9 个 Block、4 个 Flow 与 3 个 FlowCache 槽；四组都禁止 identity，constructor、alias、handler 和 helper 统一使用同一映射。
- [x] 静态 verifier 递归恢复 v4、完整验证 prototype/block/capsule；可在重算所有外层认证后生成 prototype tag、block manifest 或 capsule 内层篡改样本，运行时仍拒绝。
- [x] runtime layout 工具恢复四类排列，检查 CurrentBlock/NextBlock/SuccessorBlock aliases，并验证独立构建至少一类完整 ABI 发生变化。

当前验收：prototype/body framing、block metadata/body 和常量 capsule 都不能在仅重算外层 tag 后被无影响修改；被引用常量直到目标块实际进入才恢复。随机回归每次同时检查 Lua 语义和四组非 identity 运行时槽位布局。

### Phase 3.45：每 block columnar IR 与字段角色排列（已完成）

- [x] 将原 row-oriented instruction body 改为 descriptor、opcode、A、B、C 五个逻辑列；每列保留原有 8/16/32 bit 字段宽度并独立 length-frame。
- [x] 每个 block 由 entry state、prototype K1/K2/K3 与独立 domain 派生 physical-page → logical-role permutation，wire format 不明文保存角色表，并强制结果非 identity。
- [x] runtime 仅在完整 block manifest 认证后恢复五页角色，使用独立安全 cursor 和 descriptor/type 重建 canonical instruction；现有 opcode handler ABI 不变。
- [x] parser 严格拒绝 page 越界、重复/缺失角色、非法 descriptor、dummy descriptor 异常及任一列未精确耗尽；新增 helper/page/cursor 标识符全部进入 build-local 名称随机化。
- [x] 静态 verifier 递归验证所有 block 的排列、framing、descriptor 与精确列长度；重算所有认证后破坏 column framing 或 descriptor consumption 的样本仍由 VM 拒绝。

当前验收：同一 prototype 内各 block 按独立 entry state 派生列角色，稳定 row schema 解析器不再适用；运行语义仍由 canonical handler 执行。IR-native superoperator 已在后续 M5 完成；完整 block-local opcode dialect 与受限 self-modifying IR 不并入本阶段。

### Phase 3.5：strict executor-only 反调试与防 dump（已完成）

- [x] 将 brand-neutral executor attestation 直接嵌入生成 VM；`identifyexecutor()` 必须存在、可重复返回稳定非空身份，存在 `getexecutorname`/`executorname` 别名时必须一致，但不匹配任何品牌白名单。
- [x] 准入采用硬性 AND，不使用评分或 quorum：同时要求稳定 `getgenv()`、`checkcaller()`、Roblox `game`/`Instance`/`Vector3`/`task` 行为、`iscclosure`/`islclosure`、`newcclosure`、`loadstring`、debug constants/upvalues/proto/setupvalue 及其行为契约。
- [x] 捕获关键库表、原语、capability provider 和 debug inspector 身份；验证关键 primitive、动态 Lua closure、`newcclosure` 结果与 inspector 的 native/Lua provenance，并拒绝活动 debug hook 或中途替换。
- [x] primitive root/member 与 VM Env 读取采用 raw-first/indexed-fallback；支持 builtins 仅通过 thread environment `__index` 暴露的 executor，并禁止任何 `RawGet(nil, key)` 路径。
- [x] 所有 CALL/TAILCALL handler 在调用捕获的 `loadstring` 前执行即时身份、C/L provenance、动态编译/运行与 constants challenge；启动后替换环境 binding 会进入 silent sink。
- [x] 每次生成随机 constants/upvalue/proto/load/newcclosure challenge，按固定顺序合成 transcript；仅完整成功的 transcript 才恢复该构建的 attestation token。
- [x] `EnvironmentLock` 用 `Hash(salt|attestation token)` 派生 serializer seed；同一绑定还进入 initial flow key、edge transition key、flow verifier、完整 block manifest 和 initial route 解封，不再只是外层单点 `if bad then reject`。
- [x] guard 状态用 seal 约束 token 与内部状态，并以状态更新产生 interval+jitter 调度；避免固定周期和绝对时序阈值。
- [x] 强制检查位于 VM 启动、root prototype 反序列化后和首块进入前，dispatch 中继续周期复检；中途失败时先清理当前 invocation 可达的 root/body、stack/args/proto/instruction/FlowCache 引用，再进入 sticky sink。
- [x] 失败响应是无输出、无专用异常、non-yielding 的无限位混合状态图；图结构与常数每次构建变化，固定 O(1) 内存，不做联网/文件探测、后台扫描、递归崩溃或持续分配。成功路径按明确需求仅永久覆盖 print/error/warn 为同一 no-op。
- [x] 所有新增 guard 局部名纳入生成器随机化；默认 AntiDump 路径不把已执行块写入共享 instruction table，每个 invocation 只保留当前明文块缓存。
- [x] 唯一 CLI 配置与 `ObfuscationSettings` 默认值都启用 `AntiDump` 和 `EnvironmentLock`；普通 Lua、普通 Luau 与 Studio 不再执行真实载荷。
- [x] 正路径通过可信 executor contract shim 做语义差分；普通 Lua、缺失 debug、identity/classifier spoof 和 primitive/debug hook 等失败路径由外部 `timeout` 终止，并要求终止前 stdout/stderr 均为空。

### Phase 4：Luau、性能和发布体系

- [x] 文档明确当前源码前端为 Lua 5.1；Luau 原生前端仍是后续候选。
- [x] 当前范围明确不实施 Luau `buffer` 原地解码（性能/内存优化不要求）。
- [x] 当前范围明确不实施自适应压缩（体积/性能优化不要求）。
- [x] CLI、批处理和云端工作流统一为单一严格配置：ControlFlow/DEFLATE/AntiDump/EnvironmentLock/64–96 KiB authenticated entropy envelope 开启，AggressiveDefense 关闭。
- [x] 当前范围不设置性能/体积门槛；仅保留 timed semantic observation、超时保护与 Phase 4 生命周期观测。
- [x] 提供本地 Linux 语义差分、随机 seed 和篡改测试脚本。
- [x] 将 Linux Lua 5.1 完整回归接入 CI，并增加 Linux x64、Windows x64、macOS arm64 的 Release publish 构建矩阵。
- 不实施（当前明确不需要）：云端仅上传短期 Artifact、敏感源码/产物策略和额外二进制工具校验。

## 明确不优先做

- 继续叠加 BaseXX 编码；
- 大量 `n+0`、死代码和无意义表分配；
- 除明确要求的 `print` / `error` / `warn` no-op 外，默认开启其他会污染 `getgenv()` 的全局 API hook；
- 检测后递归崩溃、持续内存膨胀、yield/background sink；当前仅保留固定 O(1) 状态、占用当前线程的 non-yielding 位混合循环；
- 把离线客户端机制描述成“不可逆”或“绝对防 dump”。

这些手段主要增加体积、误判与固定签名，不能解决一次性静态恢复的问题。
