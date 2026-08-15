# IronBrew2 加固计划（参考 Luraph 的架构思路）

> 目标不是复制 Luraph 私有实现，而是吸收已观察到的架构特征：多层数据恢复、按原型变化、状态相关 opcode、常量延迟恢复、VM 多态和完整性耦合。

## 基线问题

当前版本的主要薄弱点：

1. K1/K2 明文位于固定 9 字节头部，所有原型共用同一线性 opcode mask。
2. 解开外层 XOR + DEFLATE 后，字符串常量和原型结构直接可读。
3. 只有一套全局 opcode bank 和固定反序列化骨架。
4. `EnvironmentLock` 是运行 gate，不是秘密；正确指纹随客户端代码交付。
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
- [x] 常量恢复缓存限定在单个 prototype 的反序列化过程；prototype 级表随后释放。默认 AntiDump 模式由各 opaque block 保留自己的最小引用集合，供重入时重新解码。
- [x] 主循环、closure upvalue 伪指令和可选 superoperator 的直接取指统一经过 `GetInstruction`；`SetList C==0` data word 仍按 Lua 5.1 skip 语义处理。

当前验收状态：字段 schema、常量 tag 和 opcode bank 均由各 prototype 的 K1/K2/K3 加独立 domain 派生，通用解析器不能只恢复一次全局 schema/opcode 表后解析所有 prototype。handler 会按安全顶层 statement 边界选择 raw、`do` scope、恒真 guard 或 prefix/suffix 嵌套模板；dispatch 的双 handler leaf 也会在 `>`、`==`、`~=` 和嵌套 guard 形式间变化。prototype 和 basic-block 两级延迟恢复均已启用；默认 AntiDump 模式下共享 `Chunk[1]` 保持为空，明文指令只存在于当前 invocation 的单块 `Flow` 缓存。

### Phase 3：真实 CFG 与执行状态耦合（核心状态协议已完成）

- [x] 在 serializer 侧建立稳定 basic-block leader 与有界分区，供按需解码使用。
- [x] 在 IR 上补全显式 CFG edge / predecessor 模型，并实际用于 wire successor records 与状态变换。
- [x] 自动选择安全 prototype 做 route-state dispatcher flattening，不要求源码 marker；跨 basic-block 转移先变为随机状态 token，再由 invocation-local dispatcher 恢复目标入口。
- [x] descriptor、opcode 与 operand mask 绑定每个基本块的独立随机入口状态；opcode 只在带当前状态的 dispatch 中恢复。
- [x] 每条合法 edge 包装目标块状态；每次 closure invocation 使用独立 `Flow`，块内只允许顺序取指，跨块只允许已认证的目标块入口。
- [x] 正确建模循环、自环、多前驱、comparison/Test/TForLoop companion JMP、`FORPREP` 优化、`LOADBOOL` skip、`SETLIST C==0` data word、Closure 伪指令和终止路径。
- [x] 每个 opaque block 从 body 解码前以入口状态、块范围、prototype keys 和 body 内容做完整性认证；AntiDump 模式下重入会再次认证。
- [ ] superoperator 基于 IR 生成并做语义验证，不用 handler 源码正则作为主实现。

当前验收：v3 指令不能只按 PC 独立解码；缺失 edge、被修改的初始/边状态、dispatcher state、错误目标入口和 block body 篡改都会以 `invalid protected payload` 拒绝。CFG 结构测试覆盖循环/自环、comparison companion、FORPREP/FORLOOP、skip-next、data word 和 24 条分页；运行测试覆盖无 marker 自动命中、单块及畸形 prototype 安全回退、递归 invocation、跨块 Closure 伪指令与合法多分支执行。自动 dispatcher flattening 已完成，IR-native superoperator 仍是后续独立项目。

### Phase 3.5：Luau 反调试与防 dump（已完成）

- [x] 移除旧前置 guard 的“必须存在执行器 API，否则明确报错”行为，将能力探针直接嵌入生成 VM。
- [x] 捕获关键原语、库表、`getgenv` capability provider 及 debug inspector 身份；宿主提供时使用 `debug.gethook`、`debug.getinfo`/`debug.info`、`iscclosure`、`islclosure` 检查活动 hook、Lua closure 替换和来源一致性。
- [x] 将快照身份、closure classifier 交叉验证、debug source provenance 与无副作用行为 canary 分层执行，并按权重聚合；不因 `getgc`、`hookfunction` 等 dump API 仅仅存在就拒绝正常执行。
- [x] guard 状态使用轻量 seal 检查自身一致性，并以状态更新产生 interval+jitter 调度；避免固定取模周期和绝对时间阈值。
- [x] 启动、root prototype 反序列化后和 dispatch 周期三阶段检查均与 VM invocation 相连；命中后 sticky 静默进入有限计算诱饵，不显示阻断错误。
- [x] 所有新增 guard 局部名纳入生成器随机化，避免新增稳定 `Guard*` 名称成为输出签名。
- [x] 默认 AntiDump 路径不再把已执行块写入共享 instruction table；每个 invocation 只缓存当前明文块，非顺序转移后替换，重入时重新认证/解码 opaque body。
- [x] 删除全局 API hook、registry 后台扫描、无限循环和大内存“自毁”；兼容字段 `AggressiveDefense` 不再注入这些行为。
- [x] 唯一固定 CLI 配置和 `ObfuscationSettings` 默认值均启用 AntiDump；严格 Roblox `EnvironmentLock` 仍保持独立 opt-in。
- [x] 自动测试覆盖无 capability 正常路径、模拟 Luau capability 正常路径、string/raw/debug 原语包装、活动 debug hook、矛盾 closure classifier、三阶段探针、名称随机化、静默诱饵、全局 API 不变和共享指令表为空。

### Phase 4：Luau、性能和发布体系

- [x] 文档明确当前源码前端为 Lua 5.1；Luau 原生前端仍是后续候选。
- [ ] Luau 专用构建使用 `buffer` 读取和原地解码。
- [ ] 自适应压缩：小 payload 不携带 inflater，大 payload 再用 DEFLATE。
- [x] CLI、批处理和云端工作流统一为单一稳定配置：ControlFlow/DEFLATE/AntiDump 开启，EnvironmentLock/AggressiveDefense 关闭。
- [ ] 为固定配置建立真实性能和体积基准。
- [x] 提供本地 Linux 语义差分、随机 seed 和篡改测试脚本。
- [x] 将 Linux Lua 5.1 完整回归接入 CI，并增加 Linux x64、Windows x64、macOS arm64 的 Release publish 构建矩阵。
- 不实施（当前明确不需要）：云端仅上传短期 Artifact、敏感源码/产物策略和额外二进制工具校验。

## 明确不优先做

- 继续叠加 BaseXX 编码；
- 大量 `n+0`、死代码和无意义表分配；
- 默认开启会污染 `getgenv()` 的全局 API hook；
- 检测后无限循环或内存膨胀；
- 把离线客户端机制描述成“不可逆”或“绝对防 dump”。

这些手段主要增加体积、误判与固定签名，不能解决一次性静态恢复的问题。
