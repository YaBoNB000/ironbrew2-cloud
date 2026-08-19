# IronBrew2 加固实施报告

> 更新（2026-08-19）：当前实现已升级到 v5 outer authenticator。下文的 v4
> 章节保留为该轮实施历史；v5 删除了可从 polynomial outer tag 逐字节逆推
> environment-derived stream seed 的 O(n) 反演关系；outer integrity key 也改为独立
> transcript 派生，不再复用 envelope stream seed，并新增静态回归测试。

日期：2026-08-15  
本轮 executor-only 扩展基线：`main` / `07cf9d3`（block-local columnar IR）

## 1. 实施原则

本轮没有复制或声称复刻 Luraph 的私有实现。实际采用的是可独立实现的通用架构思路：分层恢复、按 prototype 变化、位置相关的指令编码、常量二次编码、完整性耦合和 VM 生成多态。

底层语义与 Lua 5.1 bytecode 前端继续保持稳定；本轮运行时防护优先面向 Luau/Roblox。仓库中已知不稳定的 Mutation、SuperOperator、源码字符串解密闭包及会污染全局环境的激进 API hook 没有在固定配置中重新启用。

## 2. 已完成的源码改动

### 2.1 v4 payload 与分层完整性

`Serializer.cs` 与 `VMStrings.cs` 已同步切换到 v4 格式：

```text
4B head/salt | 4B outer integrity tag | 1B version+feature flags | encrypted entropy envelope
```

- 高 4 位为格式版本，目前必须为 `4`；v3/旧 Release 产物会被新版 VM 明确拒绝。
- 低位 bit 0 表示 DEFLATE，bit 1 表示 basic-block lazy decode，bit 2 表示 route-state dispatcher framing，新增 bit 3 表示 authenticated entropy envelope。固定配置四项全部开启，因此 feature 值为 `15`。
- 顶层完整性值绑定格式/feature 字节、整个加密 envelope 和运行 seed，并在外层解密前验证。
- 真实序列化 body 先按现有配置做 raw DEFLATE，再以由 entropy digest、nonce、seed、真实长度和独立 domain 派生的内层流状态逐字节掩码；恢复正文不再只依赖原有外层 XOR。
- 每次构建由操作系统 CSPRNG 独立生成 64–96 KiB entropy，随机切分为 12–20 个 records；掩码后的真实压缩流切成 4–8 个 data records。两类 record 使用各自 logical ordinal，物理顺序以 CSPRNG 打乱，并要求至少发生两次类型转换以保持交错。
- envelope 固定头记录真实/entropy 总长度、total/data/entropy record 数、nonce、entropy digest 和 envelope tag。每个 record 另有 kind、ordinal、长度 framing 和 bytes。
- entropy digest 绑定 seed、nonce、总长度、record 数、每个 logical ordinal/长度和全部 entropy bytes，并直接参与内层真实 body mask 的初始状态。即使某个 entropy record 位于最后，它仍会改变真实流恢复状态，因此随机区不是可裁掉的尾部 padding。
- 独立 envelope tag 绑定固定头（排除 tag 自身）、全部 record framing、record bytes 和物理顺序。VM 在 inflate 前还严格检查长度范围/终态、record 数、kind、ordinal 唯一性、logical 总长度和 digest。
- v4 为每个 prototype 写入覆盖完整 prototype slice 的独立 tag；VM 在解析 prototype-local schema、block、capsule 与 child framing 前先验证。
- 每个 block 的认证范围已从 body tag 扩展为完整 manifest：绑定块起点/长度、route token、有序常量引用及引用 capsule 的完整 bytes、flow verifier、有序 successor/wrapped-state records、body 长度/body bytes，以及 prototype keys/state。
- 修改加密 payload、删除/修改/重排 entropy record，或在重新计算外层 tag 后篡改 prototype、完整 block manifest、constant capsule、flow metadata 或 body，都会以 `invalid protected payload` 失败。
- K1/K2 不再位于固定明文头。

上述 envelope 在 basE91 前固定新增 65,536–98,304 bytes entropy，另有少量 framing；生成 Lua 的实际文本增量还包含 basE91 约 1.23 倍展开。这是当前唯一配置有意接受的保护/体积取舍。完整性机制用于检测损坏和提高直接 patch/裁剪成本；算法、seed（默认未锁环境时）和验证代码都交付给客户端，因此不是不可伪造的服务端信任根。

### 2.2 每 prototype 的指令、字段与 opcode bank

每个 prototype 在加密正文中携带独立、由操作系统 CSPRNG 生成的 K1/K2/K3。它们用于：

- 由 prototype keys 与 1-based PC 派生 opcode mask；
- 分别掩码 A、B、C、Bx/sBx；
- 区分 16 位与 32 位 operand mask；
- closure 后的伪指令用相同公式按其真实 PC 解码；
- 通过独立 domain 派生 5 项字段 schema，父子 prototype 不再共享全局 `ChunkSteps`；
- 通过另一 domain 派生 local-index → canonical-index opcode bank，serializer 写入其逆映射，VM 只在 dispatch 时恢复 canonical VIndex；
- VM 的 while、repeat、line-info 四种 wrapper 全部使用相同规则。

`OP_CLOSURE` 对附加伪指令的判断也先经过当前 prototype 的 opcode bank，避免继续拿 local VIndex 与全局 VIndex 直接比较。Lua 端保留无符号 32 位归一化，覆盖 LuaJIT 风格 `bit.bxor` 返回有符号整数的情况。

### 2.3 常量保护

- 移除了全局 `ConstantMapping`、简单 tag rotation 及 `CONST_*` 模板替换。
- Nil、Boolean、Number、String 四种 tag 由每个 prototype 的 K1/K2/K3 和独立 domain 做完整 Fisher–Yates permutation。
- v4 不在 prototype 解析时生成明文常量数组。每个值以绑定 prototype keys、1-based 常量索引、permuted type、encoded 长度与 encoded bytes 的独立认证 capsule 保存；字符串仍使用 prototype/索引相关的逐字节编码。
- 指令字段允许排在 capsule 字段之前：instruction framing 记录每块的有序常量索引，prototype-local schema 全部解析后再做完整 block manifest 交叉验证。
- `DecodeInstructionBlock` 先认证包括完整引用 capsule bytes 在内的 manifest，再在该次函数调用的局部 `ConstCache` 恢复被引用值并解析 A/B/C 常量引用。缓存不写回 Chunk/Block，也不跨 block 或 closure invocation 共享。
- 默认 AntiDump 模式保留 opaque capsule 和 opaque block body，重入时重新认证、重新恢复。未进入块的常量和未执行子 prototype 的常量均不会提前成为明文。
- 测试输入中的字符串、嵌套闭包标签和二进制字符串没有以源码字面量出现在生成结果中。

### 2.4 子 prototype 按需恢复

- 子 prototype 在父 prototype 的 Functions 字段中增加长度 framing。
- 初次反序列化只保留每个子 prototype 的 opaque byte slice，不递归展开其指令、常量和后代。
- `OP_CLOSURE` 首次访问时通过 `GetProto` 切换到该 slice 反序列化，随后把结果缓存回父 prototype 表。
- root prototype 恢复后立即释放完整解密 body；后续保留尚未使用的子 prototype slices。默认 AntiDump 模式还保留各 instruction block 的 opaque body，以便块重入时重新认证和解码，而不是依赖共享明文缓存。

### 2.5 显式 CFG、入口状态与 basic-block 按需解码

- 新增 `ControlFlowGraph` / `ControlFlowBlock` IR 模型，在 opcode mutation 前建立 instruction-indexed successor、predecessor 与 leader；长直线自然区域再按最多 24 条指令细分。
- CFG 明确建模 JMP、FORLOOP、IronBrew 优化后的 FORPREP 双路径、comparison/Test/TForLoop companion JMP、`LOADBOOL` skip、`SETLIST C==0` data word、RETURN/TAILCALL 终止路径及自环/多前驱。
- 每个块由 CSPRNG 分配独立非零 32 位 entry state；prototype framing 只写包装后的初始状态，每条合法 successor record 写目标块 1-based start PC 与由源状态、源末 PC、目标 PC 包装的目标状态。
- 每块独立写入 1-based start PC、instruction count、随机 dispatcher route token（不适用时为 0）、有序常量 capsule 引用、state verifier、complete manifest tag、successor records、body length 和 opaque body；块的物理写入顺序由 CSPRNG 打乱。
- descriptor、opcode、A/B/C/Bx/sBx 除 prototype/PC mask 外再叠加 entry-state mask。没有认证入口状态时，即使已知 PC 与 prototype keys 也不能直接按旧格式独立恢复字段。
- prototype 初始恢复只读取 block framing 并保存 body slice，不恢复 instruction table；统一的 `GetInstruction(Chunk, PC, Flow)` 先验证初始入口、块内顺序或显式 edge，再验证目标 state/verifier，然后认证并解码整个目标块。
- Flow 的四个逻辑字段分别保存该 invocation 的 last PC、current block、entry state 和当前 block/state/instruction 临时缓存；其物理数字槽由每次构建的 Flow permutation 决定。每次 wrapper 调用独立创建 Flow，因此递归/重复调用不会共享控制流游标、明文常量或明文块。
- 主 while/repeat wrapper、`OP_CLOSURE` 的 upvalue 伪指令和可选 superoperator 的内部取指全部经过同一 accessor；dispatcher 也必须结合当前 Flow 的随机化 entry-state 槽才能恢复 opcode。
- 默认 AntiDump 模式不会把明文块写入共享 instruction 槽，也不会清除 opaque body、capsule、引用索引和 manifest tag；跨块或非顺序转移会替换随机化的 FlowCache 槽。块重入时重新认证 manifest、恢复引用常量并解码 body，因此正常执行路径不会在共享 prototype 表里逐步累积完整明文 instruction/constant table。
- 库级调用若显式关闭 AntiDump，仍可使用原共享 lazy cache 路径；唯一固定 CLI 配置始终启用 invocation-local 临时缓存。

### 2.6 自动 route-state dispatcher flattening

- 新增 `DispatcherFlatteningPlanner`，递归分析普通 prototype，不再要求 `IB_MAX_CFLOW_START/END` marker；`CFContext` 记录初次决策，serializer 在所有后续合并/折叠完成后重新分析最终形态。
- eligibility 是保守的整 prototype 判定：要求至少两个真实/分页 CFG block，并验证所有 JMP/FORLOOP/FORPREP 引用、comparison/Test/TForLoop companion JMP、`SETLIST C==0` data word、Closure prototype 与 upvalue 绑定伪指令。
- 对太小、单块、畸形 companion、截断 data word、无效 closure binding、未知 opcode 或分析异常的 prototype，仅保留原 PC 执行路径；planner 不改写指令，因此不会留下半完成的控制流变换。
- 每个被选 block 获得同 prototype 内唯一、非零且不与合法 PC 重叠的 CSPRNG 32 位 route token；prototype 入口也先保存为 token。
- VM 只允许块内顺序执行继续使用线性 PC。跳转、循环、skip-next 或分页导致的跨块转移会先将下一 PC 换成目标 block token；下一轮通过 prototype-local dispatcher 恢复 block start，再交给原有 `GetInstruction` 做合法 edge 与 entry-state 验证。
- 自环和同块非顺序转移也必须经过 token；Closure/superoperator 内部消费的附加指令仍由 `GetInstruction` 维持原顺序与 Flow，结束后再统一路由。
- route map 会验证 token 唯一性、token/PC 域分离、完整 block 覆盖和 entry token 必须解析到 PC 1；修改初始 dispatcher state 会以 `invalid protected payload` 拒绝。

该实现使用已随机物理排序的 CFG block 作为 dispatcher case，不重排 Lua 寄存器指令本身，因此比较 skip-next、循环 companion、可变返回和 closure 绑定语义不需要冒险地重新合成 Lua bytecode。

### 2.7 handler 与 dispatch leaf 结构多态

- `Generator.cs` 增加小型 Lua 词法扫描器，只在 handler 的顶层分号处分段；扫描时跳过引号/长字符串、行/长注释，并跟踪圆括号、table/index 以及 function/if/loop/repeat/do 块。
- 每个 canonical handler 独立选择 raw、`do` scope、`Enum == Enum` 恒真 guard 或保持原顺序的 prefix/suffix 嵌套模板。
- prefix 位于外层 scope，后续 suffix 仍能访问 prefix 声明的 local；带顶层 `return`/`break` 的前缀不会被选为切分点。
- dispatcher 的双 handler leaf 保持两个 canonical handler 独立，不融合 bytecode 指令；leaf 会在 `>`、`==`、`~=` 和嵌套恒真 guard 选择形式间变化，因此不属于 Phase 3 superoperator。
- 递归 dispatcher 的右分支依靠 `else` 与子 leaf 的 `if` 拼成 `elseif`；所有 leaf 模板都保持以 `if` 开头，避免破坏生成语法。

这些变换改变生成源码结构而不改变指令执行次序、寄存器语义或 opcode bank。handler 仍是每次构建生成一组，并非按 prototype 复制一整套 VM。

### 2.8 每 block columnar IR 与字段角色排列

- 指令 block body 不再按 `descriptor/opcode/A/B/C` 的逐行记录串联，而是先聚合为五个逻辑列；descriptor 保持每条 1 byte，opcode/A 保持 16 bit，B/C 仍按 ABC/ABx/AsBx/AsBxC 选择原有 16/32 bit 宽度，因此没有扩大 handler ABI。
- 五个逻辑列各自使用 `u32 length | bytes` framing。每个 block 由 entry state、prototype K1/K2/K3 和独立 domain 派生一组 physical-page → logical-role permutation；若 Fisher–Yates 偶然得到 identity，会交换前两项，保证不输出 canonical 物理顺序。
- wire format 不显式保存字段角色表。VM 先验证覆盖完整新 block body 的 manifest，再由认证的 entry state/keys 恢复角色，将五列以独立 cursor 按 descriptor/type 消费并重建原有 canonical `Inst[1..4]`，opcode handler 无需感知列式存储。
- runtime 拒绝物理 page 越界、重复/缺失角色、descriptor 高位、非 `1` 的 data-word descriptor，以及任一逻辑列未精确耗尽；column permutation、page/cursor/reader 等局部标识符继续参与每次构建的名称随机化。
- Python v4 verifier 与 C#/Lua 使用对称派生和 mask 公式，递归验证每个 block 的非 identity role map、五页 framing、descriptor 与预期列长度。测试还会在重算 block/prototype/outer 全部认证后分别破坏 page framing 和 descriptor-driven consumption，两种样本仍必须由 VM 拒绝。

该层提高依赖稳定 row schema 的静态批量解析和 AI 模式匹配成本，但运行时最终仍会重建 canonical instruction；它不是 IR-native superoperator，也不宣称阻止对 `DecodeInstructionBlock` 或 handler 的动态采集。

### 2.9 运行时槽位 ABI 随机化

- 生成器每次构建一次性产生四组 build-wide Fisher–Yates permutation：Chunk 15 槽、Block 9 槽、Flow 4 槽、FlowCache 3 槽；若随机结果恰为 identity，会交换前两项以强制非 identity。
- 该层不是只改局部变量名。prototype/block 构造器、VM helper、opcode handler、CurrentBlock/NextBlock/SuccessorBlock aliases 和 line-info 路径中的所有数字索引，都会在 minify 前按同一映射重写。
- 重写器使用轻量 Lua lexical scan 跳过单双引号、long string 和注释，避免 base91 payload、watermark 或普通字符串中偶然形似 `identifier[number]` 的内容被改写。
- Chunk 与 Block constructor 使用显式 keyed assignment，字段物理位置不再依赖 table constructor 的顺序；同一生成文件内所有 prototype 和 block 共享一套 ABI，保证运行一致性。
- `tests/runtime_layout.py` 从生成 Lua 独立恢复四组 old logical slot → generated physical slot 映射，验证每组都是完整非 identity permutation，并静态确认三个 block alias 使用同一随机布局。独立构建比较还要求至少一组 ABI 发生变化。

槽位随机化用于破坏依赖旧固定数字索引的通用 dump 脚本，不把客户端 ABI 描述为秘密；分析者仍可从单个生成 VM 恢复该次布局。

### 2.10 随机源

- prototype keys、salt、XOR seed、64–96 KiB entropy、envelope nonce/record split/物理 shuffle 和随机选择改用操作系统 CSPRNG。
- 仍需要 `System.Random` 接口的代码生成器、控制流及可选变换，改为使用 CSPRNG seed，避免同一时钟窗口产生相同序列。
- 清理了不再使用的旧 XOR key 和全局常量映射字段。

### 2.11 strict executor-only attestation 与 AntiDump

本轮把上一版“可选 capability + 加权评分 + 有限诱饵”改为默认 fail-closed 的 generic executor attestation。目标不是绑定某个执行器品牌，而是要求 Roblox host、executor primitive 和 debug inspector 同时满足完整行为契约。

- 防护直接生成在 VM 内。`identifyexecutor()` 是必需信号，必须两次稳定返回 1–128 字节的非空名称，版本类型和值也必须稳定；若存在 `getexecutorname` 或 `executorname` 别名，名称必须一致。代码不包含名称或版本白名单。
- 所有准入项为硬性 AND，不再使用权重、阈值或 quorum。必须具备稳定 `getgenv()`、`checkcaller()==true`、`iscclosure`/`islclosure`、`newcclosure`、`loadstring`、`typeof`、Roblox `game`/`Instance`/`Vector3`/`task`，以及 `debug.getconstants`、`getupvalues`、`getproto`/`getprotos`、`setupvalue` 和 `debug.info`/`getinfo`。
- Roblox host challenge 实际调用 `game:GetService("Players")`、`Vector3.new()` 和 `typeof`，并核对 `Instance.new` 及 `task.wait`/`spawn`/`defer`；不是只检查全局名是否存在。
- closure/provenance challenge 区分已知 native primitive、本地 Lua closure、`loadstring` 产生的 Lua closure与 `newcclosure` 包装结果。`string.byte` 等 19 个关键 primitive 及 debug inspector 必须表现为 native source，本地 probe 必须表现为 Lua source。
- 每次生成独立的 constant、upvalue 修改/恢复、child proto 调用、动态 loadstring 和 newcclosure 输入。debug API 必须返回并操作真实 challenge 值；成功值按顺序合成随机 transcript，只有完整 transcript 才恢复本次构建的 attestation token。
- VM 启动时快照 `string`、`table`、`math`、raw/meta、转换、调用、unpack、capability provider 和全部 debug/executor primitive。后续检查要求身份不变、`getgenv()` 返回同一环境且无活动 debug hook。
- guard 维护 attestation、epoch、状态和 seal；seal 不一致、token 异常或任一检查失败都会 sticky 命中并把 token 清零。状态驱动 interval+jitter 调度，不依赖绝对时间。
- 强制检查发生在 guard 启动、root prototype 反序列化后和首个 block 进入前；四种 dispatch wrapper 继续周期复检。中途失败时尽量清除当前 invocation 可达的 `Root`/payload body、instruction/proto/args/vararg/upvalue/stack 和 FlowCache 引用。
- 失败后不打印、不抛专用阻断错误，也不返回。当前线程进入每次构建随机化的 6–10 状态位混合图并永久执行；状态量固定，内存为 O(1)，不 yield、不联网、不探测文件、不启动后台任务、不扫描 registry、不覆盖 executor global，也不持续分配内存。外部 executor/Roblox watchdog 仍可能终止该忙循环。
- 指令驻留防 dump 继续由 `AntiDump` 控制：共享 Chunk instruction 槽不积累明文，当前 invocation 的随机化 FlowCache 最多保留一个已认证块；跨块后替换，重入时从 opaque manifest/capsule/body 重建。
- `DefenseGenerator` 仅保留空兼容 shim；`AggressiveDefense` 不恢复旧全局 hook、后台扫描或破坏性内存逻辑。

这些检查比只信任 `identifyexecutor()` 或 API stub 更严格，但客户端不存在不可伪造的 executor oracle。完整模拟所有契约的宿主，或能 patch 已交付 guard/handler 的分析者，仍可绕过或采集临时块。

### 2.12 EnvironmentLock 与 payload/flow 绑定

- 固定 CLI 配置和 `ObfuscationSettings` 默认值现在都启用 `EnvironmentLock`；`EnvironmentLock && !AntiDump` 会在生成阶段被拒绝。普通 Lua、普通 Luau 和 Studio 不再执行真实 payload。
- 每次构建生成独立 salt 与非零 attestation token。构建端以 `Hash(decimal(salt) + "|" + decimal(token))` 得到 `_context.XorSeed`；运行端只有严格 challenge 完成后才能从 transcript 恢复相同 token 并派生同一 seed。
- header 在锁定模式仅写 salt。最终 seed用于 outer envelope/tag 与正文恢复，并额外进入 initial flow key、edge transition key、flow verifier、完整 block manifest tag和 initial route token 解封；因此通过结果与 payload seed、root/首块 route 及认证域共同绑定。
- 对返回 signed 32-bit 结果的 `bit.bxor`，initial route 解封显式执行 `U32(BitXOR(gBits32(), OuterSeed))`，与其余 v4 读路径保持无符号一致。
- salt、token、seed 派生和 guard 都随客户端交付；这里的“绑定”用于提高离线恢复和单点 patch 成本，不应描述成秘密、服务端信任根或无法绕过的硬件证明。库调用方仍保留显式关闭锁的兼容路径，但不属于唯一 CLI 配置。

### 2.13 line info 与 Linux 工具链

- line-info wrapper 的 legacy logical field 从错误的 Chunk 槽 7 修正为逻辑槽 4；v4 生成时该逻辑槽再与其余 Chunk 字段一起映射到随机物理槽。
- LuaSrcDiet 的 `LUA_PATH` 由 C# 显式设置，不再依赖调用者当前目录。
- 最终 minifier 非零退出码现在会被当作构建失败。

### 2.14 单一 CLI 配置

CLI、Windows 拖放脚本和 GitHub Actions 均取消强度档位，统一使用 strict executor-only 固定行为：

| 设置 | 固定值 |
|---|---:|
| v4 schema / prototype keys / block-state 字段编码 / block-local constant capsule / prototype + complete block manifest 完整性检查 | 开 |
| 64–96 KiB authenticated/state-coupled entropy envelope（feature bit 3） | 开 |
| child prototype / CFG basic-block 两级按需恢复、自动 route-state dispatcher 与合法 edge/state 验证 | 开 |
| Chunk/Block/Flow/FlowCache 四组 build-wide 非 identity 运行时槽位 permutation | 开 |
| handler / 双 handler dispatch leaf 结构多态 | 开 |
| ControlFlow | 开 |
| DEFLATE | 开 |
| AntiDump（hard-AND executor attestation / sticky non-returning O(1) sink / invocation-local 指令缓存） | 开 |
| EnvironmentLock（attestation token → payload/flow binding） | 开 |
| Mutation / SuperOperator / 源码字符串转换 | 关 |
| AggressiveDefense / Noise | 关 |

CLI 只接受 `<input.lua>` 和可选的 `--line-info`；旧 `--strength` 与旧覆盖开关会作为未知参数拒绝。`ObfuscationSettings` 构造器默认值也已同步启用 AntiDump + EnvironmentLock，避免非 CLI 调用回退到普通 Lua 可执行路径。

## 3. 自动化测试

测试入口：

```bash
DOTNET=/path/to/dotnet LUA=/path/to/lua LUAC=/path/to/luac \
  tests/run_linux_tests.sh
```

本轮实际工具链：

- .NET SDK `8.0.424`
- PUC Lua `5.1.5`
- Release 构建

最终测试结果：

| 检查 | 结果 |
|---|---|
| Release build | 通过，0 warnings / 0 errors |
| Release 生成 payload header | 通过，version 4 / features 15（DEFLATE + block flow + dispatcher + entropy envelope） |
| entropy envelope 规模/熵值/完整恢复 | 通过，每次 64–96 KiB，Shannon entropy ≥ 7.95 bits/byte，真实 DEFLATE body 可恢复 |
| 两次生成 entropy/nonce/digest 独立 | 通过 |
| 重新计算外层 tag 后修改、删除、重排 entropy record | 通过，三种均由 envelope 层拒绝 |
| 新增 envelope runtime 局部名随机化 | 通过，输出无稳定 `Payload*` / `Envelope*` 标识符 |
| 固定配置与原脚本差分 | 通过 |
| 固定配置随机构建 | 20/20 通过 |
| 旧 `--strength` 参数拒绝 | 通过，退出码 2 |
| prototype-local schema / tag / opcode bank 随机构建 | 通过 |
| 完整 prototype tag、complete block manifest、constant capsule 的可重封装内层篡改 | 通过，三类均由 v4 内层认证拒绝 |
| 每 block 五列 framing、非 identity 字段角色排列与 descriptor 驱动精确消费 | 通过，静态 verifier 递归覆盖所有 block |
| 重算 block/prototype/outer 认证后的 column framing 与 descriptor-consumption 篡改 | 通过，两类均由运行时列解析器拒绝 |
| columnar runtime 局部名随机化 | 通过，输出无稳定 permutation/column reader 标识符 |
| Chunk 15 / Block 9 / Flow 4 / FlowCache 3 槽位完整非 identity permutation | 20/20 通过 |
| 独立构建 runtime ABI 比较及 block aliases 一致性 | 通过，至少一组完整 ABI 变化，Current/Next/Successor aliases 均匹配 |
| handler 等价模板 / 双 handler leaf 随机结构与 Lua 语法 | 20/20 通过 |
| nested closure / upvalue / lazy child prototype / closure 伪指令 | 通过 |
| 30 个 upvalue 的 Closure 伪指令跨 24 条 block 边界 | 通过 |
| 显式 CFG 结构：循环/自环、predecessor、comparison/Test/TForLoop companion、FORPREP/FORLOOP、skip/data、24 条分页 | 通过 |
| 无 marker 普通 prototype 自动 dispatcher 命中与完整 route map | 通过 |
| 单块、畸形 companion/SETLIST/Closure prototype 安全回退且无部分 route metadata | 通过 |
| basic-block 进入时认证与 invocation-local 单块临时解码 | 通过 |
| root 的随机化 instruction 槽不积累明文；constant store 保持 opaque capsule；已执行/未执行 block 的 opaque body 均保留 | 通过 |
| trusted generic executor shim 的正常输出及原脚本语义差分 | 通过 |
| 普通 Lua、primitive/raw/debug hook、活动 debug hook、classifier/identity spoof、缺失 debug contract | 通过；均由外部 2 秒 timeout 终止，终止前 stdout/stderr 为 0 bytes |
| guard 启动、root 反序列化后、首块进入前与 jittered dispatch 四阶段调用 | 通过 |
| attestation-derived outer seed、flow/integrity/route binding 的静态递归恢复 | 通过 |
| 新增 guard 局部名随机化，最终输出无稳定 `Guard*` 标识符 | 通过 |
| executor global/capability provider 不被修改 | 通过 |
| block body、完整 manifest、初始 state、dispatcher state、缺失 edge、wrapped edge state 的反序列化后篡改 | 通过，均拒绝 |
| 分支/循环/递归/table constructor 与块级常量引用 | 通过 |
| `SETLIST C==0` 后继 data word（测试侧 patch Lua 5.1 chunk） | 通过 |
| boolean、number、二进制 string 常量 | 通过 |
| for/while/repeat/branch/recursion | 通过 |
| vararg 与多返回值 | 通过 |
| table 与全局调用 | 通过 |
| nested line-info 错误定位 | 通过，包含原始 line 4 |
| signed 32-bit `bit.bxor` 模拟 | 通过 |
| payload 单字符篡改 | 通过，解密前拒绝 |
| 生成源码字符串字面量扫描 | 通过 |
| 从仓库根目录调用 CLI | 通过 |

测试源位于：

- `tests/semantic.lua`
- `tests/closure_boundary.lua`
- `tests/lazy_blocks.lua`
- `tests/executor_runner.lua`（可信正路径与严格失败模式 shim）
- `tests/anti_debug_runner.lua`（兼容入口）
- `tests/cfg_regression/Program.cs`
- `tests/luac_setlist_c0_wrapper.py`（仅测试时构造 `SETLIST C==0` data word）
- `tests/line_error.lua`
- `tests/signed_bit_runner.lua`
- `tests/verify_v4_payload.py`
- `tests/runtime_layout.py`
- `tests/run_linux_tests.sh`

### 3.1 CI 与多平台构建

`.github/workflows/ci.yml` 在 push、pull request 和手动触发时运行：

- `ubuntu-24.04` 安装 .NET 8 与 PUC Lua 5.1，以 `IB2_RANDOM_RUNS=20` 执行完整 Linux 差分、authenticated entropy envelope、每 block columnar IR/字段角色排列、CFG、strict executor attestation、外部 timeout 失败路径、临时 block cache、篡改拒绝和泄漏检查套件；
- 独立 Release publish 矩阵覆盖 `linux-x64`、`win-x64` 和 `osx-arm64`，分别使用当前 GitHub-hosted Linux、Windows 与 macOS runner；
- build matrix 使用 framework-dependent publish 和 `ContinuousIntegrationBuild=true`，验证三个目标 RID 均能完成 Release 编译；
- 按当前范围不上传 CI Artifact、不调整现有云端混淆产物策略，也不增加仓库内二进制工具校验。

本地预检已完成 workflow YAML 解析、最终 Release build、`IB2_RANDOM_RUNS=20` Linux 完整回归，以及三个 RID 的 framework-dependent cross-publish；真正的三种 hosted runner 结果需在提交推送后由 GitHub Actions 给出。

## 4. 仍存在的边界

1. 这是客户端混淆，不是密码学保密。salt、attestation token、seed、VM、prototype banks、entropy envelope 派生和校验逻辑最终都在攻击者可执行的客户端中；state coupling 能阻止无脑裁剪，却不能阻止分析者同步 patch/重实现客户端验证器。
2. 字段 schema、常量 tag 与 opcode bank 按 prototype 变化，block mask、edge wrapping 和完整性域再依赖 CFG entry state 与 attestation-derived binding；但所有派生、guard、v4 验证逻辑与该次 runtime slot ABI 仍在客户端。有能力的分析者可以完整模拟 executor contract、patch guard，或 hook dispatch、`GetProto`、`GetInstruction`、handler 与随机化 FlowCache 槽收集执行路径、临时常量和指令块。
3. root prototype 的 schema、opaque constant capsules 和 block framing 仍在启动时恢复，但常量值只在引用它的完整 block manifest 认证后进入一次 block decode 的 invocation-local cache。默认 AntiDump 模式不会在共享 Chunk 表累积明文常量或指令；不过 capsule、索引和恢复算法都留在客户端，分析者仍可 hook capsule decode 或逐块触发执行来收集值。
4. CFG state 是客户端执行一致性与反静态批量恢复机制，不是不可伪造的 CFI 信任根。修改 VM、跳过 verifier，或在每个临时块进入 handler 前主动收集，仍可绕过本地保护。
5. 当前每个 block 使用一个固定 entry state；多前驱通过不同 wrapped edge 恢复同一目标状态。尚未实现按 predecessor 产生多版本 block 或动态 state merge。
6. 自动 dispatcher 已按 prototype 启用，但它复用随机物理 block 和 VM route token，不是把原 Lua 指令复制成多版本 block；客户端仍可在 route 解析后观测真实 PC。
7. Mutation/SuperOperator 没有被本轮宣告为稳定；IR-native superoperator 及更大差分语料仍是后续工作，固定配置继续关闭它们。
8. 前端仍是 Lua 5.1 bytecode，不是完整 Luau 前端。Roblox/Luau 专有语法需要单独支持；“Luau/Roblox 优先”目前仅指 capability-gated 运行时防护。
9. 活动合法调试 hook 会进入无限静默 sink。准入是 hard-AND，因此缺失某项 inspector 或行为差异的真实执行器也会被拒绝；本实现不承诺覆盖所有定制执行器或零误报。恶意宿主若一致伪造 closure/debug/provenance/host 全部契约，客户端无法从根本上区分。
10. CI 已覆盖 Linux 完整语义回归和 Linux/Windows/macOS Release publish；自动测试已验证 64–96 KiB 随机区及 basE91 前的载荷范围，但尚未在 Windows/macOS 上运行 Lua 语义套件，也尚未完成大程序下 envelope 解码时间、峰值内存和最终文本体积基准。

后续工作按 `HARDENING_PLAN.md` 的剩余候选继续：IR-native superoperator、Luau 原生前端，以及性能、内存和体积基准。
