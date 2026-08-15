# 反 dump、反调试与体积优化说明

> 本文件原先记录旧版多档位实现，现已按单一固定配置同步。完整实现与验证结果请以 [`HARDENING_REPORT.md`](HARDENING_REPORT.md) 为准。

## 当前固定配置

所有 CLI、Windows 拖放脚本和 GitHub Actions 调用都使用同一配置：

- ControlFlow、字节码 DEFLATE：开启
- v4 payload、prototype-local 字段 schema / 常量 tag / opcode bank、block-state 字段编码和分层完整性检查：开启
- 每次 64–96 KiB authenticated/state-coupled entropy envelope（feature 15）：开启
- 完整 prototype tag、complete block manifest 和独立认证 constant capsules：开启
- 子 prototype 按 `OP_CLOSURE` 首次访问延迟恢复；常量按实际进入 block 延迟恢复：开启
- Chunk/Block/Flow/FlowCache 四组 build-wide 非 identity 运行时槽位随机化：开启
- 显式 CFG、invocation-local Flow、合法 successor edge、包装目标 state 与目标块入口验证：开启
- 安全 prototype 自动 route-state dispatcher flattening；不满足准入条件时原子回退：开启
- handler 安全分段/等价模板与双 handler dispatch leaf 结构多态：开启
- **AntiDump：开启**（Luau/Roblox capability 探针、静默诱饵、invocation-local 临时指令缓存）
- EnvironmentLock、AggressiveDefense、Noise：关闭
- Mutation、SuperOperator、源码字符串转换：关闭

这里的 AntiDump 不再是旧版“要求存在某个执行器 API，否则明确报错”的前置 bytecode 块。防护代码现在直接位于生成 VM 内：普通 Lua 环境可以兼容运行；宿主提供能力时，VM 才使用 `debug.gethook`、`debug.getinfo`/`debug.info`、`iscclosure` 和 `islclosure`。当前实现采用分层探针：先做快照身份与 capability provider 一致性检查，再在重探针中交叉验证 C/L closure 分类、debug source provenance，并用 raw table/string/select 等无副作用行为 canary 检查语义。各信号按权重聚合，达到高置信阈值后 sticky 命中，进入无输出、有限计算的诱饵路径，不显示“blocked”错误。

guard 自身维护带 seal 的运行状态；seal 不一致会直接命中。该状态同时驱动 LCG 式抖动调度，避免固定的 `counter % N` 周期。强制检查分别发生在 VM guard 启动和 root prototype 反序列化之后，dispatch 中继续按 interval+jitter 复检；所有 guard 局部名仍经过每次构建的随机化。

旧 `AggressiveDefense` 的全局 API 删除/替换、registry 后台扫描、联网/文件探测、绝对时序判断、无限循环和大内存分配均未恢复。生成脚本不会修改 `getgenv()` 中的 `hookfunction`、文件 API 或 load API，也不会启动常驻扫描任务。`AggressiveDefense` 字段仅为源码兼容保留，不再注入这些行为。

## VM / payload 耦合的防 dump 路径

1. 真实序列化 body 在 DEFLATE 后先由全量 entropy digest 派生的状态流掩码，再拆成 data records，与 64–96 KiB CSPRNG entropy records 交错；VM 必须验证 envelope tag/framing/digest 并恢复全部 data records 后才能 inflate。
2. entropy digest 覆盖所有 logical entropy records，envelope tag 覆盖物理顺序；随机区即使位于真实数据之后也会改变内层 mask state，不能作为尾部 padding 直接删除。
3. v4 在读取 schema、block、capsule 或 child framing 前先验证完整 prototype slice；每个 constant value 在启动时只保留为独立认证的 opaque capsule。
4. block body 继续使用 entry-state 掩码；其完整 manifest 同时绑定 range、route token、有序引用及引用 capsule bytes、flow verifier、有序 successor/wrapped states 和 body。
5. 只有完整 manifest 通过后，才在本次 `DecodeInstructionBlock` 的局部缓存恢复该块引用的常量并解码 body；明文常量不写回 prototype。
6. 默认 AntiDump 模式不把已执行块写入共享 instruction table。当前 invocation 的随机化 FlowCache 槽只保存当前块；跨块、跳转、自环或其他非顺序转移会替换该缓存。
7. opaque capsule、manifest 和 body 被保留，块重入时重新认证、重新恢复常量与指令；因此不会随执行路径增长而累积共享明文全集。
8. Chunk 15、Block 9、Flow 4、FlowCache 3 个逻辑槽在每次构建映射到四组完整非 identity 物理槽；constructor、alias、helper 与 handler 使用同一 build-wide ABI。
9. guard 在启动、root 反序列化后及 dispatch 周期三个阶段检查捕获的库/关键原语、debug/closure provenance 与行为 canary；周期由密封状态产生抖动。中途命中同样从当前 VM invocation 静默返回诱饵结果。
10. 关闭 AntiDump 的库级调用仍可使用共享 lazy cache 路径，但唯一固定 CLI 配置默认开启上述临时缓存。

该设计会以块重入时重复认证/解码换取更小的明文驻留窗口，属于安全与性能的明确取舍。

## 当前体积与结构取舍

1. 真实字节码正文先使用 DEFLATE，再加入 64–96 KiB 认证 entropy envelope、外层 streaming XOR 和 basE91。高熵区不再重复套用收益为负的 LZW；固定随机区及约 1.23 倍 basE91 展开是明确接受的体积成本。
2. VM 模板只包含实际需要的 opcode handler。
3. 常量由外层 payload、prototype/索引相关内层编码和 capsule tag 共同保护；只在引用它的 block 进入时局部恢复。不启用会放大体积且影响闭包语义的源码级解密函数。
4. 父 prototype 只保留子 prototype 的长度分帧 opaque slice；子 prototype 在 closure 首次创建时验证并解析，其常量仍按 block 延迟恢复。
5. instruction stream 由显式 CFG 的 leader、successor 和 predecessor 分块；每块保存完整认证的 manifest、opaque body 和有序 capsule 引用。
6. 每个 block 使用独立随机 entry state；descriptor/opcode/operands 都叠加 state mask，每条合法 edge 才能解包目标 state。
7. 通过完整 CFG 准入的多块 prototype 自动获得随机 route token；跨块、非顺序和自循环转换先提交 token，再解析为真实入口。
8. 四组 runtime slot permutation 改变 VM 数据结构的数字 ABI，但不增加 envelope 体积；handler 使用词法安全边界的等价模板，双 handler dispatch leaf 也采用多种结构，但不冒充 IR-native superoperator。

## 当前安全边界

- 这是客户端混淆，不是密码学保密。guard、decoy、校验、密钥派生和 VM 最终都交付给客户端，有能力的分析者仍可 patch 探针或 hook dispatch。
- capability 探针采用高置信信号并避免“API 存在即判定”；但宿主可伪造 `iscclosure` 等结果，合法调试 hook 也会按反调试策略进入诱饵。
- 临时缓存阻止正常执行路径在共享 prototype 表中累积明文常量/指令全集，但攻击者仍可 hook capsule decode、`GetInstruction`、handler 或随机化 FlowCache 槽收集当前块。
- 顶层、entropy envelope、prototype、complete block manifest 与 capsule 多层完整性/状态检查可确定性拒绝简单篡改和 record 裁剪；但校验与派生算法随客户端交付，不是服务端信任根。
- runtime slot ABI 每次变化会破坏固定槽位工具，但布局可从单个生成 VM 恢复，不能被视作秘密。
- 当前每个目标 block 对所有合法 predecessor 使用同一 entry state；尚未做 predecessor-specific 多版本或动态 state merge。
- 前端仍由 Lua 5.1 `luac` 产生 bytecode；本轮“Luau/Roblox 优先”指运行时 capability 防护，不等同于已经支持全部 Luau 专有源语法。
- IR-native superoperator 仍是独立候选项目，固定配置继续关闭 Mutation/SuperOperator。

## 验证

Linux 自动测试入口：

```bash
DOTNET=/path/to/dotnet LUA=/path/to/lua5.1 LUAC=/path/to/luac5.1 \
  tests/run_linux_tests.sh
```

测试覆盖固定配置语义差分、20 次随机生成、64–96 KiB 规模与 Shannon entropy、跨次 entropy 独立性、envelope 完整恢复、在重算外层 tag 后修改/删除/重排 record 的拒绝、v4 prototype/complete block manifest/constant capsule 三类可重封装内层篡改拒绝、四组完整非 identity runtime slot permutation、跨构建 ABI 变化及 block aliases 一致性、Luau/executor capability 正常与篡改模拟、静默诱饵、三阶段探针、名称随机化、executor 全局不被修改、共享 instruction table 不积累明文、constant store 保持 opaque capsule、显式 CFG、dispatcher 准入/回退、Closure/SETLIST 边界、line info、有符号 bit、flow/block 篡改拒绝及明文字符串扫描。
