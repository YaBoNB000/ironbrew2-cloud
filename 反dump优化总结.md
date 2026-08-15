# 反 dump、反调试与体积优化说明

> 本文件原先记录旧版多档位实现，现已按单一固定配置同步。完整实现与验证结果请以 [`HARDENING_REPORT.md`](HARDENING_REPORT.md) 为准。

## 当前固定配置

所有 CLI、Windows 拖放脚本和 GitHub Actions 调用都使用同一配置：

- ControlFlow、字节码 DEFLATE：开启
- v3 payload、prototype-local 字段 schema / 常量 tag / opcode bank、block-state 字段编码和分层完整性检查：开启
- 子 prototype 按 `OP_CLOSURE` 首次访问延迟恢复：开启
- 显式 CFG、invocation-local Flow、合法 successor edge、包装目标 state 与目标块入口验证：开启
- 安全 prototype 自动 route-state dispatcher flattening；不满足准入条件时原子回退：开启
- handler 安全分段/等价模板与双 handler dispatch leaf 结构多态：开启
- **AntiDump：开启**（Luau/Roblox capability 探针、静默诱饵、invocation-local 临时指令缓存）
- EnvironmentLock、AggressiveDefense、Noise：关闭
- Mutation、SuperOperator、源码字符串转换：关闭

这里的 AntiDump 不再是旧版“要求存在某个执行器 API，否则明确报错”的前置 bytecode 块。防护代码现在直接位于生成 VM 内：普通 Lua 环境可以兼容运行；宿主若提供 `debug.gethook`、`iscclosure` 或 `islclosure`，VM 才使用这些能力检查活动调试 hook 和被 Lua closure 替换的关键原语。检测命中后进入无输出、有限计算的诱饵路径，不显示“blocked”错误。

旧 `AggressiveDefense` 的全局 API 删除/替换、registry 后台扫描、无限循环和大内存分配已经移除。生成脚本不会修改 `getgenv()` 中的 `hookfunction`、文件 API 或 load API，也不会启动常驻扫描任务。`AggressiveDefense` 字段仅为源码兼容保留，不再注入这些行为。

## VM / payload 耦合的防 dump 路径

1. 指令仍以经过 entry-state 掩码和块级完整性认证的 opaque block body 存放。
2. 默认 AntiDump 模式不再把已执行块写入共享的 `Chunk[1]` 明文 instruction table。
3. `GetInstruction` 只在当前 closure invocation 的 `Flow[4]` 中保存当前块的解码结果；跨块、跳转、自环或其他非顺序转移会替换该缓存。
4. opaque body、最小常量引用和 body tag 被保留，以便块再次进入时重新认证、重新解码；因此不会随着执行路径增长而累积一份共享明文指令全集。
5. 运行中 guard 按随机间隔从 dispatch 检查捕获的 `string`、`table`、`math` 与关键原语身份。中途命中同样从当前 VM invocation 静默返回诱饵结果。
6. 关闭 AntiDump 的库级调用仍可使用原共享 lazy cache 路径，但唯一固定 CLI 配置默认开启上述临时缓存。

该设计会以块重入时重复认证/解码换取更小的明文驻留窗口，属于安全与性能的明确取舍。

## 已保留的体积与结构优化

1. 字节码正文在加密前使用 DEFLATE，生成结果再以 basE91 表示；加密后的高熵数据不再重复套用收益为负的 LZW。
2. VM 模板只包含实际需要的 opcode handler。
3. 字符串常量由外层 payload 加密和 prototype/常量索引相关的内层编码保护，不启用会放大体积且影响闭包语义的源码级解密函数。
4. 父 prototype 只保留子 prototype 的长度分帧 opaque slice；子指令和常量在 closure 首次创建时恢复。
5. instruction stream 由显式 CFG 的 leader、successor 和 predecessor 分块；每块保存 opaque body 和自己的最小常量引用集合。
6. 每个 block 使用独立随机 entry state；descriptor/opcode/operands 都叠加 state mask，每条合法 edge 才能解包目标 state。
7. 通过完整 CFG 准入的多块 prototype 自动获得随机 route token；跨块、非顺序和自循环转换先提交 token，再解析为真实入口。
8. handler 使用词法安全边界的等价模板，双 handler dispatch leaf 也采用多种结构，但不冒充 IR-native superoperator。

## 当前安全边界

- 这是客户端混淆，不是密码学保密。guard、decoy、校验、密钥派生和 VM 最终都交付给客户端，有能力的分析者仍可 patch 探针或 hook dispatch。
- capability 探针采用高置信信号并避免“API 存在即判定”；但宿主可伪造 `iscclosure` 等结果，合法调试 hook 也会按反调试策略进入诱饵。
- 临时缓存阻止正常执行路径在共享 prototype 表中累积明文全集，但攻击者仍可 hook `GetInstruction`、handler 或 `Flow[4]` 收集当前块。
- 顶层与 block 两级完整性检查可确定性拒绝简单篡改，但校验算法随客户端交付，不是服务端信任根。
- 当前每个目标 block 对所有合法 predecessor 使用同一 entry state；尚未做 predecessor-specific 多版本或动态 state merge。
- 前端仍由 Lua 5.1 `luac` 产生 bytecode；本轮“Luau/Roblox 优先”指运行时 capability 防护，不等同于已经支持全部 Luau 专有源语法。
- IR-native superoperator 仍是独立候选项目，固定配置继续关闭 Mutation/SuperOperator。

## 验证

Linux 自动测试入口：

```bash
DOTNET=/path/to/dotnet LUA=/path/to/lua5.1 LUAC=/path/to/luac5.1 \
  tests/run_linux_tests.sh
```

测试覆盖固定配置语义差分、20 次随机生成、Luau/executor capability 正常模拟、关键原语 Lua-hook 模拟、活动 `debug` hook 模拟、静默诱饵无输出、executor 全局不被修改、共享 `Chunk[1]` 不积累明文指令、opaque block 保留、显式 CFG、dispatcher 准入/回退、Closure/SETLIST 边界、line info、有符号 bit、payload 与 flow/block 篡改拒绝及明文字符串扫描。
