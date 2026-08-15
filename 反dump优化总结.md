# 反 dump 与体积优化说明

> 本文件原先记录旧版多档位实现，现已按单一固定配置同步。完整的当前实现与验证结果请以 [`HARDENING_REPORT.md`](HARDENING_REPORT.md) 为准。

## 当前固定配置

所有 CLI、Windows 拖放脚本和 GitHub Actions 调用都使用同一配置：

- ControlFlow：开启
- 字节码 DEFLATE：开启
- v3 payload、prototype-local 字段 schema / 常量 tag / opcode bank、block-state 字段编码和分层完整性检查：开启
- 子 prototype 按 `OP_CLOSURE` 首次访问延迟恢复：开启
- 显式 CFG basic block 按 PC 首次进入恢复，长直线块最多 24 条且物理顺序随机：开启
- invocation-local Flow、合法 successor edge、包装目标 state 与目标块入口验证：开启
- handler 安全分段/等价模板与双 handler dispatch leaf 结构多态：开启
- AntiDump、EnvironmentLock、AggressiveDefense、Noise：关闭
- Mutation、SuperOperator、源码字符串转换：关闭

此选择以 Lua 5.1 语义正确性和兼容性为优先。AntiDump 与环境探针代码仍保留为库级实验能力，但不属于固定 CLI 行为。

## 已保留的体积优化

1. 字节码正文在加密前使用 DEFLATE，生成结果再以 basE91 表示。
2. 加密后的高熵数据不再重复套用收益为负的 LZW。
3. VM 模板只包含实际需要的 opcode handler。
4. 字符串常量由 serializer 的外层 payload 加密和 prototype/常量索引相关内层编码保护，不启用容易放大体积且影响闭包语义的源码级解密函数。
5. 父 prototype 只保留子 prototype 的长度分帧 opaque slice；子指令和常量在 closure 首次创建时恢复，root 解密 body 随后释放。
6. instruction stream 由显式 CFG 的 leader、successor 和 predecessor 分块；每块仅保存自己的 opaque body 和最小常量引用集合，首次取指时才恢复，恢复后立即释放块 body 和常量引用。
7. 每个 block 使用独立随机 entry state；descriptor/opcode/operands 都叠加 state mask，每条合法 edge 才能解包目标 state。块首次解码前还会认证绑定状态与块范围的 body tag。
8. handler 通过词法扫描器在顶层 statement 边界安全分段，随机使用 raw、`do`、恒真 guard 和 prefix/suffix 嵌套模板；双 handler dispatch leaf 也使用多种等价选择结构，但不融合指令或冒充 superoperator。

## 当前安全边界

- v3 顶层与 block 两级完整性检查可以确定性拒绝正文、opaque body、初始 state 和 edge metadata 的简单篡改，但校验算法随客户端交付，不是服务端信任根。
- AntiDump 或环境 fingerprint 都不能让离线客户端机制变成“不可逆”。
- CFG/state coupling 阻止按 PC 使用旧格式线性恢复，并认证正常 VM 的跨块转换；攻击者仍可修改客户端 verifier、hook `GetInstruction`/Flow 或在解码后收集已执行块。
- 当前每个目标 block 对所有合法 predecessor 使用同一 entry state；尚未做 predecessor-specific block 多版本或动态 state merge。
- 当前常量值在 prototype schema 恢复时解码，再由相关 block 的最小引用集合保留；尚未做到逐次使用时解码。
- 自动 dispatcher flattening 与 IR-native superoperator 尚未完成，固定配置继续关闭 Mutation/SuperOperator。
- 后续体积优化应通过语义差分、性能和产物大小基准评估，而不是增加无意义编码层或默认启用高误判 API hook。

## 验证

Linux 自动测试入口：

```bash
DOTNET=/path/to/dotnet LUA=/path/to/lua5.1 LUAC=/path/to/luac5.1 \
  tests/run_linux_tests.sh
```

当前测试覆盖固定配置语义差分、20 次 handler/dispatch/schema/tag/opcode/block/state 随机生成、显式 CFG 结构、循环/自环/递归、closure/upvalue、30 个 Closure 伪指令跨块、vararg、多返回值、`SETLIST C==0` data word、line info、有符号 32 位 bit、顶层 payload 篡改、block body/初始 state/缺失 edge/wrapped state 篡改和明文字符串扫描。测试只对 `temp/t2.lua` 工作副本注入运行时探针，确认未执行 block 保持 opaque 并验证 v3 内部拒绝路径；生产 VM 不包含该调试接口。
