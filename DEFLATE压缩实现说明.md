# DEFLATE 字节码压缩实现说明

## 当前实现

字节码正文使用 **DEFLATE（RFC 1951）**，不再使用旧 LZ77/LZW 数据流。

| 端 | 实现 |
|---|---|
| C# 混淆器 | `System.IO.Compression.DeflateStream` |
| Lua VM | pure-Lua inflate，支持 stored、fixed Huffman 和 dynamic Huffman block |

固定 CLI 配置始终开启压缩。当前数据流为：

```text
v3 prototype/常量/CFG block-state 指令序列化
→ DEFLATE
→ seed 驱动的流式 XOR
→ 9 字节 v3 头（head/salt + integrity tag + version/features）
→ basE91
```

运行端按相反顺序处理，并在解密、inflate 和反序列化前验证版本、feature 位及 seed-bound integrity tag。版本必须为 3，当前只接受 feature 值 2 或 3；bit 0 表示 DEFLATE，bit 1 表示 CFG basic-block lazy decode/state framing。固定配置产生 feature 值 3。

## 位序注意事项

DEFLATE Huffman code 与 extra bits 的读取方向不同。VM inflate 实现保留独立位读取路径，fixed distance code 使用与 Huffman 表匹配的位序，extra bits 使用 LSB-first。错误处理统一为 `invalid protected payload`，避免继续解析损坏正文。

## 体积边界

DEFLATE 对较大的重复字节码通常有效，但最终 Lua 产物还包含 VM、opcode handler、inflate 和 basE91 解码器，因此数据段压缩率不会直接等于最终文件缩减比例。固定配置暂不按输入大小自动关闭压缩；自适应压缩属于 `HARDENING_PLAN.md` 的后续基准工作。

## 验证

`tests/run_linux_tests.sh` 当前验证：

- 固定压缩配置与原脚本输出一致；
- 默认独立随机生成 20 次（可由 `IB2_RANDOM_RUNS` 调整）均一致；
- 生成产物头必须为 v3 且携带 CFG basic-block feature；
- signed 32-bit `bit.bxor` 模拟兼容；
- payload 单字符篡改在 inflate 前确定性拒绝；
- `luac -p` 语法检查通过。

当前权威实现位置：

- `IronBrew2/Bytecode Library/Bytecode/Serializer.cs`
- `IronBrew2/Obfuscator/VM Generation/VMStrings.cs`
- `IronBrew2/Obfuscator/VM Generation/Generator.cs`
