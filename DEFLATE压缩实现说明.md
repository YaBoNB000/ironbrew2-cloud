# DEFLATE 字节码压缩实现说明

## 做了什么

把字节码压缩算法从 LZ77 升级为 **DEFLATE（RFC 1951，标准 zlib 格式）**。

| 端 | 实现 |
|---|---|
| C# 混淆器 | `System.IO.Compression.DeflateStream`（.NET 内置，零第三方依赖） |
| Lua VM 端 | 手写 pure-Lua inflate 解压器（~130 行，支持 fixed/dynamic Huffman + stored block） |

数据流不变：**明文字节码 → DEFLATE 压缩 → 流式 XOR 加密 → base91**（压缩仍在加密前）。

## 实测体积（数据段压缩率，同一次混淆 dump 对比）

| 脚本 | 明文字节码 | DEFLATE 后 | 压缩率 |
|---|---|---|---|
| big（80 函数） | 23150 B | 6478 B | **0.28x** |
| 多组随机/文本/重复用例 | — | — | 全部 round-trip 一致 |

对比之前的 LZ77（0.45x），DEFLATE 数据段再省 ~38%。最终产物（high 档）实测比 LZ77 小约 2%。

> 说明：最终产物收益是 2% 量级而非 38%，因为数据段只占总产物的一小部分
> ——膨胀大头是 VM 的 opcode 解释器 handler 和 EncryptStrings 密文，它们不在
> 数据段压缩范围内。数据段本身确实省了 38%。

## 调试中发现的 2 个关键 bug（都已修复并验证）

1. **LZ4 offset 顺序**（LZ77 时代遗留，DEFLATE 无关）：已在上一轮修复。

2. **DEFLATE distance code 位序**（本次核心 bug）：
   DEFLATE 规范里 **Huffman 码是 MSB-first 打包，但 extra bits 是 LSB-first**。
   我最初的实现里，fixed block 的 5 位 distance code 用了 LSB-first 的 `gb(5)` 读取，
   导致 distance 解错。之前用随机/文本用例测试没暴露（那些数据恰好是 dynamic block，
   distance 走 `dec(dtbl)` Huffman 解码），真实字节码触发 fixed block 才暴露。
   修复：新增 `gbr(n)`（MSB-first 读位），fixed distance code 改用 `gbr(5)`。

   修复后验证：2000+ 组随机数据 + 真实混淆字节码，全部 round-trip 一致。

## 功能验证（全部实测通过）

| 测试 | 结果 |
|---|---|
| low 档纯 Lua 运行 | ✅ 输出正确 |
| high 档纯 Lua（环境绑定） | ✅ 拦截（乱码报错） |
| high 档模拟执行器环境（bench/strheavy/big 三脚本） | ✅ 输出与原始逐字节一致 |
| 反 dump loadstring hook（2 词拦截 / 正常放行 / 单词不拦） | ✅ 全部符合预期 |
| inflate 解压正确性（5 次独立混淆 dump 对比） | ✅ 5/5 一致 |

## 改动文件

| 文件 | 改动 |
|---|---|
| `IronBrew2/Bytecode Library/Bytecode/Lz77.cs` | **删除**（被 DEFLATE 取代） |
| `IronBrew2/Bytecode Library/Bytecode/Serializer.cs` | LZ77 → `DeflateStream`（加 `using System.IO.Compression`） |
| `IronBrew2/Obfuscator/VM Generation/VMStrings.cs` | `lz77d` → 手写 inflate（含 `gbr` MSB-first 读位） |

其余（base91 + 流式 XOR + 环境绑定 + 反 dump + header flag）**完全不变**。

## 与其他语言的关系

- C# `DeflateStream` = Python `zlib` = Java `Deflater`，都是 DEFLATE/RFC 1951，
  产物可以跨语言交叉验证（实现过程中用 Python zlib 验证了 Lua inflate 的正确性）。

## 要 push 的文件

重新编译的 DLL 在 `IronBrew2 CLI/bin/Release/net8.0/`，源码改动在
`Serializer.cs`、`VMStrings.cs`（+ 删除 `Lz77.cs`），一起提交即可。
