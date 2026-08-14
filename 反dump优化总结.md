# 反 dump 代码 VM 化 + 体积优化 — 完成总结

## 需求回顾

1. 反 dump 代码**必须在 VM 里**（不能是明文源码）—— 已还原为「编译成字节码 → 合并进主 chunk → 整体 XOR 加密进 blob」
2. **最大化压缩** —— 两处优化
3. **保证功能** —— 全部实测通过

## 改了什么（3 处）

### ① 还原为 VM 内执行（Program.cs）
撤销了上一版「源码前置」的做法，恢复原来的「defense + guard 编译成字节码 → 合并进主 chunk → 由 VM 解释执行」。
产物中反 dump 代码以**加密 blob 形式**存在，无任何明文源码（已 grep 验证）。

### ② 防御块字符串改为明文源码字面量（DefenseGenerator.cs）
原来每个 API 名都写成 `string.char(103,101,116,...)`，**每个字符 = 一个数字常量**，
导致 7KB 源码编译成 17KB 字节码（还触发大量 >255 常量的 opcode 变体，拖入额外 handler）。

关键认知：防御块编译成字节码后，字符串常量会被 Serializer 的**流式 XOR 整体加密**进 blob，
产物中本来就是密文。所以源码侧用明文 `"getscriptbytecode"` 完全安全。

→ defense 字节码 17KB → 11.4KB，且不再触发大量额外 opcode 变体。

### ③ 数据段编码 LZW+base92 → base91（Generator.cs）
字节码经流式 XOR 加密后是高熵数据，LZW 压缩率为负（越压越大），再 base92 又 +30%。
换成 **base91 字节流编码**（标准 basE91 算法），膨胀率 1.23x，且 VM 端解码器更小（去掉 LZW 解压器）。

Python 端 2000 组随机数据 round-trip 全过，实机混淆后运行结果与原始脚本完全一致。

## 效果

| 脚本 | 优化前 | 优化后 | 缩减 |
|---|---|---|---|
| 小脚本(118B) high | 130 KB | **59.2 KB** | **-54%** |
| 大脚本(10KB) high | 562 KB 级别 | **555 KB** | 反dump开销 119KB→17.5KB |

**反 dump 固定开销**（核心指标）：
- 小脚本：119KB → **48KB**（defense 用了小脚本没有的 ~90 个 opcode，需额外 handler）
- 大脚本：119KB → **17.5KB**（大脚本已覆盖所有 opcode，defense 几乎不增加 handler）

> 大脚本总膨胀率高的主因是 **EncryptStrings**：每个字符串都变成独立的解密函数 + 密文 blob，
> 60 个函数 × 若干字符串 = 数百个额外子函数。这是「字符串加密强度」与「体积」的权衡，与反 dump 无关。

## 功能验证（全部实测）

| 测试 | 结果 |
|---|---|
| high 纯 Lua 运行 | ✅ 环境绑定先拦截（种子错 → 字节码乱码） |
| high 模拟执行器+Roblox | ✅ 输出与原始脚本完全一致 |
| loadstring hook 拦截（2 个 dump 词） | ✅ 返回 nil（拦截） |
| loadstring 正常脚本 | ✅ 放行 |
| low 纯 Lua | ✅ 正常运行 |
| 大脚本(60函数) round-trip | ✅ 输出 `done 37820 610` 与原始一致 |
| 产物无明文反dump代码 | ✅ grep 验证 0 命中 |

## 改动文件

| 文件 | 改动 |
|---|---|
| `IronBrew2/Program.cs` | 还原为 VM 内合并执行（保留 EnvironmentLock 构造函数调用） |
| `IronBrew2/Obfuscator/AntiDump/DefenseGenerator.cs` | 字符串 string.char → 明文源码字面量 |
| `IronBrew2/Obfuscator/VM Generation/Generator.cs` | 新增 base91 编码器 + 替换 LZW 调用点 + 替换 VM 模板解压器 |

## 可选的进一步压缩（未做，需权衡安全性）

1. **关 Noise**（`settings.Noise=false`）：还能再省 ~18KB（59→41KB），但失去 handler 混淆噪声。
2. **降低 EncryptStrings 强度**：大脚本体积的主要来源，可加 `--no-encrypt-strings` 开关。
3. **handler 去重**：mutation/super-operator 产生大量语义重复的 handler，可合并。

## 注意

- 重新编译的 DLL 已更新到 `IronBrew2 CLI/bin/Release/net8.0/`，提交时需一并 push（GitHub Actions 直接运行仓库里的 DLL 不重编）。
- 产物在纯 Lua 里报错是正常的（环境绑定 + 反 dump），必须在 Roblox 执行器里测试。
