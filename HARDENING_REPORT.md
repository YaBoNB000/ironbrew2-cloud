# IronBrew2 加固实施报告

日期：2026-08-15  
基线：`main` / `d6896333f26dc80a8a8c93aa7ff111bd3f9dab42`

## 1. 实施原则

本轮没有复制或声称复刻 Luraph 的私有实现。实际采用的是可独立实现的通用架构思路：分层恢复、按 prototype 变化、位置相关的指令编码、常量二次编码、完整性耦合和 VM 生成多态。

优先级是语义正确性与 Lua 5.1 兼容性。仓库中已知不稳定的 Mutation、SuperOperator、源码字符串解密闭包及激进 API hook 没有在固定配置中重新启用。

## 2. 已完成的源码改动

### 2.1 v2 payload 与完整性

`Serializer.cs` 与 `VMStrings.cs` 已同步切换到 v2 格式：

```text
4B head/salt | 4B integrity tag | 1B version+feature flags | encrypted body
```

- 高 4 位为格式版本，目前必须为 `2`。
- 低位 bit 0 表示 DEFLATE；未知 feature bits 会被拒绝。
- 完整性值绑定格式/feature 字节、加密正文和运行 seed，并在解密、解压及反序列化前验证。
- 修改加密 payload 会以 `invalid protected payload` 失败。
- K1/K2 不再位于固定明文头。

该完整性机制用于检测损坏和提高直接 patch 成本；算法和验证代码都交付给客户端，因此不是不可伪造的服务端信任根。

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
- 字符串常量在外层 payload 加密之外，再按 prototype keys 和 1-based 常量索引逐字节编码。
- 指令字段允许排在常量字段之前：VM 先保留 constant mask，五类字段读取完毕后再解析 A/B/C 的常量引用。
- prototype 的临时常量 decode cache 在引用绑定后清空；未引用常量可回收，未执行子 prototype 的常量不会在启动时恢复。
- 测试输入中的字符串、嵌套闭包标签和二进制字符串没有以源码字面量出现在生成结果中。

### 2.4 子 prototype 按需恢复

- 子 prototype 在父 prototype 的 Functions 字段中增加长度 framing。
- 初次反序列化只保留每个子 prototype 的 opaque byte slice，不递归展开其指令、常量和后代。
- `OP_CLOSURE` 首次访问时通过 `GetProto` 切换到该 slice 反序列化，随后把结果缓存回父 prototype 表。
- root prototype 恢复后立即释放完整解密 body；后续仅保留尚未使用的子 prototype slices。

当前延迟粒度是 prototype；basic-block 粒度的按需解码仍属于后续工作。

### 2.5 handler 与 dispatch leaf 结构多态

- `Generator.cs` 增加小型 Lua 词法扫描器，只在 handler 的顶层分号处分段；扫描时跳过引号/长字符串、行/长注释，并跟踪圆括号、table/index 以及 function/if/loop/repeat/do 块。
- 每个 canonical handler 独立选择 raw、`do` scope、`Enum == Enum` 恒真 guard 或保持原顺序的 prefix/suffix 嵌套模板。
- prefix 位于外层 scope，后续 suffix 仍能访问 prefix 声明的 local；带顶层 `return`/`break` 的前缀不会被选为切分点。
- dispatcher 的双 handler leaf 保持两个 canonical handler 独立，不融合 bytecode 指令；leaf 会在 `>`、`==`、`~=` 和嵌套恒真 guard 选择形式间变化，因此不属于 Phase 3 superoperator。
- 递归 dispatcher 的右分支依靠 `else` 与子 leaf 的 `if` 拼成 `elseif`；所有 leaf 模板都保持以 `if` 开头，避免破坏生成语法。

这些变换改变生成源码结构而不改变指令执行次序、寄存器语义或 opcode bank。handler 仍是每次构建生成一组，并非按 prototype 复制一整套 VM。

### 2.6 随机源

- prototype keys、salt、XOR seed、shuffle 和随机选择改用操作系统 CSPRNG。
- 仍需要 `System.Random` 接口的代码生成器、控制流及可选变换，改为使用 CSPRNG seed，避免同一时钟窗口产生相同序列。
- 清理了不再使用的旧 XOR key 和全局常量映射字段。

### 2.7 EnvironmentLock

- salt 与最终序列化 seed 的关系已核对：开启时头部写 salt，构建端和运行端都以相同 fingerprint 派生 seed；关闭时头部直接写随机 seed。
- 完整性验证使用最终 seed，因此错误环境会在正文恢复前失败。
- 环境探针属于可选的 Roblox capability gate，而不是秘密；固定 CLI 配置不启用它。若库调用方显式开启，预期 fingerprint 和算法仍随客户端交付，可被有能力的攻击者 patch。

### 2.8 line info 与 Linux 工具链

- line-info wrapper 从错误的 `Chunk[7]` 修正为 `Chunk[4]`。
- LuaSrcDiet 的 `LUA_PATH` 由 C# 显式设置，不再依赖调用者当前目录。
- 最终 minifier 非零退出码现在会被当作构建失败。

### 2.9 单一 CLI 配置

CLI、Windows 拖放脚本和 GitHub Actions 均取消强度档位，统一使用原 `mid` 的稳定行为：

| 设置 | 固定值 |
|---|---:|
| v2 schema / prototype keys / 字段编码 / 常量内层编码 / 完整性检查 | 开 |
| handler / 双 handler dispatch leaf 结构多态 | 开 |
| ControlFlow | 开 |
| DEFLATE | 开 |
| AntiDump / EnvironmentLock | 关 |
| Mutation / SuperOperator / 源码字符串转换 | 关 |
| AggressiveDefense / Noise | 关 |

CLI 只接受 `<input.lua>` 和可选的 `--line-info`；旧 `--strength` 与旧覆盖开关会作为未知参数拒绝。`ObfuscationSettings` 构造器默认值也已同步到同一行为，避免非 CLI 调用回退到旧的环境 gate。

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
| 固定配置与原脚本差分 | 通过 |
| 固定配置随机构建 | 20/20 通过 |
| 旧 `--strength` 参数拒绝 | 通过，退出码 2 |
| prototype-local schema / tag / opcode bank 随机构建 | 通过 |
| handler 等价模板 / 双 handler leaf 随机结构与 Lua 语法 | 20/20 通过 |
| nested closure / upvalue / lazy child prototype / closure 伪指令 | 通过 |
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
- `tests/line_error.lua`
- `tests/signed_bit_runner.lua`
- `tests/run_linux_tests.sh`

## 4. 仍存在的边界

1. 这是客户端混淆，不是密码学保密。seed、fingerprint、VM、prototype banks 和校验逻辑最终都在攻击者可执行的客户端中。
2. 字段 schema、常量 tag 与 opcode bank 虽然按 prototype 变化，但 bank 会在运行时派生；有能力的分析者仍可 hook dispatch 或 `GetProto` 收集已执行 prototype。
3. 按需恢复目前以 prototype 为粒度；root prototype 仍在启动时恢复，已执行 prototype 的字符串常量会绑定到其指令操作数。basic-block 和使用点级常量延迟尚未实现。
4. handler 拆分/合并/等价模板已经完成，但每次构建仍只生成一组 canonical handler；它们不是按 prototype 复制，也还没有依赖真实 CFG 入口状态的 bank/state。
5. Mutation/SuperOperator 没有被本轮宣告为稳定；在没有更大差分语料前不应纳入固定配置。
6. 前端仍是 Lua 5.1 bytecode，不是完整 Luau 前端。Roblox/Luau 专有语法需要单独支持。
7. 尚未接入 CI，也尚未完成大程序、性能、内存和体积基准。

后续工作按 `HARDENING_PLAN.md` 的 Phase 2–4 继续：basic-block 延迟解码、IR/CFG 级状态耦合、性能基准及多平台 CI。
