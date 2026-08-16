# Luraph Obfuscator v15.0：独立静态结构复核与 IronBrew2 加强依据

## 范围与方法

样本：`/home/user/uploads/luraph15.txt`

- 文件大小：171,753 bytes
- SHA-256：`3d528decf216d85566b637a24cf990d11f8f795e0b689431a8c6373786073e1a`
- 全程未执行样本；结论来自自有 Luau 词法器、根表字段切分、循环/条件边界分析和外壳字符替换的离线复现。
- 样本使用 Luau conditional expression、`+=` 和 `continue`，不能把 Lua 5.1 parser 的结果当作可靠结构证据。

本文区分“由当前源码独立确认”和“既有报告声称但当前材料不足以确认”的内容。

## 1. 外壳与根对象

顶层形态是一个大型 `setmetatable({...}, {})` 对象，最终调用其方法。可靠根字段统计如下：

| 类别 | 数量 |
|---|---:|
| 根字段总数 | 227 |
| function | 145 |
| reference/call | 69 |
| string | 8 |
| table | 3 |
| long string | 1 |
| parenthesized zero | 1 |

数字键区不是“127 个连续项”。实际只有 73 个已填数字字段，键范围为 1..126，中间有 53 个缺口；其中 69 个是库/API 引用，4 个是函数（`[18]`、`[63]`、`[73]`、`[96]`）。其余 154 个为命名字段。

全局词法统计：62,323 tokens、151 个 `function`、525 个 `return`、563 个 `if`、14 个 `while`、45 个 `continue`、17 个 `+=`。根表的 145 个函数中，127 个至少有一个以数值开头的返回；共找到 365 个这种返回和 136 个不同状态字面量。这支持“helper 以返回的下一状态串接，而不是普通直接调用”的判断。

### 对自动分析的影响

- 巨型对象把 reader、算术 helper、状态迁移、VM 和环境访问都放到同一 receiver 上，削弱基于函数名或模块边界的分类。
- 稀疏数字 bank 与命名 method 混用，使“数字索引一定是常量池/库表”的启发式不可靠。
- 但根表边界本身仍能被正确处理 Luau conditional expression 的词法器稳定恢复；它是工作量放大，不是不可逆边界。

## 2. `LPH:` 外壳的独立恢复

长字符串字段 `RC` 的内容长度为 74,566，前四字符是 `LPH:`。复现 `string.sub(RC, 5)` 和十字符替换表后得到：

- 输出长度：74,690 bytes
- Shannon entropy：6.40741362085066 bits/byte
- SHA-256：`2902b4a502de8a8dcaa061b6ca460af62807d0f50f9f23985c671475bb20bd0f`
- 原 body 里只有 32 个字符发生五字符展开。

因此既有报告的 74,690-byte 外壳解码长度和约 6.41 entropy 可以独立复现。这个步骤只是字符层 envelope 展开，不等于还原载荷、常量池或 VM 指令语义。

### 对自动分析的影响

- `LPH:`、固定 `gsub` 形态和替换字典是 loader fingerprint；一旦定位，第一层展开很容易自动化。
- 真正的阻力位于展开后的 reader、状态机和运行时改写，而不是这层字符替换本身。
- 防御设计不应把安全性押在一个固定 magic、固定 alphabet 或固定 loader AST 上。

## 3. 四个 VM 分发循环

四个循环全部位于数字字段函数 `[18]` 内，而不是四个互不相关的根函数。`[18]` 先建立列别名和执行 closure，再由模式状态 `S` 选择循环：

| `S` | selector | opcode column | 循环源码 offset | 静态 selector 范围 | handler slots |
|---:|---|---|---:|---|---:|
| 251 | `O` | `J[Q]` | 9,220 | 0..38 | 39 |
| 99 | `q` | `J[Q]` | 13,778 | 0..77 | 78 |
| 8 | `q` | `y[Q]` | 22,020 | 0..98 | 99 |
| 140 | `q` | `R[Q]` | 31,643 | 0..94 | 95 |

四棵树合计 311 个静态 handler slots。每棵都是以 `<`、`>=`、`==`、`~=` 组合成的二叉判定树，叶节点直接包含寄存器/PC/列操作。

### 对“199 个 opcode”的修正

当前源码不能支持“热点循环有 199 个 opcode”这一说法：`S == 8` 的 selector 完整覆盖 0..98，严格是 99 个静态 opcode ID。四个模式的静态槽总数则是 311。

“199”可能来自另一次运行时 trace、跨模式语义去重或报告笔误，但这些所需的 `optab8.json` 等产物不在当前工作区，不能把它当作已独立确认的事实。

### 对自动分析的影响

- 四模式与不同 selector column 破坏“找到一个 dispatcher 就得到完整 opcode map”的假设。
- 二叉树的阈值是连续的，自动工具仍可通过区间传播枚举每个叶节点；dispatcher 定位和 slot 数恢复并不困难。
- 叶节点直接暴露语义特征，因此只做 opcode number 随机化不足以阻止 handler 分类。

## 4. 运行时改写与 replay

四个循环中分别找到 3、6、6、6 个 `Q -= 1` replay 位置，共 21 个。它们通常：

1. 从 reader `b:vL(...)` 取得新值；
2. 写回 `J[Q]`、`m[Q]`、`R[Q]`、`y[Q]` 等指令列；
3. 令 `Q -= 1`；
4. 在循环尾部统一 `Q += 1`，从而用新内容重跑当前位置。

第一模式确实存在 `O == 30` 的四列改写 handler，但“opcode 30 是整个 VM 唯一/通用自解密操作”不准确；多个模式有多个 replay/decode handler，编号也不相同。

### 对自动分析的影响

- 对初始数组做一次性 dump 会遗漏随后 materialize 的指令。
- 符号执行必须把 opcode/operand columns 当作可写状态，并建模“改写后同 PC replay”，不能把指令内存视为 immutable IR。
- 分支中的 32-bit MBA 很多可归一化，但 reader state、列写回和 replay 联合后会迅速扩大路径状态。
- 动态 tracer 若处在真实可通过 gate 的环境，仍可在每次 replay 后快照稳定 IR；这不是密码学不可见性。

## 5. 常量、handler 分类和 CFG 的实际难点

| 自动化目标 | 样本造成的阻力 | 仍可利用的稳定点 |
|---|---|---|
| loader/decoder 识别 | 大根表、method indirection、continuation state | `LPH:`、`RC` 长串、`sub` + `gsub` + reader 链 |
| 常量池恢复 | 字符串不以普通源码 literal 出现；reader 与运行时列状态耦合 | 第一层 envelope 可完全离线展开；reader helper 可按调用图归类 |
| handler 分类 | 四模式、311 槽、列别名、MBA、运行时改写 | 叶节点仍直接操作寄存器表、PC 和宿主库；数据流特征明显 |
| opcode 映射 | selector 来自三个不同列；mapping 可被 replay 改写 | 每棵判定树的整数区间可静态枚举 |
| dispatcher 识别 | dispatcher 嵌在 `[18]` 的 outer loop/closure 中 | `while true` + `local q = column[Q]` + 尾部 PC 更新是强结构特征 |
| 符号执行 | 21 个 replay 点、可写指令内存、reader state、32-bit MBA | 大量 MBA 可先常量折叠；模式和 selector 范围有限 |
| CFG 重建 | `Q` 不只线性递增；handler 能跳转、改写和重跑 | 把 `(S,Q,column-state)` 作为状态后仍可逐步构图 |

既有报告关于 executor 指纹、静默空转和运行时常量的结论依赖其外部 emulator/trace 产物。当前源码表面没有 `identifyexecutor` 或 `loadstring` literal；它们可能位于已编码数据中，但仅凭这份静态源码不能重新证明具体 gate 行为。

## 6. 本轮 IronBrew2 加强

本轮没有复制 Luraph 的固定 magic 或巨型根表，而是针对 IronBrew2 原先最稳定的“opcode 比较树叶节点直接等于 handler”特征修改 `Generator.cs`：

1. opcode 判定树只选择 masked entry token 和 entry lane，不再直接拥有 handler；
2. 每个 opcode 生成独立的 3..5 节点 continuation path；
3. 构建随机产生 3..5 lanes，节点跨 lane 分布，相邻节点不得处于同一 lane；
4. 第一条 path 覆盖全部 lanes；
5. 每节点使用唯一、非零、完整 32-bit token，并在每次 XOR 后显式做 unsigned-32 normalization，兼容返回有符号结果的 bit library；
6. state 由 invocation-local `Flow`、PC、prototype keys 和 block-field derivation 绑定的 mask 保护；
7. 每次迁移先递增 step，再以 flow-derived odd salt 重算 step mask；
8. selector、lane 顺序、节点顺序、条件形态、token 算术拼写和图拓扑均随构建改变；
9. handler 仍在原 `Wrap` 词法作用域，保留对 `InstrPoint`、`Top`、upvalues 和函数级 `return` 的原语义；
10. 未把 handler 提升为可单独枚举/调用的 Lua function。

另行审阅了 `Obfuscator/Opcodes/*.cs` 的控制转移：唯一的 `break` 位于 `OpNewStk` 自己的 `for` 循环内，不会错误退出新增 continuation loop；函数级 `return` 只来自 Return/TailCall 家族并应继续退出 `Wrap`。完整语义套件也覆盖了这些路径。

这同时提高了 handler 分类、opcode 到 handler 映射和静态 CFG 归一化的成本。攻击者必须先恢复 flow-bound mask、entry 映射、lane membership 和 continuation edges，才能把 selector leaf 与终端 handler 对齐。

### 限制

这是结构性工作量放大，不是不可逆保护。当前测试故意实现了一个静态 graph recovery verifier；它证明 token 表达式在未压缩 VM 中仍可被足够专门的工具恢复。真正收益在于：

- 旧的通用“比较树 leaf body fingerprint”脚本不再直接适用；
- 每次 build 的图和名字不同；
- opcode selector、terminal handler 和运行时 flow state 之间多了一层需要联合分析的状态关系；
- 与已有 authenticated envelope、constant capsules、columnar IR、lazy block decode、route token 和严格 executor attestation 叠加，而不是替代它们。

## 7. 回归约束

`tests/runtime_layout.py` 现会恢复并验证：

- opcode count 与 entry 数一致；
- 3..5 完整 lanes；
- 每 opcode 3..5 节点；
- token 唯一、无环、不合流、无不可达节点；
- entry lane 和 transition target lane 正确；
- 相邻节点不在同 lane；
- 至少一条恢复出的 path 覆盖全部 lanes（生成器保证 opcode 0 path 满足此条件）；
- step mask 在循环入口及每次迁移后重算；
- salt factor 为非零奇数；
- mask 绑定当前 `Flow` state；
- terminal 数等于 opcode 数；
- stable dispatcher identifier 不泄漏；
- 两次独立构建的 continuation fingerprint 不同。

本轮未改变 executor gate 判据、attestation transcript/token/seal 或 sink 响应；此前按兼容性结果删除的六个根 sink 合同没有恢复，严格 enforcement 继续启用。
