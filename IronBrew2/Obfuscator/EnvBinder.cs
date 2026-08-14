using System;
using System.Text;

namespace IronBrew2.Obfuscator
{
    /// <summary>
    /// 环境绑定：让字节码解密密钥依赖运行时环境指纹。
    ///
    /// 原理（两层）：
    ///   1. 混淆时（C# 端）生成随机盐 Salt，并预知探针在真 Roblox 环境中的确定性结果
    ///      ExpectedFingerprint；真正的 XOR 种子 = Hash(Salt + "|" + 指纹)。
    ///   2. 运行时（Lua 端，VM 模板里）执行同一份探针得到实际指纹，再派生种子。
    ///      真环境 → 种子一致 → 解密成功；
    ///      离线 dump / 纯 Lua / unluac 环境 → 探针失败或结果不同 → 种子错 → 全盘乱码。
    ///
    /// 注意：这防的是"离线反编译"，不能防止攻击者在真 Roblox 环境里 hook。
    /// </summary>
    public class EnvBinder
    {
        public uint   Salt { get; private set; }
        public uint   ExpectedFingerprint { get; private set; }

        /// <summary>
        /// 嵌入 VM 模板的种子派生代码，产出 XorSeed（写进变量 Xs）。
        /// 会经过 Generator 的 T() 标识符随机化，所以代码里只用 identKeys 里已有的
        /// 标识符（Byte）或全局（pcall/tostring/typeof/...）。
        /// </summary>
        public string SeedDeriveLua { get; private set; }

        /// <summary>EnvironmentLock 关闭时用：直接以头部值为种子（兼容 plain Lua 测试）。</summary>
        public const string PlainSeedLua = "local Xs = __ib2Head;";

        public EnvBinder()
        {
            var r = new Random();

            Salt = (uint)(r.Next(1, int.MaxValue) ^ (r.Next(1, int.MaxValue) << 1));
            if (Salt == 0)
                Salt = 0x9E3779B9u;

            // 探针在真 Roblox 环境中的确定性结果。全部取"字符串常量"型返回值，
            // 避免 tostring(浮点数) 的格式差异导致指纹不一致。
            // 注意：改探针时这里必须与 SeedDeriveLua 里的探针保持一致。
            ExpectedFingerprint = ComputeFingerprint(new[]
            {
                "Instance",   // typeof(Instance.new('Part'))
                "Players",    // game:GetService('Players').ClassName
                "Vector3",    // typeof(Vector3.new())
                "table",      // typeof(setmetatable({}, {}))
            });

            SeedDeriveLua = BuildSeedDeriveLua()
                .Replace("__IB2_EXPECTED_FP__", ExpectedFingerprint.ToString());
        }

        /// <summary>
        /// 多项式哈希。C# 用 uint（自动 mod 2^32），Lua 端用 `% 4294967296`，
        /// 乘数 31 保证中间值 &lt; 2^53（Lua double 精确，无精度损失）。已实测两端一致。
        /// </summary>
        public static uint ComputeFingerprint(string[] parts) =>
            Hash(string.Join("|", parts));

        public static uint Hash(string s)
        {
            uint h = 0;
            foreach (byte b in Encoding.UTF8.GetBytes(s))
                h = h * 31u + b;   // uint 自动 mod 2^32
            return h;
        }

        /// <summary>最终 XOR 种子：混淆端用 ExpectedFingerprint，运行端用实际指纹。</summary>
        public uint DeriveSeed(uint fingerprint) =>
            Hash(Salt.ToString() + "|" + fingerprint.ToString());

        private string BuildSeedDeriveLua() => @"
-- Environment lock: read salt -> run probe -> derive XOR seed.
-- 诱饵水印：正常环境不打印；dump/decompile 工具会在代码或阻断错误里看到。
local __ib2Watermark = '__IB2_WATERMARK__'
-- The probe returns a deterministic value in a real Roblox env.
local function __ib2Probe()
    local ok, r = pcall(function()
        local p = {}
        p[1] = typeof(Instance.new('Part'))
        p[2] = game:GetService('Players').ClassName
        p[3] = typeof(Vector3.new())
        p[4] = typeof(setmetatable({}, {}))
        local s = table.concat(p, '|')
        local h = 0
        for i = 1, #s do
            h = (h * 31 + Byte(s, i)) % 4294967296
        end
        return h
    end)
    if ok and r == __IB2_EXPECTED_FP__ then return r end
    error(__ib2Watermark .. ' | dump blocked', 0)
end
-- seed = Hash(Salt .. '|' .. fingerprint). Matches C# side only in a real env.
local __ib2SeedStr = tostring(__ib2Head) .. '|' .. tostring(__ib2Probe())
local Xs = 0
for __ib2i = 1, #__ib2SeedStr do
    Xs = (Xs * 31 + Byte(__ib2SeedStr, __ib2i)) % 4294967296
end
";
    }
}
