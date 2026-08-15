namespace IronBrew2.Obfuscator
{
	public class ObfuscationSettings
	{
		public bool EncryptStrings;
		public bool EncryptImportantStrings;
		public bool ControlFlow;
		public bool BytecodeCompress;
		public int DecryptTableLen;
		public bool PreserveLineInfo;
		public bool Mutate;
		public bool SuperOperators;
		public int MaxMiniSuperOperators;
		public int MaxMegaSuperOperators;
		public int MaxMutations;
		public bool AntiDump;
		// 激进主动防御会修改执行器全局 API、扫描 debug/registry 并启动后台任务。
		// 不同执行器对 debug API 的实现差异很大，可能误判并触发冻结，因此默认关闭。
		// AntiDump guard 与 EnvironmentLock 仍然保留。
		public bool AggressiveDefense;
		public bool Noise;
		// 环境绑定：字节码 XOR 种子 = Hash(盐 | Roblox 环境指纹)。
		// 单一默认配置为 false，以保持 stock Lua 5.1 兼容；库调用方仍可显式启用。
		public bool EnvironmentLock;
		// 离线 dump/decompile 环境会在解密前看到此诱饵文字，并在阻断错误中显示。
		// 正常 Roblox 执行器环境不会打印它。
		public string Watermark;
		
		public ObfuscationSettings()
		{
			// 字符串已经包含在 DEFLATE + 流式 XOR 加密的字节码正文中。
			// 源码级解密闭包会引入不稳定的 upvalue/inlining，默认关闭。
			EncryptStrings = false;
			EncryptImportantStrings = false;
			ControlFlow = true;
			BytecodeCompress = true;
			DecryptTableLen = 500;
			PreserveLineInfo = false;
			// Mutation/SuperOperator 当前属于实验性变换，复杂闭包与分支中可能破坏寄存器引用。
			// 默认关闭；调用方确认兼容性后仍可显式开启。
			Mutate = false;
			SuperOperators = false;
			MaxMegaSuperOperators = 120;
			MaxMiniSuperOperators = 120;
			MaxMutations = 200;
			// 单一稳定配置沿用原 mid 行为：不注入执行器专用 guard 或环境 gate。
			AntiDump = false;
			AggressiveDefense = false;
			Noise = false;
			EnvironmentLock = false;
			Watermark = "Protected by IOI obf";
		}
	}
}