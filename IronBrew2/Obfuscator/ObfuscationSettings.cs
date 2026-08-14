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
		public bool Noise;
		// 环境绑定：字节码 XOR 种子 = Hash(盐 | Roblox 环境指纹)。
		// true(默认) = 离线/纯 Lua 环境解密出乱码；false = 兼容 plain Lua 测试。
		public bool EnvironmentLock;
		
		public ObfuscationSettings()
		{
			EncryptStrings = true;
			EncryptImportantStrings = true;
			ControlFlow = true;
			BytecodeCompress = true;
			DecryptTableLen = 500;
			PreserveLineInfo = false;
			Mutate = true;
			SuperOperators = true;
			MaxMegaSuperOperators = 120;
			MaxMiniSuperOperators = 120;
			MaxMutations = 200;
			AntiDump = true;
			Noise = true;
			EnvironmentLock = true;
		}
	}
}