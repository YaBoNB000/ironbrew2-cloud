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
		// Enables the VM-integrated Luau capability probes, silent decoy routing and
		// invocation-local ephemeral instruction-block cache.
		public bool AntiDump;
		// Kept for source compatibility. The destructive global-hook implementation
		// was removed; this flag no longer injects executor hooks or background scans.
		public bool AggressiveDefense;
		public bool Noise;
		// Strict brand-neutral Roblox executor attestation. The fixed profile requires
		// this together with AntiDump; plain Lua/Luau and Studio enter the silent sink.
		public bool EnvironmentLock;
		// Watermark retained for source compatibility.
		public string Watermark;
		
		public ObfuscationSettings()
		{
			// Strings already live inside the DEFLATE + streaming-XOR bytecode body.
			EncryptStrings = false;
			EncryptImportantStrings = false;
			ControlFlow = true;
			BytecodeCompress = true;
			DecryptTableLen = 500;
			PreserveLineInfo = false;
			// The fixed profile uses only bounded straight-line (2..6 instruction)
			// fusions; mutation and legacy mega operators remain disabled.
			Mutate = false;
			SuperOperators = true;
			MaxMegaSuperOperators = 0;
			MaxMiniSuperOperators = 24;
			MaxMutations = 200;
			AntiDump = true;
			AggressiveDefense = false;
			Noise = false;
			EnvironmentLock = true;
			Watermark = "Protected by IOI obf";
		}
	}
}
