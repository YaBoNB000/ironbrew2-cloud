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
		// Optional strict Roblox fingerprint binding. This is independent of AntiDump
		// and remains opt-in because it intentionally rejects non-Roblox runtimes.
		public bool EnvironmentLock;
		// Watermark used only by the optional strict EnvironmentLock implementation.
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
			// Mutation/SuperOperator remain experimental and are not part of the fixed profile.
			Mutate = false;
			SuperOperators = false;
			MaxMegaSuperOperators = 120;
			MaxMiniSuperOperators = 120;
			MaxMutations = 200;
			AntiDump = true;
			AggressiveDefense = false;
			Noise = false;
			EnvironmentLock = false;
			Watermark = "Protected by IOI obf";
		}
	}
}
