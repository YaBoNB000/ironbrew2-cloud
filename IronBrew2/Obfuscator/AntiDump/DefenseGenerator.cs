using System;

namespace IronBrew2.Obfuscator.AntiDump
{
	/// <summary>
	/// Compatibility shim for the removed legacy defense injector. The former
	/// implementation rewrote executor globals, scanned registries in background
	/// tasks and responded with unbounded allocation/infinite loops. Runtime defense
	/// now lives inside the VM and uses a bounded silent-decoy response instead.
	/// </summary>
	[Obsolete("Legacy global-hook defense was removed; enable ObfuscationSettings.AntiDump instead.")]
	public static class DefenseGenerator
	{
		public static string GenerateSourceBlock() => string.Empty;
	}
}
