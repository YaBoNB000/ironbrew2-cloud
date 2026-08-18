using System;

namespace IronBrew2.Obfuscator
{
	/// <summary>
	/// Build-local arithmetic recipe shared by the serializer and generated VM.
	/// The recipe is self-contained rather than secret: its coordinates are
	/// deterministically coupled to independent BuildDomains and therefore change
	/// together with the payload grammar, integrity and state domains.
	/// </summary>
	public sealed class PayloadDerivationProfile
	{
		public uint BinderMultiplier { get; }
		public uint BinderIncrement { get; }
		public uint BinderInitial { get; }
		public uint BinderFinalXor { get; }
		public uint StreamMultiplier { get; }
		public uint StreamIncrement { get; }

		public PayloadDerivationProfile(BuildDomains domains)
		{
			if (domains == null) throw new ArgumentNullException(nameof(domains));

			BinderMultiplier = ((domains.FlowDomain ^ domains.PayloadFormatDomain) & 0xFFFFu) | 1u;
			if (BinderMultiplier == 1u) BinderMultiplier = 3u;
			BinderIncrement = ((domains.ChunkStateDomain ^ domains.DecodePipelineDomain) & 0xFFFFu) | 1u;
			BinderInitial = domains.EnvelopeMaskDomain ^ domains.PrototypeIntegrityDomain;
			BinderFinalXor = domains.IntegrityDomain ^ domains.BlockIntegrityDomain;

			// A == 1 (mod 4), C odd gives a full-period 32-bit LCG. Keeping A below
			// 2^20 also keeps every Lua 5.1 double multiplication exact below 2^53.
			uint streamSeed = (domains.EnvelopeMaskDomain ^ domains.DecodePipelineDomain) % 1048572u;
			StreamMultiplier = (streamSeed & 0xFFFFFCu) + 5u;
			StreamIncrement = ((domains.EntropyDigestDomain ^ domains.PayloadFormatDomain) & 0x3FFFFFFFu) | 1u;
		}

		public uint DeriveEnvironmentSeed(uint salt, uint attestationToken)
		{
			uint hash = BinderInitial;
			string transcript = salt.ToString() + "|" + attestationToken.ToString();
			foreach (char value in transcript)
				hash = unchecked(hash * BinderMultiplier + (byte)value + BinderIncrement);
			return hash ^ BinderFinalXor;
		}

		public uint AdvanceStream(uint state) =>
			unchecked(state * StreamMultiplier + StreamIncrement);
	}
}
