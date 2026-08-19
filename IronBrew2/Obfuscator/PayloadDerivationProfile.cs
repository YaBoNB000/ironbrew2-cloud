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

		public uint[] DeriveEvidenceWords(uint attestationToken)
		{
			return new[]
			{
				unchecked(attestationToken * 65599u + 0x9E3779B9u),
				unchecked(attestationToken * 48271u + 0x6D2B79F5u),
				unchecked((attestationToken + 0xA5C3F1E7u) * 131071u + 0x7F4A7C15u),
				unchecked((attestationToken + 0xC4D29A6Bu) * 524287u + 0xC2B2AE35u)
			};
		}

		private uint[] DeriveBindingWords(uint salt, uint attestationToken)
		{
			uint[] evidence = DeriveEvidenceWords(attestationToken);
			uint[] words =
			{
				BinderInitial ^ evidence[0],
				BinderInitial ^ 0xA5C3F1E7u ^ evidence[1],
				BinderFinalXor ^ 0x6D2B79F5u ^ evidence[2],
				salt ^ evidence[3] ^ 0x9E3779B9u
			};
			string transcript = salt.ToString() + "|" + string.Join("|", evidence);
			uint index = 1;
			foreach (char value in transcript)
			{
				words[0] = unchecked(words[0] * BinderMultiplier + (byte)value + BinderIncrement);
				words[1] = unchecked(words[1] * (BinderMultiplier + 2u) + (byte)value + BinderIncrement + index * 17u);
				words[2] = unchecked(words[2] * 65599u + (byte)value + (words[0] >> 16));
				words[3] = unchecked(words[3] * 48271u + (byte)value + (words[1] & 0xFFFFu) + index);
				index++;
			}
			return words;
		}

		private static uint Rotate16(uint value) => (value << 16) | (value >> 16);

		public uint DeriveEnvironmentSeed(uint salt, uint attestationToken)
		{
			uint[] words = DeriveBindingWords(salt, attestationToken);
			return words[0] ^ Rotate16(words[1]) ^ words[2] ^ words[3] ^ BinderFinalXor;
		}

		public uint DerivePayloadBinding(uint salt, uint attestationToken)
		{
			uint[] words = DeriveBindingWords(salt, attestationToken);
			return unchecked((words[0] ^ words[1]) + (words[2] ^ words[3]) + 0xC2B2AE35u);
		}

		/// <summary>
		/// Derives an outer-authenticator key in a separate fold of the four-word
		/// binding state. Even if an authenticator implementation leaks or is
		/// inverted, its key is not the state that decrypts the envelope.
		/// </summary>
		public uint DeriveOuterIntegrityKey(uint salt, uint attestationToken)
		{
			uint[] words = DeriveBindingWords(salt, attestationToken);
			uint result = words[1] ^ Rotate16(words[2]) ^ words[3] ^ BinderFinalXor ^ 0xC4D29A6Bu;
			return result == 0 ? 0xC4D29A6Bu : result;
		}

		public uint AdvanceStream(uint state) =>
			unchecked(state * StreamMultiplier + StreamIncrement);
	}
}
