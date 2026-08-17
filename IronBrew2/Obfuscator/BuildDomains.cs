using System;
using System.Collections.Generic;

namespace IronBrew2.Obfuscator
{
	/// <summary>
	/// Per-build domain separation for the serializer and generated VM.  These
	/// values are format coordinates rather than secrets: changing all of them on
	/// every generation prevents one build's payload parser and fixed numeric
	/// signatures from being reused unchanged against another build.
	/// </summary>
	public sealed class BuildDomains
	{
		private static readonly HashSet<uint> LegacyWords = new HashSet<uint>
		{
			0xA5C31F27u, 0x7F4A7C15u, 0x6D2B79F5u, 0xC4D29A6Bu,
			0x91E10DA5u, 0x3A75C9EFu, 0xD13C5E79u, 0x4B8F21A3u,
			0xE9274D6Bu, 113u, 911u, 1777u, 3253u, 0x5A5Au
		};
		private static readonly HashSet<ushort> LegacyEffectiveWords = new HashSet<ushort>
		{
			113, 911, 1777, 3253, 0x5A5A
		};

		public uint IntegrityDomain { get; }
		public uint BlockIntegrityDomain { get; }
		public uint FlowDomain { get; }
		public uint ChunkStateDomain { get; }
		public uint InstructionStateDomain { get; }
		public uint EnvelopeIntegrityDomain { get; }
		public uint EntropyDigestDomain { get; }
		public uint EnvelopeMaskDomain { get; }
		public uint ConstantIntegrityDomain { get; }
		public uint ConstantMaskDomain { get; }
		public uint PrototypeIntegrityDomain { get; }
		public uint OpcodePermutationDomain { get; }
		public uint SchemaPermutationDomain { get; }
		public uint ConstantTagPermutationDomain { get; }
		public uint BlockColumnDomain { get; }
		public uint CodeDataPermutationDomain { get; }
		public uint BlockFieldStride { get; }
		public ushort FlowVerifierMask { get; }
		public byte EntropyRecordKind { get; }
		public byte DataRecordKind { get; }

		public BuildDomains(BuildRandom random)
		{
			if (random == null) throw new ArgumentNullException(nameof(random));
			var used = new HashSet<uint>();
			IntegrityDomain = NextWord(random, used);
			BlockIntegrityDomain = NextWord(random, used);
			FlowDomain = NextWord(random, used);
			ChunkStateDomain = NextWord(random, used);
			InstructionStateDomain = NextWord(random, used);
			EnvelopeIntegrityDomain = NextWord(random, used);
			EntropyDigestDomain = NextWord(random, used);
			EnvelopeMaskDomain = NextWord(random, used);
			ConstantIntegrityDomain = NextWord(random, used);
			ConstantMaskDomain = NextWord(random, used);
			PrototypeIntegrityDomain = NextWord(random, used);

			// These values are reduced modulo 2^16 by the permutation/masking
			// recurrences.  Their effective words must therefore be independently
			// randomized too, rather than merely having distinct 32-bit containers.
			var effectiveWords = new HashSet<ushort>(LegacyEffectiveWords);
			OpcodePermutationDomain = NextEffectiveWord(random, used, effectiveWords);
			SchemaPermutationDomain = NextEffectiveWord(random, used, effectiveWords);
			ConstantTagPermutationDomain = NextEffectiveWord(random, used, effectiveWords);
			BlockColumnDomain = NextEffectiveWord(random, used, effectiveWords);
			CodeDataPermutationDomain = NextEffectiveWord(random, used, effectiveWords);
			// An odd non-zero stride avoids short slot-mask cycles modulo 2^16.
			BlockFieldStride = NextEffectiveWord(random, used, effectiveWords, true);

			ushort verifierMask;
			do verifierMask = (ushort)random.Next(1, 65536);
			while (effectiveWords.Contains(verifierMask));
			FlowVerifierMask = verifierMask;

			byte entropyKind;
			do entropyKind = (byte)random.Next(1, 256);
			while (entropyKind == 0xA7 || entropyKind == 0x5C);
			EntropyRecordKind = entropyKind;

			byte dataKind;
			do dataKind = (byte)random.Next(1, 256);
			while (dataKind == entropyKind || dataKind == 0xA7 || dataKind == 0x5C);
			DataRecordKind = dataKind;
		}

		private static uint NextWord(BuildRandom random, HashSet<uint> used)
		{
			uint value;
			do value = random.NextUInt32();
			while (value == 0 || LegacyWords.Contains(value) || !used.Add(value));
			return value;
		}

		private static uint NextEffectiveWord(
			BuildRandom random, HashSet<uint> used, HashSet<ushort> effectiveWords, bool requireOdd = false)
		{
			while (true)
			{
				uint value = random.NextUInt32();
				ushort effective = (ushort)value;
				if (value == 0 || effective == 0 || (requireOdd && (effective & 1) == 0) ||
					LegacyWords.Contains(value) || used.Contains(value) || effectiveWords.Contains(effective))
					continue;
				used.Add(value);
				effectiveWords.Add(effective);
				return value;
			}
		}
	}
}
