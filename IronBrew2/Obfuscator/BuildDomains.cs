using System;
using System.Collections.Generic;
using System.Security.Cryptography;

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
		public uint BlockFieldStride { get; }
		public ushort FlowVerifierMask { get; }
		public byte EntropyRecordKind { get; }
		public byte DataRecordKind { get; }

		public BuildDomains()
		{
			var used = new HashSet<uint>();
			IntegrityDomain = NextWord(used);
			BlockIntegrityDomain = NextWord(used);
			FlowDomain = NextWord(used);
			EnvelopeIntegrityDomain = NextWord(used);
			EntropyDigestDomain = NextWord(used);
			EnvelopeMaskDomain = NextWord(used);
			ConstantIntegrityDomain = NextWord(used);
			ConstantMaskDomain = NextWord(used);
			PrototypeIntegrityDomain = NextWord(used);

			// These values are reduced modulo 2^16 by the permutation/masking
			// recurrences.  Their effective words must therefore be independently
			// randomized too, rather than merely having distinct 32-bit containers.
			var effectiveWords = new HashSet<ushort>(LegacyEffectiveWords);
			OpcodePermutationDomain = NextEffectiveWord(used, effectiveWords);
			SchemaPermutationDomain = NextEffectiveWord(used, effectiveWords);
			ConstantTagPermutationDomain = NextEffectiveWord(used, effectiveWords);
			BlockColumnDomain = NextEffectiveWord(used, effectiveWords);
			// An odd non-zero stride avoids short slot-mask cycles modulo 2^16.
			BlockFieldStride = NextEffectiveWord(used, effectiveWords, true);

			ushort verifierMask;
			do verifierMask = (ushort)RandomNumberGenerator.GetInt32(1, 65536);
			while (effectiveWords.Contains(verifierMask));
			FlowVerifierMask = verifierMask;

			byte entropyKind;
			do entropyKind = (byte)RandomNumberGenerator.GetInt32(1, 256);
			while (entropyKind == 0xA7 || entropyKind == 0x5C);
			EntropyRecordKind = entropyKind;

			byte dataKind;
			do dataKind = (byte)RandomNumberGenerator.GetInt32(1, 256);
			while (dataKind == entropyKind || dataKind == 0xA7 || dataKind == 0x5C);
			DataRecordKind = dataKind;
		}

		private static uint NextWord(HashSet<uint> used)
		{
			uint value;
			do value = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(sizeof(uint)), 0);
			while (value == 0 || LegacyWords.Contains(value) || !used.Add(value));
			return value;
		}

		private static uint NextEffectiveWord(
			HashSet<uint> used, HashSet<ushort> effectiveWords, bool requireOdd = false)
		{
			while (true)
			{
				uint value = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(sizeof(uint)), 0);
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
