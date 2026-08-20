using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;
using IronBrew2.Obfuscator.Control_Flow;

namespace IronBrew2.Bytecode_Library.Bytecode
{
	public class Serializer
	{
		private const byte FormatVersion = 5;
		private const byte BasicBlockFeature = 2;
		private const byte DispatcherFlatteningFeature = 4;
		private const byte EntropyEnvelopeFeature = 8;
		private const int EntropyMinBytes = 64 * 1024;
		private const int EntropyMaxBytes = 96 * 1024;
		private const int PayloadPageMinBytes = 2048;
		private const int PayloadPageMaxBytes = 6144;

		private sealed class EntropyRecord
		{
			public byte Kind { get; init; }
			public ushort Ordinal { get; init; }
			public byte[] Data { get; init; }
		}

		private sealed class ChunkSuccessor
		{
			public int Destination { get; init; }
			public uint WrappedEntryState { get; init; }
			public uint WrappedChunkState { get; init; }
		}

		private readonly ObfuscationContext _context;
		private readonly ObfuscationSettings _settings;
		private readonly BuildRandom _random;
		private readonly Encoding _luaEncoding = Encoding.GetEncoding(28591);

		public Serializer(ObfuscationContext context, ObfuscationSettings settings)
		{
			_context = context;
			_settings = settings;
			_random = context.Seed.GetStream("payload.serializer");
		}

		/// <summary>
		/// v5 顶层格式（固定 9 字节头）：
		///   head/salt 4B | integrity tag 4B | version+flags 1B | encrypted envelope
		/// 压缩后的真实 body 被拆为多个 data records，并与 64–96 KiB CSPRNG entropy
		/// records 交错。entropy digest 同时派生内层 body mask；物理 record 顺序由独立
		/// envelope tag 认证，因此删除、修改或重排 record 都不能退化为可移除 padding。
		/// v5 outer authenticator uses a separately derived integrity key and compresses
		/// two coupled 32-bit lanes instead of exposing the stream seed through an
		/// invertible polynomial accumulator. It remains a client-side keyed
		/// corruption/tamper check, but the tag is no longer an O(n) algebraic
		/// seed-recovery oracle.
		/// 每个 prototype 和完整 block manifest 都有独立认证；常量以延迟恢复 capsule
		/// 保存，只有进入引用它的 block 时才恢复到 invocation-local cache。
		/// </summary>
		public byte[] SerializeLChunk(Chunk chunk)
		{
			byte[] plain = SerializeBody(chunk);
			// The serialized VM body is framed before compression. Each bounded page is
			// an independent raw-DEFLATE stream, so the runtime never needs the complete
			// compressed stream or the complete plaintext VM buffer.
			byte[] envelope = WrapEntropyEnvelope(plain, _context.XorSeed, _settings.BytecodeCompress);

			uint state = _context.XorSeed;
			byte[] encrypted = new byte[envelope.Length];
			for (int i = 0; i < envelope.Length; i++)
			{
				encrypted[i] = (byte)(envelope[i] ^ (byte)(state >> 24));
				state = _context.PayloadDerivation.AdvanceStream(state);
			}

			uint head = _settings.EnvironmentLock ? _context.Binder.Salt : _context.XorSeed;
			byte flags = (byte)((FormatVersion << 4) | BasicBlockFeature | DispatcherFlatteningFeature |
			                    EntropyEnvelopeFeature | (_settings.BytecodeCompress ? 1 : 0));
			// Bind both the format/feature byte and encrypted body. This is tamper/corruption
			// detection, not a client-side cryptographic trust root.
			uint integrity = ComputeIntegrity(encrypted, _context.OuterIntegrityKey, flags);

			var output = new List<byte>(encrypted.Length + 9);
			foreach (OuterHeaderField field in _context.PayloadFormat.OuterHeaderOrder)
			{
				switch (field)
				{
					case OuterHeaderField.Head: WriteUInt32(output, head); break;
					case OuterHeaderField.Integrity: WriteUInt32(output, integrity); break;
					case OuterHeaderField.Flags: output.Add(flags); break;
					default: throw new InvalidOperationException("Unknown outer payload header field.");
				}
			}
			output.AddRange(encrypted);
			return output.ToArray();
		}

		private static uint Rotate16(uint value) =>
			(value << 16) | (value >> 16);

		private uint ComputeIntegrity(byte[] encrypted, uint integrityKey, byte flags)
		{
			// The v4 polynomial started with (seed ^ domain) and multiplied by the
			// invertible word 31 for every public ciphertext byte. Walking that tag
			// backwards therefore recovered the exact stream seed in O(n). v5 keeps
			// two coupled lanes and compresses them only after all ciphertext bytes
			// have been absorbed. The small odd multipliers keep the mirrored Lua 5.1
			// arithmetic exact while cross-lane XOR destroys the old direct inverse.
			uint domain = _context.Domains.IntegrityDomain;
			uint left = unchecked((integrityKey ^ domain) + 0xA5C3F1E7u + (uint)flags * 257u);
			uint right = unchecked(integrityKey + Rotate16(domain) + 0x7F4A7C15u + (uint)encrypted.Length * 17u);
			for (int index = 0; index < encrypted.Length; index++)
			{
				uint mixedByte = unchecked((uint)encrypted[index] + (uint)(index + 1) * 257u + (uint)flags * 17u);
				left = unchecked((left ^ mixedByte) * 65599u + 0x9E3779B9u);
				right = unchecked((right + mixedByte + (left >> 16)) * 48271u + 0x6D2B79F5u);
				left ^= Rotate16(right);
			}
			left = unchecked((left ^ right ^ (uint)encrypted.Length) * 65599u + domain);
			right = unchecked((right ^ Rotate16(left) ^ flags) * 48271u + 0xC4D29A6Bu);
			return left ^ Rotate16(right);
		}

		private byte[] WrapEntropyEnvelope(byte[] body, uint seed, bool compressPages)
		{
			if (body == null || body.Length == 0)
				throw new InvalidOperationException("Cannot envelope an empty protected payload.");

			PayloadFormatLayout format = _context.PayloadFormat;
			int entropyLength = _random.Next(EntropyMinBytes, EntropyMaxBytes + 1);
			byte[] entropy = _random.GetBytes(entropyLength);
			uint nonce = NextState32();
			List<byte[]> entropyParts = SplitRandom(entropy, _random.Next(12, 21));
			uint entropyDigest = ComputeEntropyDigest(entropyParts, seed, nonce, entropyLength);

			int pageSize = _random.Next(PayloadPageMinBytes, PayloadPageMaxBytes + 1);
			var framedPages = new List<byte[]>((body.Length + pageSize - 1) / pageSize);
			for (int offset = 0, ordinal = 1; offset < body.Length; offset += pageSize, ordinal++)
			{
				int rawLength = Math.Min(pageSize, body.Length - offset);
				var rawPage = new byte[rawLength];
				Buffer.BlockCopy(body, offset, rawPage, 0, rawLength);
				byte[] encodedPage = compressPages ? Deflate(rawPage) : rawPage;
				byte[] transformedPage = TransformEncodedPage(encodedPage, ordinal, seed, nonce, entropyDigest);
				var frame = new List<byte>(transformedPage.Length + format.PageLengthWidth);
				if (!format.PageLengthSuffix) WriteUIntWidth(frame, (uint)rawLength, format.PageLengthWidth);
				frame.AddRange(transformedPage);
				if (format.PageLengthSuffix) WriteUIntWidth(frame, (uint)rawLength, format.PageLengthWidth);
				framedPages.Add(frame.ToArray());
			}
			if (framedPages.Count > ushort.MaxValue)
				throw new InvalidOperationException("Protected payload requires too many bounded pages.");

			uint framedLength = checked((uint)framedPages.Sum(page => (long)page.Length));
			uint maskState = seed ^ nonce ^ entropyDigest ^ _context.Domains.EnvelopeMaskDomain ^
			                 _context.Domains.PayloadFormatDomain ^ _context.Domains.DecodePipelineDomain ^ framedLength;
			var maskedPages = new List<byte[]>(framedPages.Count);
			foreach (byte[] framedPage in framedPages)
			{
				var maskedPage = new byte[framedPage.Length];
				for (int index = 0; index < framedPage.Length; index++)
				{
					maskedPage[index] = (byte)(framedPage[index] ^ (byte)(maskState >> 24));
					maskState = _context.PayloadDerivation.AdvanceStream(maskState);
				}
				maskedPages.Add(maskedPage);
			}

			var records = new List<EntropyRecord>(entropyParts.Count + maskedPages.Count);
			for (int index = 0; index < entropyParts.Count; index++)
				records.Add(new EntropyRecord {Kind = _context.Domains.EntropyRecordKind, Ordinal = (ushort)(index + 1), Data = entropyParts[index]});
			for (int index = 0; index < maskedPages.Count; index++)
				records.Add(new EntropyRecord {Kind = _context.Domains.DataRecordKind, Ordinal = (ushort)(index + 1), Data = maskedPages[index]});
			ShuffleEntropyRecords(records);

			var headerValues = new Dictionary<EnvelopeHeaderField, uint>
			{
				[EnvelopeHeaderField.FramedLength] = framedLength,
				[EnvelopeHeaderField.EntropyLength] = (uint)entropyLength,
				[EnvelopeHeaderField.RecordCount] = (uint)records.Count,
				[EnvelopeHeaderField.DataCount] = (uint)maskedPages.Count,
				[EnvelopeHeaderField.EntropyCount] = (uint)entropyParts.Count,
				[EnvelopeHeaderField.Nonce] = nonce,
				[EnvelopeHeaderField.EntropyDigest] = entropyDigest,
				[EnvelopeHeaderField.Integrity] = 0u
			};
			var envelope = new List<byte>(checked(32 + records.Count * format.RecordHeaderWidth + entropyLength + (int)framedLength));
			foreach (EnvelopeHeaderField field in format.EnvelopeHeaderOrder)
				WriteUInt32(envelope, headerValues[field]);
			foreach (EntropyRecord record in records)
			{
				foreach (EnvelopeRecordField field in format.EnvelopeRecordOrder)
				{
					switch (field)
					{
						case EnvelopeRecordField.Kind: envelope.Add(record.Kind); break;
						case EnvelopeRecordField.Ordinal: WriteUIntWidth(envelope, record.Ordinal, format.RecordOrdinalWidth); break;
						case EnvelopeRecordField.Length: WriteUIntWidth(envelope, (uint)record.Data.Length, format.RecordLengthWidth); break;
						default: throw new InvalidOperationException("Unknown envelope record field.");
					}
				}
				envelope.AddRange(record.Data);
			}

			byte[] result = envelope.ToArray();
			uint tag = ComputeEnvelopeIntegrity(result, seed);
			WriteUInt32(result, format.EnvelopeIntegrityOffset, tag);
			return result;
		}

		private List<byte[]> SplitRandom(byte[] data, int requestedCount)
		{
			int count = Math.Max(1, Math.Min(requestedCount, data.Length));
			if (count == 1)
				return new List<byte[]> {data.ToArray()};

			var cuts = new HashSet<int>();
			while (cuts.Count < count - 1)
				cuts.Add(_random.Next(1, data.Length));
			var lengths = new List<int>(count);
			int previous = 0;
			foreach (int cut in cuts.OrderBy(value => value))
			{
				lengths.Add(cut - previous);
				previous = cut;
			}
			lengths.Add(data.Length - previous);
			return SplitAtLengths(data, lengths);
		}

		private static List<byte[]> SplitAtLengths(byte[] data, IEnumerable<int> lengths)
		{
			var result = new List<byte[]>();
			int offset = 0;
			foreach (int length in lengths)
			{
				var part = new byte[length];
				Buffer.BlockCopy(data, offset, part, 0, length);
				result.Add(part);
				offset += length;
			}
			if (offset != data.Length)
				throw new InvalidOperationException("Invalid entropy envelope split.");
			return result;
		}

		private uint ComputeEntropyDigest(IReadOnlyList<byte[]> records, uint seed, uint nonce, int totalLength)
		{
			uint hash = unchecked((seed ^ _context.Domains.EntropyDigestDomain) * 31u + nonce);
			hash = unchecked(hash * 31u + (uint)totalLength);
			hash = unchecked(hash * 31u + (uint)records.Count);
			for (int index = 0; index < records.Count; index++)
			{
				byte[] record = records[index];
				hash = unchecked(hash * 31u + (uint)(index + 1));
				hash = unchecked(hash * 31u + (uint)record.Length);
				foreach (byte value in record)
					hash = unchecked(hash * 31u + value);
			}
			return hash;
		}

		private uint ComputeEnvelopeIntegrity(byte[] envelope, uint seed)
		{
			uint hash = unchecked((seed ^ _context.Domains.EnvelopeIntegrityDomain) * 31u);
			int integrityOffset = _context.PayloadFormat.EnvelopeIntegrityOffset;
			for (int index = 0; index < envelope.Length; index++)
			{
				// The Build-local integrity slot holds the tag itself and is omitted.
				if (index >= integrityOffset && index < integrityOffset + 4) continue;
				hash = unchecked(hash * 31u + envelope[index]);
			}
			return hash;
		}

		private void ShuffleEntropyRecords(List<EntropyRecord> records)
		{
			int transitions;
			do
			{
				for (int index = records.Count - 1; index > 0; index--)
				{
					int swapIndex = _random.Next(index + 1);
					(records[index], records[swapIndex]) = (records[swapIndex], records[index]);
				}
				transitions = 0;
				for (int index = 1; index < records.Count; index++)
					if (records[index - 1].Kind != records[index].Kind) transitions++;
			} while (transitions < 2);
		}

		private ushort NextKey16() =>
			(ushort)_random.Next(1, 65536);

		private static ushort OpcodeMask(int pc, ushort k1, ushort k2, ushort k3)
		{
			long linear = ((long)pc * k1 + k2) % 65536L;
			return (ushort)((linear * ((pc % 251) + 1L) + k3) % 65536L);
		}

		private static ushort OperandMask16(int pc, ushort k1, ushort k2, ushort k3, int slot) =>
			OpcodeMask(pc + slot * 257, k2, k3, k1);

		private static uint OperandMask32(int pc, ushort k1, ushort k2, ushort k3, int slot) =>
			(uint)(OperandMask16(pc, k1, k2, k3, slot) |
			       (OperandMask16(pc, k1, k2, k3, slot + 4) << 16));

		private uint NextState32()
		{
			uint state;
			do
			{
				state = _random.NextUInt32();
			} while (state == 0);
			return state;
		}

		private uint InitialFlowKey(ushort k1, ushort k2, ushort k3, uint binding)
		{
			uint value = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3 + _context.Domains.FlowDomain + binding);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint FlowKey(uint entryState, int fromPc, int toPc, ushort k1, ushort k2, ushort k3, uint binding)
		{
			uint value = unchecked(entryState * 1664525u + (uint)fromPc * 257u +
			                       (uint)toPc * 65537u + (uint)k1 * 251u +
			                       (uint)k2 * 17u + k3 + _context.Domains.FlowDomain + binding);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint FlowVerifier(uint entryState, int blockStart, ushort k1, ushort k2, ushort k3, uint binding) =>
			FlowKey(entryState, blockStart, blockStart ^ _context.Domains.FlowVerifierMask, k1, k2, k3, binding);

		private uint ChunkState(uint entryState, int blockStart, int count, ushort k1, ushort k2, ushort k3,
			uint binding, uint attestation)
		{
			uint value = unchecked(entryState * 22695477u + (uint)blockStart * 65537u + (uint)count * 257u +
			                       (uint)k1 * 251u + (uint)k2 * 17u + k3 +
			                       _context.Domains.ChunkStateDomain + binding + attestation);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint InitialChunkKey(ushort k1, ushort k2, ushort k3, uint binding, uint attestation)
		{
			uint value = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3 +
			                       _context.Domains.ChunkStateDomain + binding + attestation);
			return unchecked(value * 22695477u + 1u);
		}

		private uint ChunkChainKey(uint sourceChunkState, uint sourceEntryState, int fromPc, int toPc,
			ushort k1, ushort k2, ushort k3, uint binding, uint attestation)
		{
			uint value = unchecked(sourceChunkState * 1664525u + sourceEntryState * 22695477u +
			                       (uint)fromPc * 257u + (uint)toPc * 65537u + (uint)k1 * 251u +
			                       (uint)k2 * 17u + k3 + _context.Domains.ChunkStateDomain + binding + attestation);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint BeginOpcodeState(uint chunkState, uint entryState, int blockStart,
			ushort k1, ushort k2, ushort k3, uint attestation)
		{
			uint value = unchecked(chunkState * 22695477u + entryState * 1664525u +
			                       (uint)blockStart * 65537u + (uint)k1 * 251u + (uint)k2 * 17u + k3 +
			                       _context.Domains.OpcodeStateDomain + attestation);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint AdvanceOpcodeState(uint state, uint digest, int index, uint chunkState, uint entryState,
			uint attestation)
		{
			uint value = unchecked(state * 1664525u + digest + (uint)index * 257u +
			                       chunkState * 17u + entryState + _context.Domains.OpcodeStateDomain + attestation);
			return unchecked(value * 22695477u + 1u);
		}

		private ushort OpcodeStateMask(uint state, int pc)
		{
			uint low = state & 0xffffu;
			uint high = state >> 16;
			return (ushort)((low * (uint)((pc % 251) + 1) + high * 17u +
			                 (_context.Domains.OpcodeStateDomain & 0xffffu)) & 0xffffu);
		}

		private uint ComputeInstructionDigest(byte[] record, int index, ushort k1, ushort k2, ushort k3,
			uint chunkState, uint entryState)
		{
			uint domain = _context.Domains.InstructionStateDomain;
			uint keyed = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3);
			uint left = keyed ^ domain ^ (uint)index ^ entryState;
			uint right = chunkState ^ Rotate16(keyed) ^ unchecked((uint)index * 257u) ^ Rotate16(entryState);
			uint counter = 1;
			void Absorb(uint word)
			{
				uint mixed = unchecked(word + counter * 257u);
				left = unchecked((left ^ mixed) * 65599u + 0x9E3779B9u);
				right = unchecked((right + mixed + (left >> 16)) * 48271u + 0x6D2B79F5u);
				left ^= Rotate16(right);
				counter++;
			}
			Absorb((uint)index); Absorb(k1); Absorb(k2); Absorb(k3); Absorb((uint)record.Length);
			foreach (byte value in record) Absorb(value);
			left = unchecked((left ^ right ^ (uint)record.Length) * 65599u + domain);
			right = unchecked((right ^ Rotate16(left) ^ (uint)index) * 48271u + 0xC4D29A6Bu);
			return left ^ Rotate16(right);
		}

		private ushort BlockFieldMask(uint entryState, int pc, int slot, ushort k1, ushort k2, ushort k3)
		{
			uint low = entryState & 0xFFFFu;
			uint high = entryState >> 16;
			return (ushort)((low * (uint)((pc + slot * 29) % 251 + 1) + high * 17u +
			                 (uint)k1 * 13u + (uint)k2 * 7u + k3 + (uint)slot * _context.Domains.BlockFieldStride) & 0xFFFFu);
		}

		private static uint HashWord(uint hash, uint value) => unchecked(hash * 31u + value);

		private static uint HashBytes(uint hash, IEnumerable<byte> values)
		{
			foreach (byte value in values)
				hash = HashWord(hash, value);
			return hash;
		}

		private uint ConstantMaskState(int oneBasedIndex, uint entryState, uint chunkState, int blockStart,
			ushort k1, ushort k2, ushort k3)
		{
			uint value = unchecked((uint)oneBasedIndex * 65537u + entryState * 22695477u +
			                       chunkState * 1664525u + (uint)blockStart * 257u +
			                       (uint)k1 * 257u + (uint)k2 * 17u + k3 +
			                       _context.Domains.ConstantMaskDomain);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint BeginConstantChain(uint entryState, uint chunkState, int blockStart,
			ushort k1, ushort k2, ushort k3)
		{
			uint keyed = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3);
			uint value = unchecked((entryState ^ Rotate16(chunkState)) + (uint)blockStart * 65537u
			                       + keyed + _context.Domains.ConstantMaskDomain + 3266489909u);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private static uint AdvanceConstantChain(uint state, IReadOnlyList<byte> capsule, int oneBasedIndex)
		{
			uint value = state ^ unchecked((uint)oneBasedIndex * 2654435761u);
			for (int index = 0; index < capsule.Count; index++)
				value = unchecked(value * 65599u + capsule[index] + (uint)(index + 1) * 257u);
			return value ^ Rotate16(unchecked((uint)capsule.Count * 65537u + (uint)oneBasedIndex));
		}

		private uint StringShardState(int oneBasedIndex, int logicalShard, int length, uint constantChainState,
			uint entryState, uint chunkState, int blockStart, ushort k1, ushort k2, ushort k3)
		{
			uint value = unchecked(ConstantMaskState(oneBasedIndex, entryState, chunkState, blockStart, k1, k2, k3)
			                       + (uint)logicalShard * 65537u + (uint)length * 257u
			                       + constantChainState * 257u
			                       + _context.Domains.ConstantMaskDomain + 2654435769u);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private uint ComputeConstantIntegrity(byte[] encodedBody, int oneBasedIndex,
			uint entryState, uint chunkState, int blockStart, ushort k1, ushort k2, ushort k3)
		{
			uint keyed = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3);
			uint domain = _context.Domains.ConstantIntegrityDomain;
			uint left = keyed ^ domain ^ entryState ^ Rotate16(chunkState);
			uint right = chunkState ^ Rotate16(keyed) ^ unchecked((uint)blockStart * 257u) ^ (uint)oneBasedIndex;
			uint counter = 1;
			void Absorb(uint word)
			{
				uint mixed = unchecked(word + counter * 257u);
				left = unchecked((left ^ mixed) * 65599u + 0x9E3779B9u);
				right = unchecked((right + mixed + (left >> 16)) * 48271u + 0x6D2B79F5u);
				left ^= Rotate16(right);
				counter++;
			}
			Absorb((uint)blockStart);
			Absorb((uint)oneBasedIndex);
			Absorb((uint)encodedBody.Length);
			foreach (byte value in encodedBody) Absorb(value);
			left = unchecked((left ^ right ^ (uint)encodedBody.Length) * 65599u + domain);
			right = unchecked((right ^ Rotate16(left) ^ (uint)oneBasedIndex) * 48271u + 0xC4D29A6Bu);
			return left ^ Rotate16(right);
		}

		private uint ComputeBlockIntegrity(byte[] body, uint entryState, int start, int count,
			uint routeToken, IReadOnlyList<int> constantReferences, uint verifier,
			IReadOnlyList<ChunkSuccessor> successors, ushort k1, ushort k2, ushort k3, uint binding)
		{
			uint domain = _context.Domains.BlockIntegrityDomain;
			uint keyed = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3);
			uint left = entryState ^ domain ^ binding ^ Rotate16(keyed);
			uint right = binding ^ Rotate16(entryState) ^ keyed ^ unchecked((uint)start * 257u);
			uint counter = 1;
			void Absorb(uint word)
			{
				uint mixed = unchecked(word + counter * 257u);
				left = unchecked((left ^ mixed) * 65599u + 0x9E3779B9u);
				right = unchecked((right + mixed + (left >> 16)) * 48271u + 0x6D2B79F5u);
				left ^= Rotate16(right);
				counter++;
			}
			foreach (uint word in new[]
			         {
				         (uint)start, (uint)count, k1, k2, k3, routeToken,
				         (uint)constantReferences.Count
			         })
				Absorb(word);
			foreach (int constantIndex in constantReferences) Absorb((uint)constantIndex);
			Absorb(verifier);
			Absorb((uint)successors.Count);
			foreach (ChunkSuccessor successor in successors)
			{
				Absorb((uint)successor.Destination);
				Absorb(successor.WrappedEntryState);
				Absorb(successor.WrappedChunkState);
			}
			Absorb((uint)body.Length);
			foreach (byte value in body) Absorb(value);
			left = unchecked((left ^ right ^ (uint)body.Length) * 65599u + domain);
			right = unchecked((right ^ Rotate16(left) ^ (uint)start ^ (uint)count) * 48271u + 0xC4D29A6Bu);
			return left ^ Rotate16(right);
		}

		private uint ComputePrototypeIntegrity(byte[] body, ushort k1, ushort k2, ushort k3)
		{
			uint keyed = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3);
			uint domain = _context.Domains.PrototypeIntegrityDomain;
			uint left = keyed ^ domain ^ (uint)body.Length;
			uint right = Rotate16(keyed) ^ _context.XorSeed ^ unchecked((uint)body.Length * 257u);
			uint counter = 1;
			void Absorb(uint word)
			{
				uint mixed = unchecked(word + counter * 257u);
				left = unchecked((left ^ mixed) * 65599u + 0x9E3779B9u);
				right = unchecked((right + mixed + (left >> 16)) * 48271u + 0x6D2B79F5u);
				left ^= Rotate16(right);
				counter++;
			}
			Absorb((uint)body.Length);
			for (int index = 0; index < body.Length; index++)
			{
				if (index >= 6 && index < 10) continue;
				Absorb(body[index]);
			}
			left = unchecked((left ^ right ^ (uint)body.Length) * 65599u + domain);
			right = unchecked((right ^ Rotate16(left) ^ keyed) * 48271u + 0xC4D29A6Bu);
			return left ^ Rotate16(right);
		}

		private void ShuffleBlocks(List<ControlFlowBlock> blocks)
		{
			for (int index = blocks.Count - 1; index > 0; index--)
			{
				int swapIndex = _random.Next(index + 1);
				(blocks[index], blocks[swapIndex]) = (blocks[swapIndex], blocks[index]);
			}
		}

		/// <summary>
		/// Derives a prototype-local permutation from that prototype's independent keys.
		/// Domains keep schema order and constant tags from sharing the same permutation.
		/// The Lua deserializer implements the exact same Fisher-Yates schedule.
		/// </summary>
		private static int[] DerivePermutation(int count, ushort k1, ushort k2, ushort k3, uint domain)
		{
			int[] values = Enumerable.Range(0, count).ToArray();
			uint state = ((uint)k1 * 251u + (uint)k2 * 17u + k3 + domain) & 0xFFFFu;
			for (int i = count; i >= 2; i--)
			{
				state = (state * 251u + k3 + (uint)i * k1 + k2 + domain) & 0xFFFFu;
				int j = (int)(state % (uint)i);
				(values[i - 1], values[j]) = (values[j], values[i - 1]);
			}
			return values;
		}

		/// <summary>
		/// Derives a block-local physical page order for the five logical IR columns:
		/// descriptor, opcode, A, B and C. EntryState makes the order independent per
		/// block; forcing a final swap avoids ever emitting the canonical identity order.
		/// Values[physical page] is the logical column stored in that page.
		/// </summary>
		private static int[] DeriveBlockPermutation(int count, uint entryState,
			ushort k1, ushort k2, ushort k3, uint domain)
		{
			int[] values = Enumerable.Range(0, count).ToArray();
			uint low = entryState & 0xFFFFu;
			uint high = entryState >> 16;
			uint state = (low * 251u + high * 17u + (uint)k1 * 13u +
			              (uint)k2 * 7u + k3 + domain) & 0xFFFFu;
			for (int i = count; i >= 2; i--)
			{
				state = (state * 251u + k3 + (uint)i * (k1 + low) +
				         k2 + high + domain) & 0xFFFFu;
				int j = (int)(state % (uint)i);
				(values[i - 1], values[j]) = (values[j], values[i - 1]);
			}

			bool identity = true;
			for (int index = 0; index < count; index++)
				identity &= values[index] == index;
			if (identity && count > 1)
				(values[0], values[1]) = (values[1], values[0]);
			return values;
		}

		private int PrototypeDecoderMode(ushort k1, ushort k2, ushort k3) =>
			(int)(((uint)k1 * 13u + (uint)k2 * 7u + (uint)k3 * 11u +
			       _context.Domains.DecodePipelineDomain) % 4u);

		private byte[] EncodePrototypeColumn(IReadOnlyList<byte> column, int role, int pc,
			uint entryState, ushort k1, ushort k2, ushort k3)
		{
			int mode = PrototypeDecoderMode(k1, k2, k3);
			var output = new byte[column.Count];
			uint low = entryState & 0xFFFFu;
			uint high = entryState >> 16;
			for (int index = 0; index < column.Count; index++)
			{
				byte value = column[index];
				int mask = (int)((low + high * 3u + (uint)k1 * 5u + (uint)k2 * 7u +
				                      (uint)k3 * 11u + (uint)pc * 13u + (uint)role * 17u +
				                      (uint)index * 29u + _context.Domains.DecodePipelineDomain) & 0xFFu);
				byte encoded;
				switch (mode)
				{
					case 0:
						encoded = (byte)(value ^ mask);
						break;
					case 1:
						encoded = (byte)(value + mask);
						break;
					case 2:
						byte nibble = (byte)((value << 4) | (value >> 4));
						encoded = (byte)(nibble ^ mask);
						break;
					default:
						int shift = ((role + pc + index) % 7) + 1;
						byte rotated = (byte)((value << shift) | (value >> (8 - shift)));
						encoded = (byte)(rotated + mask);
						break;
				}
				int destination = mode == 1 || mode == 3 ? column.Count - index - 1 : index;
				output[destination] = encoded;
			}
			return output;
		}

		private static int[] DeriveCodeDataPermutation(int instructionCount, int constantCount,
			uint stateValue, ushort k1, ushort k2, ushort k3, uint domain)
		{
			int[] values = DeriveBlockPermutation(instructionCount + constantCount, stateValue,
				k1, k2, k3, domain);
			if (instructionCount == 0 || constantCount == 0 || values.Length <= 2) return values;

			bool previousData = values[0] >= instructionCount;
			int transitions = 0;
			int firstBoundary = 0;
			for (int index = 1; index < values.Length; index++)
			{
				bool currentData = values[index] >= instructionCount;
				if (currentData != previousData)
				{
					transitions++;
					if (firstBoundary == 0) firstBoundary = index;
				}
				previousData = currentData;
			}

			// A single transition is still just two contiguous type partitions, even
			// when data happens to precede code.  Move one item across that boundary
			// so every non-trivial mixed block contains at least three type runs.
			if (transitions < 2)
				(values[firstBoundary - 1], values[firstBoundary]) =
					(values[firstBoundary], values[firstBoundary - 1]);
			return values;
		}

		private static void WriteUInt16(List<byte> output, ushort value)
		{
			output.Add((byte)value);
			output.Add((byte)(value >> 8));
		}

		private static void WriteUInt32(List<byte> output, uint value)
		{
			output.Add((byte)value);
			output.Add((byte)(value >> 8));
			output.Add((byte)(value >> 16));
			output.Add((byte)(value >> 24));
		}

		private static void WriteUIntWidth(List<byte> output, uint value, int width)
		{
			if (width < 1 || width > 4 || (width < 4 && value >= (1u << (width * 8))))
				throw new InvalidOperationException("Protected payload field exceeds its Build-local width.");
			for (int index = 0; index < width; index++)
				output.Add((byte)(value >> (index * 8)));
		}

		private static void WriteUInt32(byte[] output, int offset, uint value)
		{
			output[offset] = (byte)value;
			output[offset + 1] = (byte)(value >> 8);
			output[offset + 2] = (byte)(value >> 16);
			output[offset + 3] = (byte)(value >> 24);
		}

		/// <summary>raw DEFLATE（RFC 1951）。</summary>
		private static byte[] Deflate(byte[] data)
		{
			using var stream = new MemoryStream();
			using (var deflate = new DeflateStream(stream, CompressionLevel.Optimal, true))
				deflate.Write(data, 0, data.Length);
			return stream.ToArray();
		}

		private byte TransformPipelineByte(byte value, int ordinal)
		{
			PayloadFormatLayout format = _context.PayloadFormat;
			switch (format.ByteTransformVariant)
			{
				case 0:
					return value;
				case 1:
					return (byte)((value << 4) | (value >> 4));
				case 2:
					return (byte)(value ^ (byte)(format.ByteTransformParameter + ordinal * 29));
				case 3:
					int shift = format.ByteTransformParameter;
					return (byte)((value << shift) | (value >> (8 - shift)));
				default:
					throw new InvalidOperationException("Unknown protected payload byte transform.");
			}
		}

		private byte[] TransformEncodedPage(byte[] page, int ordinal, uint seed, uint nonce, uint entropyDigest)
		{
			var output = new byte[page.Length];
			for (int index = 0; index < page.Length; index++)
				output[index] = TransformPipelineByte(page[index], ordinal);
			switch (_context.PayloadFormat.PipelineVariant)
			{
				case 0:
					return output;
				case 1:
					Array.Reverse(output);
					return output;
				case 2:
					uint state = seed ^ nonce ^ entropyDigest ^ _context.Domains.DecodePipelineDomain ^
					             unchecked((uint)ordinal * 0x9e3779b9u);
					for (int index = 0; index < output.Length; index++)
					{
						byte plain = output[index];
						output[index] = (byte)(plain ^ (byte)(state >> 24));
						state = unchecked(_context.PayloadDerivation.AdvanceStream(state) + plain + (uint)index);
					}
					return output;
				default:
					throw new InvalidOperationException("Unknown protected payload decode pipeline.");
			}
		}

		private byte[] SerializeBody(Chunk chunk)
		{
			var bytes = new List<byte>();
			List<byte> output = bytes;
			ushort k1 = NextKey16();
			ushort k2 = NextKey16();
			ushort k3 = NextKey16();

			if (_context.VirtualOpcodeCount <= 0 || _context.VirtualOpcodeCount > ushort.MaxValue)
				throw new InvalidOperationException("Invalid virtual opcode count.");

			// Bank[local index] = canonical VIndex. The serialized opcode is the inverse
			// lookup, so each prototype keeps a different opcode numbering until dispatch.
			int[] opcodeBank = DerivePermutation(_context.VirtualOpcodeCount, k1, k2, k3, _context.Domains.OpcodePermutationDomain);
			int[] opcodeToLocal = new int[opcodeBank.Length];
			for (int localIndex = 0; localIndex < opcodeBank.Length; localIndex++)
				opcodeToLocal[opcodeBank[localIndex]] = localIndex;

			// Constant operands carry per-use random handles rather than stable
			// prototype constant indices. Every occurrence gets its own capsule.
			var constantsByHandle = new Dictionary<int, Constant>();

			void WriteByte(byte value) => output.Add(value);
			void WriteUInt16Local(ushort value) => WriteUInt16(output, value);
			void WriteUInt32Local(uint value) => WriteUInt32(output, value);

			void SerializeInstruction(Instruction instruction, int zeroBasedIndex, uint entryState,
				uint opcodeState, IReadOnlyList<List<byte>> columns)
			{
				// Logical columns are descriptor/opcode/A/B/C. They are accumulated
				// independently, then emitted in a block-local physical permutation.
				List<byte> descriptors = columns[0];
				List<byte> opcodes = columns[1];
				List<byte> operandsA = columns[2];
				List<byte> operandsB = columns[3];
				List<byte> operandsC = columns[4];
				int pc = zeroBasedIndex + 1;
				byte descriptorMask = (byte)BlockFieldMask(entryState, pc, 7, k1, k2, k3);
				if (instruction.InstructionType == InstructionType.Data)
				{
					descriptors.Add((byte)(1 ^ descriptorMask));
					return;
				}

				int opcode = (int)instruction.OpCode;
				if (instruction.CustomData != null)
				{
					var virtualOpcode = instruction.CustomData.Opcode;
					opcode = instruction.CustomData.WrittenOpcode?.VIndex ?? virtualOpcode.VIndex;
				}

				opcode = opcodeToLocal[opcode];

				int type = (int)instruction.InstructionType;
				int constantMask = (int)instruction.ConstantMask;
				List<Instruction> fusedInstructions = instruction.CustomData?.FusedInstructions;
				bool isFused = fusedInstructions is {Count: > 1};
				descriptors.Add((byte)(((type << 1) | (constantMask << 3) | (isFused ? 64 : 0)) ^ descriptorMask));

				ushort storedOpcode = (ushort)((ushort)opcode ^ OpcodeMask(pc, k1, k2, k3) ^
				                               BlockFieldMask(entryState, pc, 0, k1, k2, k3) ^
				                               OpcodeStateMask(opcodeState, pc));
				ushort storedA = (ushort)((ushort)instruction.A ^ OperandMask16(pc, k1, k2, k3, 1) ^
				                          BlockFieldMask(entryState, pc, 1, k1, k2, k3));
				WriteUInt16(opcodes, storedOpcode);
				WriteUInt16(operandsA, storedA);

				uint BlockMask32(int slot) =>
					(uint)(BlockFieldMask(entryState, pc, slot, k1, k2, k3) |
					       (BlockFieldMask(entryState, pc, slot + 4, k1, k2, k3) << 16));

				int b = instruction.B;
				int c = instruction.C;
				switch (instruction.InstructionType)
				{
					case InstructionType.AsBx:
						WriteUInt32(operandsB, unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						break;
					case InstructionType.AsBxC:
						WriteUInt32(operandsB, unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						WriteUInt16(operandsC, (ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3) ^
						                              BlockFieldMask(entryState, pc, 3, k1, k2, k3)));
						break;
					case InstructionType.ABC:
						WriteUInt16(operandsB, (ushort)((ushort)b ^ OperandMask16(pc, k1, k2, k3, 2) ^
						                              BlockFieldMask(entryState, pc, 2, k1, k2, k3)));
						WriteUInt16(operandsC, (ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3) ^
						                              BlockFieldMask(entryState, pc, 3, k1, k2, k3)));
						break;
					case InstructionType.ABx:
						WriteUInt32(operandsB, unchecked((uint)b) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						break;
				}

				if (isFused)
				{
					if (fusedInstructions.Count > 6 || !ReferenceEquals(fusedInstructions[0], instruction))
						throw new InvalidOperationException("Invalid IR fusion descriptor.");
					descriptors.Add((byte)(fusedInstructions.Count - 1));
					foreach (Instruction member in fusedInstructions.Skip(1))
					{
						int memberType = (int)member.InstructionType;
						int memberMask = (int)member.ConstantMask;
						if (member.InstructionType == InstructionType.Data || memberType > 3 || memberMask > 7)
							throw new InvalidOperationException("Unsafe IR fusion member.");
						descriptors.Add((byte)((memberType << 1) | (memberMask << 3)));
						WriteUInt16(operandsA, unchecked((ushort)member.A));
						switch (member.InstructionType)
						{
							case InstructionType.ABC:
								WriteUInt16(operandsB, unchecked((ushort)member.B));
								WriteUInt16(operandsC, unchecked((ushort)member.C));
								break;
							case InstructionType.ABx:
								WriteUInt32(operandsB, unchecked((uint)member.B));
								break;
							case InstructionType.AsBx:
								WriteUInt32(operandsB, unchecked((uint)(member.B + (1 << 16))));
								break;
							case InstructionType.AsBxC:
								WriteUInt32(operandsB, unchecked((uint)(member.B + (1 << 16))));
								WriteUInt16(operandsC, unchecked((ushort)member.C));
								break;
						}
					}
				}
			}

			// Mutate supplemental IR nodes while the original instruction map is
			// still available, then physically lower every safe sequence to its head.
			chunk.UpdateMappings();
			foreach (Instruction head in chunk.Instructions.Where(value => value.CustomData?.FusedInstructions is {Count: > 1}))
				foreach (Instruction member in head.CustomData.FusedInstructions.Skip(1))
				{
					member.UpdateRegisters();
					member.CustomData?.Opcode?.Mutate(member);
				}
			var loweredInstructions = new List<Instruction>(chunk.Instructions.Count);
			for (int index = 0; index < chunk.Instructions.Count; index++)
			{
				Instruction instruction = chunk.Instructions[index];
				if (instruction.CustomData?.FusionContinuation == true)
					continue;
				loweredInstructions.Add(instruction);
			}
			chunk.Instructions = loweredInstructions;
			chunk.UpdateMappings();
			foreach (Instruction instruction in chunk.Instructions) instruction.UpdateRegisters();
			foreach (Instruction instruction in chunk.Instructions) instruction.CustomData?.Opcode?.Mutate(instruction);
			var usedConstantHandles = new HashSet<int>();
			int AssignConstantHandle(int oneBasedConstantIndex)
			{
				if (oneBasedConstantIndex < 1 || oneBasedConstantIndex > chunk.Constants.Count)
					throw new InvalidOperationException("Invalid constant operand before handle assignment.");
				int handle;
				do handle = _random.Next(1, 65536); while (!usedConstantHandles.Add(handle));
				constantsByHandle.Add(handle, chunk.Constants[oneBasedConstantIndex - 1]);
				return handle;
			}
			foreach (Instruction physical in chunk.Instructions)
			{
				IEnumerable<Instruction> members = physical.CustomData?.FusedInstructions ?? (IEnumerable<Instruction>)new[] {physical};
				foreach (Instruction member in members)
				{
					if ((member.ConstantMask & InstructionConstantMask.RA) != 0) member.A = AssignConstantHandle(member.A);
					if ((member.ConstantMask & InstructionConstantMask.RB) != 0) member.B = AssignConstantHandle(member.B);
					if ((member.ConstantMask & InstructionConstantMask.RC) != 0) member.C = AssignConstantHandle(member.C);
				}
			}

			DispatcherFlatteningDecision flattening = _settings.ControlFlow
				? DispatcherFlatteningPlanner.Apply(chunk, _context.MaxBlockInstructions)
				: null;
			if (!_settings.ControlFlow)
			{
				chunk.DispatcherFlattened = false;
				chunk.DispatcherFlatteningReason = "control-flow-disabled";
			}

			ControlFlowGraph controlFlow = flattening?.Graph ??
			                                   ControlFlowGraph.Build(chunk, _context.MaxBlockInstructions);
			var instructionBlocks = controlFlow.Blocks.ToList();
			if (controlFlow.EntryBlock == null)
				throw new InvalidOperationException("Prototype has no entry block.");
			bool dispatcherFlattened = flattening?.IsEligible == true;

			// Every block receives an independent execution state. Successor edges wrap
			// the destination state with the source state, so a block cannot be entered
			// or decoded using only its linear PC.
			var blockStates = new Dictionary<ControlFlowBlock, uint>(instructionBlocks.Count);
			var usedBlockStates = new HashSet<uint>();
			foreach (ControlFlowBlock block in instructionBlocks)
			{
				uint state;
				do state = NextState32(); while (!usedBlockStates.Add(state));
				blockStates.Add(block, state);
			}
			uint payloadAttestation = _settings.AntiDump ? _context.Binder.PayloadBinding : _context.XorSeed;
			var blockChunkStates = instructionBlocks.ToDictionary(
				block => block,
				block => ChunkState(blockStates[block], block.Start + 1, block.Count, k1, k2, k3,
					_context.XorSeed, payloadAttestation));

			// Eligible prototypes receive unrelated route tokens. A token is never a
			// valid linear PC, so each cross-block transfer must be resolved by the VM's
			// dispatcher before GetInstruction can validate and decode the destination.
			var blockRoutes = new Dictionary<ControlFlowBlock, uint>(instructionBlocks.Count);
			var usedRoutes = new HashSet<uint>();
			if (dispatcherFlattened)
			{
				foreach (ControlFlowBlock block in instructionBlocks)
				{
					uint route;
					do route = NextState32();
					while (route <= (uint)chunk.Instructions.Count || !usedRoutes.Add(route));
					blockRoutes.Add(block, route);
				}
			}

			ShuffleBlocks(instructionBlocks);

			// 每 prototype 独立密钥位于外层加密正文中，不再泄露在固定头部。
			// 紧随其后的 tag 在正文完成后回填，认证整个 prototype slice（包括
			// schema、block manifests、constant capsules 与 child framing）。
			WriteUInt16Local(k1);
			WriteUInt16Local(k2);
			WriteUInt16Local(k3);
			WriteUInt32Local(0u);

			// Schema 与常量 tag 都由当前 prototype 的独立 keys 派生，并使用不同 domain。
			// 因此父子 prototype 不再共享一个全局 ChunkSteps 或简单 tag rotation。
			int[] schema = DerivePermutation((int)ChunkStep.StepCount, k1, k2, k3, _context.Domains.SchemaPermutationDomain);
			int[] constantTags = DerivePermutation(4, k1, k2, k3, _context.Domains.ConstantTagPermutationDomain);

			byte[] BuildConstantCapsule(Constant constant, int constantHandle, uint constantChainState, uint entryState,
				uint chunkState, int blockStart)
			{
				int oneBasedIndex = constantHandle;
				var raw = new List<byte>();
				raw.Add((byte)constantTags[(int)constant.Type]);
				switch (constant.Type)
				{
					case ConstantType.Boolean:
						raw.Add(constant.Data ? (byte)1 : (byte)0);
						break;
					case ConstantType.Number:
					{
						byte[] number = BitConverter.GetBytes((double)constant.Data);
						if (!BitConverter.IsLittleEndian) Array.Reverse(number);
						raw.AddRange(number);
						break;
					}
					case ConstantType.String:
					{
						byte[] value = _luaEncoding.GetBytes((string)constant.Data);
						WriteUInt32(raw, (uint)value.Length);
						int shardCount = value.Length <= 1 ? 1 : Math.Min(value.Length, 3 + _random.Next(5));
						raw.Add((byte)shardCount);
						int[] shardOrder = DerivePermutation(shardCount, k1, k2, k3,
							unchecked(_context.Domains.ConstantMaskDomain + 2654435769u));
						foreach (int logicalShard in shardOrder)
						{
							var shard = new List<byte>();
							uint shardState = StringShardState(oneBasedIndex, logicalShard, value.Length, constantChainState,
								entryState, chunkState, blockStart, k1, k2, k3);
							for (int position = logicalShard; position < value.Length; position += shardCount)
							{
								byte encoded = (byte)(value[position] ^ (byte)(shardState >> 24));
								shard.Add(encoded);
								shardState = unchecked(shardState * 1664525u + 1013904223u
									+ encoded + (uint)(position + 1) * 257u);
							}
							WriteUInt32(raw, (uint)shard.Count);
							raw.AddRange(shard);
						}
						break;
					}
				}

				uint state = ConstantMaskState(oneBasedIndex, entryState, chunkState, blockStart, k1, k2, k3);
				byte[] encodedBody = new byte[raw.Count];
				for (int index = 0; index < raw.Count; index++)
				{
					encodedBody[index] = (byte)(raw[index] ^ (byte)(state >> 24));
					state = unchecked(state * 1664525u + 1013904223u);
				}

				var capsule = new List<byte>(encodedBody.Length + 4);
				WriteUInt32(capsule, ComputeConstantIntegrity(encodedBody, oneBasedIndex,
					entryState, chunkState, blockStart, k1, k2, k3));
				capsule.AddRange(encodedBody);
				return capsule.ToArray();
			}

			void SerializeConstants()
			{
				// Constant bodies are no longer emitted as a prototype-wide pool.  The
				// count is retained for reference validation; authenticated capsules are
				// rebuilt with block state and interleaved into each block's code records.
				WriteUInt32Local((uint)chunk.Constants.Count);
			}

			foreach (int stepValue in schema)
			{
				switch ((ChunkStep)stepValue)
				{
					case ChunkStep.ParameterCount:
						WriteByte(chunk.ParameterCount);
						break;
					case ChunkStep.StringTable:
						SerializeConstants();
						break;
					case ChunkStep.Instructions:
						WriteUInt32Local((uint)chunk.Instructions.Count);
						WriteUInt32Local((uint)instructionBlocks.Count);
						WriteUInt32Local(blockStates[controlFlow.EntryBlock] ^ InitialFlowKey(k1, k2, k3, _context.XorSeed));
						WriteUInt32Local(blockChunkStates[controlFlow.EntryBlock] ^
						                 InitialChunkKey(k1, k2, k3, _context.XorSeed, payloadAttestation));
						// Store the first route under the attestation-derived binding. In the
						// non-dispatcher case seed^seed decodes back to the zero sentinel.
						WriteUInt32Local((dispatcherFlattened ? blockRoutes[controlFlow.EntryBlock] : 0u) ^ _context.XorSeed);
						foreach (ControlFlowBlock block in instructionBlocks)
						{
							int start = block.Start;
							int count = block.Count;
							uint entryState = blockStates[block];
							uint sourceChunkState = blockChunkStates[block];

							// Each instruction is an independently framed five-role record.  The
							// decoder can therefore authenticate the block, locate one record and
							// materialize only the instruction requested by the VM loop.
							var instructionRecords = new List<byte[]>(count);
							int[] columnOrder = DeriveBlockPermutation(5, entryState, k1, k2, k3,
								_context.Domains.BlockColumnDomain);
							uint opcodeState = BeginOpcodeState(sourceChunkState, entryState, start + 1,
								k1, k2, k3, payloadAttestation);
							for (int offset = 0; offset < count; offset++)
							{
								int instructionIndex = start + offset + 1;
								var columns = Enumerable.Range(0, 5).Select(_ => new List<byte>()).ToArray();
								SerializeInstruction(chunk.Instructions[start + offset], start + offset, entryState, opcodeState, columns);
								var instructionRecord = new List<byte>();
								foreach (int logicalColumn in columnOrder)
								{
									byte[] encodedColumn = EncodePrototypeColumn(
										columns[logicalColumn], logicalColumn, instructionIndex,
										entryState, k1, k2, k3);
									WriteUInt32(instructionRecord, (uint)encodedColumn.Length);
									instructionRecord.AddRange(encodedColumn);
								}
								byte[] record = instructionRecord.ToArray();
								instructionRecords.Add(record);
								opcodeState = AdvanceOpcodeState(opcodeState,
									ComputeInstructionDigest(record, instructionIndex, k1, k2, k3, sourceChunkState, entryState), instructionIndex,
									sourceChunkState, entryState, payloadAttestation);
							}

							var referenceSet = new HashSet<int>();
							for (int offset = 0; offset < count; offset++)
							{
								Instruction instruction = chunk.Instructions[start + offset];
								IEnumerable<Instruction> referencedInstructions = instruction.CustomData?.FusedInstructions ?? (IEnumerable<Instruction>)new[] {instruction};
								foreach (Instruction referenced in referencedInstructions)
								{
									if ((referenced.ConstantMask & InstructionConstantMask.RA) != 0) referenceSet.Add(referenced.A);
									if ((referenced.ConstantMask & InstructionConstantMask.RB) != 0) referenceSet.Add(referenced.B);
									if ((referenced.ConstantMask & InstructionConstantMask.RC) != 0) referenceSet.Add(referenced.C);
								}
							}
							List<int> constantReferences = referenceSet.OrderBy(value => value).ToList();
							foreach (int constantHandle in constantReferences)
								if (!constantsByHandle.ContainsKey(constantHandle))
									throw new InvalidOperationException("Invalid block constant handle.");

							// Logical records are instruction windows followed by this block's
							// state-bound constant partition.  Their physical order is shuffled from
							// EntryState + ChunkState, producing real code/data record interleaving.
							var logicalFragments = new List<byte[]>(count + constantReferences.Count);
							logicalFragments.AddRange(instructionRecords);
							uint constantChainState = BeginConstantChain(entryState, sourceChunkState, start + 1, k1, k2, k3);
							foreach (int constantHandle in constantReferences)
							{
								byte[] capsule = BuildConstantCapsule(constantsByHandle[constantHandle],
									constantHandle, constantChainState, entryState, sourceChunkState, start + 1);
								logicalFragments.Add(capsule);
								constantChainState = AdvanceConstantChain(constantChainState, capsule, constantHandle);
							}

							var blockBody = new List<byte>();
							uint fragmentState = entryState ^ sourceChunkState;
							int[] fragmentOrder = DeriveCodeDataPermutation(count, constantReferences.Count, fragmentState,
								k1, k2, k3, _context.Domains.CodeDataPermutationDomain);
							foreach (int logicalFragment in fragmentOrder)
							{
								byte[] fragment = logicalFragments[logicalFragment];
								WriteUInt32(blockBody, (uint)fragment.Length);
								blockBody.AddRange(fragment);
							}

							uint routeToken = dispatcherFlattened ? blockRoutes[block] : 0u;
							uint verifier = FlowVerifier(entryState, start + 1, k1, k2, k3, _context.XorSeed);
							var successorRecords = new List<ChunkSuccessor>();
							foreach (ControlFlowBlock successor in block.Successors.OrderBy(value => value.Start))
							{
								int successorStart = successor.Start + 1;
								uint wrappedState = blockStates[successor] ^
								                    FlowKey(entryState, block.EndExclusive, successorStart, k1, k2, k3, _context.XorSeed);
								uint wrappedChunkState = blockChunkStates[successor] ^ ChunkChainKey(
									sourceChunkState, entryState, block.EndExclusive, successorStart, k1, k2, k3,
									_context.XorSeed, payloadAttestation);
								successorRecords.Add(new ChunkSuccessor
								{
									Destination = successorStart,
									WrappedEntryState = wrappedState,
									WrappedChunkState = wrappedChunkState
								});
							}
							byte[] encodedBlockBody = blockBody.ToArray();
							uint blockTag = ComputeBlockIntegrity(encodedBlockBody, entryState, start + 1, count,
								routeToken, constantReferences, verifier, successorRecords, k1, k2, k3,
								_context.XorSeed);

							WriteUInt32Local((uint)(start + 1));
							WriteUInt32Local((uint)count);
							WriteUInt32Local(routeToken);
							WriteUInt32Local((uint)constantReferences.Count);
							foreach (int constantIndex in constantReferences)
								WriteUInt32Local((uint)constantIndex);
							WriteUInt32Local(verifier);
							WriteUInt32Local(blockTag);
							WriteUInt32Local((uint)successorRecords.Count);
							foreach (ChunkSuccessor successor in successorRecords)
							{
								WriteUInt32Local((uint)successor.Destination);
								WriteUInt32Local(successor.WrappedEntryState);
								WriteUInt32Local(successor.WrappedChunkState);
							}

							WriteUInt32Local((uint)encodedBlockBody.Length);
							output.AddRange(encodedBlockBody);
						}
						break;
					case ChunkStep.Functions:
						WriteUInt32Local((uint)chunk.Functions.Count);
						foreach (Chunk child in chunk.Functions)
						{
							// Length framing lets the VM retain child prototypes as opaque byte
							// slices and deserialize each one only when OP_CLOSURE first needs it.
							byte[] childBody = SerializeBody(child);
							WriteUInt32Local((uint)childBody.Length);
							output.AddRange(childBody);
						}
						break;
					case ChunkStep.LineInfo when _settings.PreserveLineInfo:
						WriteUInt32Local((uint)chunk.Instructions.Count);
						foreach (Instruction instruction in chunk.Instructions)
							WriteUInt32Local(unchecked((uint)instruction.Line));
						break;
				}
				}

				byte[] result = bytes.ToArray();
				WriteUInt32(result, 6, ComputePrototypeIntegrity(result, k1, k2, k3));
				return result;
			}
		}
	}
