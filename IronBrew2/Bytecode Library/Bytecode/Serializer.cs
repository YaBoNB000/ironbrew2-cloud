using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;
using IronBrew2.Obfuscator.Control_Flow;

namespace IronBrew2.Bytecode_Library.Bytecode
{
	public class Serializer
	{
		private const byte FormatVersion = 3;
		private const byte BasicBlockFeature = 2;
		private const byte DispatcherFlatteningFeature = 4;
		private const byte EntropyEnvelopeFeature = 8;
		private const int MaxBlockInstructions = DispatcherFlatteningPlanner.MaxBlockInstructions;
		private const int EntropyMinBytes = 64 * 1024;
		private const int EntropyMaxBytes = 96 * 1024;
		private const byte EntropyRecordKind = 0xA7;
		private const byte DataRecordKind = 0x5C;
		private const uint IntegrityDomain = 0xA5C31F27u;
		private const uint BlockIntegrityDomain = 0x7F4A7C15u;
		private const uint FlowDomain = 0x6D2B79F5u;
		private const uint EnvelopeIntegrityDomain = 0xC4D29A6Bu;
		private const uint EntropyDigestDomain = 0x91E10DA5u;
		private const uint EnvelopeMaskDomain = 0x3A75C9EFu;

		private sealed class EntropyRecord
		{
			public byte Kind { get; init; }
			public ushort Ordinal { get; init; }
			public byte[] Data { get; init; }
		}

		private readonly ObfuscationContext _context;
		private readonly ObfuscationSettings _settings;
		private readonly Encoding _luaEncoding = Encoding.GetEncoding(28591);

		public Serializer(ObfuscationContext context, ObfuscationSettings settings)
		{
			_context = context;
			_settings = settings;
		}

		/// <summary>
		/// v3 顶层格式（固定 9 字节头）：
		///   head/salt 4B | integrity tag 4B | version+flags 1B | encrypted envelope
		/// 压缩后的真实 body 被拆为多个 data records，并与 64–96 KiB CSPRNG entropy
		/// records 交错。entropy digest 同时派生内层 body mask；物理 record 顺序由独立
		/// envelope tag 认证，因此删除、修改或重排 record 都不能退化为可移除 padding。
		/// K1/K2/K3 不再出现在明文头，而是每个 prototype 独立生成并放入保护正文。
		/// </summary>
		public byte[] SerializeLChunk(Chunk chunk)
		{
			byte[] plain = SerializeBody(chunk);
			byte[] payload = _settings.BytecodeCompress ? Deflate(plain) : plain;
			byte[] envelope = WrapEntropyEnvelope(payload, _context.XorSeed);

			uint state = _context.XorSeed;
			byte[] encrypted = new byte[envelope.Length];
			for (int i = 0; i < envelope.Length; i++)
			{
				encrypted[i] = (byte)(envelope[i] ^ (byte)(state >> 24));
				state = unchecked(state * 1664525u + 1013904223u);
			}

			uint head = _settings.EnvironmentLock ? _context.Binder.Salt : _context.XorSeed;
			byte flags = (byte)((FormatVersion << 4) | BasicBlockFeature | DispatcherFlatteningFeature |
			                    EntropyEnvelopeFeature | (_settings.BytecodeCompress ? 1 : 0));
			// Bind both the format/feature byte and encrypted body. This is tamper/corruption
			// detection, not a client-side cryptographic trust root.
			uint integrity = ComputeIntegrity(encrypted, _context.XorSeed, flags);

			var output = new List<byte>(encrypted.Length + 9);
			WriteUInt32(output, head);
			WriteUInt32(output, integrity);
			output.Add(flags);
			output.AddRange(encrypted);
			return output.ToArray();
		}

		private static uint ComputeIntegrity(byte[] encrypted, uint seed, byte flags)
		{
			uint hash = unchecked((seed ^ IntegrityDomain) * 31u + flags);
			foreach (byte value in encrypted)
				hash = unchecked(hash * 31u + value);
			return hash;
		}

		private static byte[] WrapEntropyEnvelope(byte[] payload, uint seed)
		{
			if (payload == null || payload.Length == 0)
				throw new InvalidOperationException("Cannot envelope an empty protected payload.");

			int entropyLength = RandomNumberGenerator.GetInt32(EntropyMinBytes, EntropyMaxBytes + 1);
			byte[] entropy = RandomNumberGenerator.GetBytes(entropyLength);
			uint nonce = NextState32();

			List<byte[]> entropyParts = SplitRandom(entropy, RandomNumberGenerator.GetInt32(12, 21));
			List<byte[]> dataParts = SplitRandom(payload, RandomNumberGenerator.GetInt32(4, 9));
			uint entropyDigest = ComputeEntropyDigest(entropyParts, seed, nonce, entropyLength);

			uint maskState = seed ^ nonce ^ entropyDigest ^ EnvelopeMaskDomain ^ (uint)payload.Length;
			byte[] maskedPayload = new byte[payload.Length];
			for (int index = 0; index < payload.Length; index++)
			{
				maskedPayload[index] = (byte)(payload[index] ^ (byte)(maskState >> 24));
				maskState = unchecked(maskState * 1664525u + 1013904223u);
			}
			dataParts = SplitAtLengths(maskedPayload, dataParts.Select(part => part.Length));

			var records = new List<EntropyRecord>(entropyParts.Count + dataParts.Count);
			for (int index = 0; index < entropyParts.Count; index++)
				records.Add(new EntropyRecord {Kind = EntropyRecordKind, Ordinal = (ushort)(index + 1), Data = entropyParts[index]});
			for (int index = 0; index < dataParts.Count; index++)
				records.Add(new EntropyRecord {Kind = DataRecordKind, Ordinal = (ushort)(index + 1), Data = dataParts[index]});
			ShuffleEntropyRecords(records);

			// 8 x u32 fields. The final field is patched with a keyed envelope tag.
			var envelope = new List<byte>(32 + records.Count * 7 + entropyLength + payload.Length);
			WriteUInt32(envelope, (uint)payload.Length);
			WriteUInt32(envelope, (uint)entropyLength);
			WriteUInt32(envelope, (uint)records.Count);
			WriteUInt32(envelope, (uint)dataParts.Count);
			WriteUInt32(envelope, (uint)entropyParts.Count);
			WriteUInt32(envelope, nonce);
			WriteUInt32(envelope, entropyDigest);
			WriteUInt32(envelope, 0u);
			foreach (EntropyRecord record in records)
			{
				envelope.Add(record.Kind);
				WriteUInt16(envelope, record.Ordinal);
				WriteUInt32(envelope, (uint)record.Data.Length);
				envelope.AddRange(record.Data);
			}

			byte[] result = envelope.ToArray();
			uint tag = ComputeEnvelopeIntegrity(result, seed);
			WriteUInt32(result, 28, tag);
			return result;
		}

		private static List<byte[]> SplitRandom(byte[] data, int requestedCount)
		{
			int count = Math.Max(1, Math.Min(requestedCount, data.Length));
			if (count == 1)
				return new List<byte[]> {data.ToArray()};

			var cuts = new HashSet<int>();
			while (cuts.Count < count - 1)
				cuts.Add(RandomNumberGenerator.GetInt32(1, data.Length));
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

		private static uint ComputeEntropyDigest(IReadOnlyList<byte[]> records, uint seed, uint nonce, int totalLength)
		{
			uint hash = unchecked((seed ^ EntropyDigestDomain) * 31u + nonce);
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

		private static uint ComputeEnvelopeIntegrity(byte[] envelope, uint seed)
		{
			uint hash = unchecked((seed ^ EnvelopeIntegrityDomain) * 31u);
			for (int index = 0; index < envelope.Length; index++)
			{
				// Bytes 28..31 hold the tag itself and are intentionally omitted.
				if (index >= 28 && index < 32) continue;
				hash = unchecked(hash * 31u + envelope[index]);
			}
			return hash;
		}

		private static void ShuffleEntropyRecords(List<EntropyRecord> records)
		{
			int transitions;
			do
			{
				for (int index = records.Count - 1; index > 0; index--)
				{
					int swapIndex = RandomNumberGenerator.GetInt32(index + 1);
					(records[index], records[swapIndex]) = (records[swapIndex], records[index]);
				}
				transitions = 0;
				for (int index = 1; index < records.Count; index++)
					if (records[index - 1].Kind != records[index].Kind) transitions++;
			} while (transitions < 2);
		}

		private static ushort NextKey16() =>
			(ushort)RandomNumberGenerator.GetInt32(1, 65536);

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

		private static uint NextState32()
		{
			uint state;
			do
			{
				state = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(sizeof(uint)), 0);
			} while (state == 0);
			return state;
		}

		private static uint InitialFlowKey(ushort k1, ushort k2, ushort k3)
		{
			uint value = unchecked((uint)k1 * 65537u + (uint)k2 * 257u + k3 + FlowDomain);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private static uint FlowKey(uint entryState, int fromPc, int toPc, ushort k1, ushort k2, ushort k3)
		{
			uint value = unchecked(entryState * 1664525u + (uint)fromPc * 257u +
			                       (uint)toPc * 65537u + (uint)k1 * 251u +
			                       (uint)k2 * 17u + k3 + FlowDomain);
			return unchecked(value * 1664525u + 1013904223u);
		}

		private static uint FlowVerifier(uint entryState, int blockStart, ushort k1, ushort k2, ushort k3) =>
			FlowKey(entryState, blockStart, blockStart ^ 0x5A5A, k1, k2, k3);

		private static ushort BlockFieldMask(uint entryState, int pc, int slot, ushort k1, ushort k2, ushort k3)
		{
			uint low = entryState & 0xFFFFu;
			uint high = entryState >> 16;
			return (ushort)((low * (uint)((pc + slot * 29) % 251 + 1) + high * 17u +
			                 (uint)k1 * 13u + (uint)k2 * 7u + k3 + (uint)slot * 911u) & 0xFFFFu);
		}

		private static uint ComputeBlockIntegrity(byte[] body, uint entryState, int start, int count,
			ushort k1, ushort k2, ushort k3)
		{
			uint hash = unchecked((entryState ^ BlockIntegrityDomain) * 31u + (uint)start);
			hash = unchecked(hash * 31u + (uint)count);
			hash = unchecked(hash * 31u + k1);
			hash = unchecked(hash * 31u + k2);
			hash = unchecked(hash * 31u + k3);
			foreach (byte value in body)
				hash = unchecked(hash * 31u + value);
			return hash;
		}

		private static void ShuffleBlocks(List<ControlFlowBlock> blocks)
		{
			for (int index = blocks.Count - 1; index > 0; index--)
			{
				int swapIndex = RandomNumberGenerator.GetInt32(index + 1);
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
			int[] opcodeBank = DerivePermutation(_context.VirtualOpcodeCount, k1, k2, k3, 1777u);
			int[] opcodeToLocal = new int[opcodeBank.Length];
			for (int localIndex = 0; localIndex < opcodeBank.Length; localIndex++)
				opcodeToLocal[opcodeBank[localIndex]] = localIndex;

			void WriteByte(byte value) => output.Add(value);
			void WriteUInt16Local(ushort value) => WriteUInt16(output, value);
			void WriteUInt32Local(uint value) => WriteUInt32(output, value);

			void WriteRaw(byte[] value, bool checkEndian = true)
			{
				if (!BitConverter.IsLittleEndian && checkEndian)
					value = value.Reverse().ToArray();
				output.AddRange(value);
			}

			void WriteNumber(double value) => WriteRaw(BitConverter.GetBytes(value));
			void WriteBool(bool value) => WriteByte(value ? (byte)1 : (byte)0);

			void WriteProtectedString(string value, int constantIndex)
			{
				byte[] raw = _luaEncoding.GetBytes(value);
				WriteUInt32Local((uint)raw.Length);

				int oneBasedIndex = constantIndex + 1;
				uint state = (uint)((k1 + k2 + k3 + oneBasedIndex * 257L) % 65536L);
				foreach (byte item in raw)
				{
					WriteByte((byte)(item ^ (state & 0xFF)));
					state = (state * 251u + k3 + (uint)oneBasedIndex) & 0xFFFFu;
				}
			}

			void SerializeInstruction(Instruction instruction, int zeroBasedIndex, uint entryState)
			{
				int pc = zeroBasedIndex + 1;
				byte descriptorMask = (byte)BlockFieldMask(entryState, pc, 7, k1, k2, k3);
				if (instruction.InstructionType == InstructionType.Data)
				{
					WriteByte((byte)(1 ^ descriptorMask));
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
				WriteByte((byte)(((type << 1) | (constantMask << 3)) ^ descriptorMask));

				ushort storedOpcode = (ushort)((ushort)opcode ^ OpcodeMask(pc, k1, k2, k3) ^
				                               BlockFieldMask(entryState, pc, 0, k1, k2, k3));
				ushort storedA = (ushort)((ushort)instruction.A ^ OperandMask16(pc, k1, k2, k3, 1) ^
				                          BlockFieldMask(entryState, pc, 1, k1, k2, k3));
				WriteUInt16Local(storedOpcode);
				WriteUInt16Local(storedA);

				uint BlockMask32(int slot) =>
					(uint)(BlockFieldMask(entryState, pc, slot, k1, k2, k3) |
					       (BlockFieldMask(entryState, pc, slot + 4, k1, k2, k3) << 16));

				int b = instruction.B;
				int c = instruction.C;
				switch (instruction.InstructionType)
				{
					case InstructionType.AsBx:
						WriteUInt32Local(unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						break;
					case InstructionType.AsBxC:
						WriteUInt32Local(unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						WriteUInt16Local((ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3) ^
						                              BlockFieldMask(entryState, pc, 3, k1, k2, k3)));
						break;
					case InstructionType.ABC:
						WriteUInt16Local((ushort)((ushort)b ^ OperandMask16(pc, k1, k2, k3, 2) ^
						                              BlockFieldMask(entryState, pc, 2, k1, k2, k3)));
						WriteUInt16Local((ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3) ^
						                              BlockFieldMask(entryState, pc, 3, k1, k2, k3)));
						break;
					case InstructionType.ABx:
						WriteUInt32Local(unchecked((uint)b) ^ OperandMask32(pc, k1, k2, k3, 2) ^ BlockMask32(2));
						break;
				}
			}

			chunk.UpdateMappings();
			DispatcherFlatteningDecision flattening = _settings.ControlFlow
				? DispatcherFlatteningPlanner.Apply(chunk)
				: null;
			if (!_settings.ControlFlow)
			{
				chunk.DispatcherFlattened = false;
				chunk.DispatcherFlatteningReason = "control-flow-disabled";
			}

			ControlFlowGraph controlFlow = flattening?.Graph ??
			                                   ControlFlowGraph.Build(chunk, MaxBlockInstructions);
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

			// Preserve the original linear mutation order. Several comparison/test
			// opcodes consume the following JMP's still-relative B operand while
			// mutating, even though blocks are emitted in randomized order below.
			foreach (Instruction instruction in chunk.Instructions)
				instruction.UpdateRegisters();
			foreach (Instruction instruction in chunk.Instructions)
				instruction.CustomData?.Opcode?.Mutate(instruction);

			ShuffleBlocks(instructionBlocks);

			// 每 prototype 独立密钥位于外层加密正文中，不再泄露在固定头部。
			WriteUInt16Local(k1);
			WriteUInt16Local(k2);
			WriteUInt16Local(k3);

			// Schema 与常量 tag 都由当前 prototype 的独立 keys 派生，并使用不同 domain。
			// 因此父子 prototype 不再共享一个全局 ChunkSteps 或简单 tag rotation。
			int[] schema = DerivePermutation((int)ChunkStep.StepCount, k1, k2, k3, 113u);
			int[] constantTags = DerivePermutation(4, k1, k2, k3, 911u);

			void SerializeConstants()
			{
				WriteUInt32Local((uint)chunk.Constants.Count);
				for (int constantIndex = 0; constantIndex < chunk.Constants.Count; constantIndex++)
				{
					Constant constant = chunk.Constants[constantIndex];
					WriteByte((byte)constantTags[(int)constant.Type]);
					switch (constant.Type)
					{
						case ConstantType.Boolean:
							WriteBool(constant.Data);
							break;
						case ConstantType.Number:
							WriteNumber(constant.Data);
							break;
						case ConstantType.String:
							WriteProtectedString(constant.Data, constantIndex);
							break;
					}
				}
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
						WriteUInt32Local(blockStates[controlFlow.EntryBlock] ^ InitialFlowKey(k1, k2, k3));
						WriteUInt32Local(dispatcherFlattened ? blockRoutes[controlFlow.EntryBlock] : 0u);
						foreach (ControlFlowBlock block in instructionBlocks)
						{
							int start = block.Start;
							int count = block.Count;
							uint entryState = blockStates[block];
							var blockBody = new List<byte>();
							List<byte> savedOutput = output;
							output = blockBody;
							for (int offset = 0; offset < count; offset++)
								SerializeInstruction(chunk.Instructions[start + offset], start + offset, entryState);
							output = savedOutput;

							// Bind each opaque block only to the constants it can resolve. This
							// lets the VM release the prototype-wide constant cache immediately.
							var constantReferences = new HashSet<int>();
							for (int offset = 0; offset < count; offset++)
							{
								Instruction instruction = chunk.Instructions[start + offset];
								if ((instruction.ConstantMask & InstructionConstantMask.RA) != 0) constantReferences.Add(instruction.A);
								if ((instruction.ConstantMask & InstructionConstantMask.RB) != 0) constantReferences.Add(instruction.B);
								if ((instruction.ConstantMask & InstructionConstantMask.RC) != 0) constantReferences.Add(instruction.C);
							}

							WriteUInt32Local((uint)(start + 1));
							WriteUInt32Local((uint)count);
							WriteUInt32Local(dispatcherFlattened ? blockRoutes[block] : 0u);
							WriteUInt32Local((uint)constantReferences.Count);
							foreach (int constantIndex in constantReferences.OrderBy(value => value))
							{
								if (constantIndex < 1 || constantIndex > chunk.Constants.Count)
									throw new InvalidOperationException("Invalid block constant reference.");
								WriteUInt32Local((uint)constantIndex);
							}

							WriteUInt32Local(FlowVerifier(entryState, start + 1, k1, k2, k3));
							WriteUInt32Local(ComputeBlockIntegrity(blockBody.ToArray(), entryState, start + 1, count, k1, k2, k3));
							WriteUInt32Local((uint)block.Successors.Count);
							foreach (ControlFlowBlock successor in block.Successors.OrderBy(value => value.Start))
							{
								int successorStart = successor.Start + 1;
								uint wrappedState = blockStates[successor] ^
								                    FlowKey(entryState, block.EndExclusive, successorStart, k1, k2, k3);
								WriteUInt32Local((uint)successorStart);
								WriteUInt32Local(wrappedState);
							}

							WriteUInt32Local((uint)blockBody.Count);
							output.AddRange(blockBody);
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

			return bytes.ToArray();
		}
	}
}
