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
		private const int MaxBlockInstructions = DispatcherFlatteningPlanner.MaxBlockInstructions;
		private const uint IntegrityDomain = 0xA5C31F27u;
		private const uint BlockIntegrityDomain = 0x7F4A7C15u;
		private const uint FlowDomain = 0x6D2B79F5u;

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
		///   head/salt 4B | integrity tag 4B | version+flags 1B | encrypted body
		/// K1/K2/K3 不再出现在明文头，而是每个 prototype 独立生成并放入加密正文。
		/// </summary>
		public byte[] SerializeLChunk(Chunk chunk)
		{
			byte[] plain = SerializeBody(chunk);
			byte[] payload = _settings.BytecodeCompress ? Deflate(plain) : plain;

			uint state = _context.XorSeed;
			byte[] encrypted = new byte[payload.Length];
			for (int i = 0; i < payload.Length; i++)
			{
				encrypted[i] = (byte)(payload[i] ^ (byte)(state >> 24));
				state = unchecked(state * 1664525u + 1013904223u);
			}

			uint head = _settings.EnvironmentLock ? _context.Binder.Salt : _context.XorSeed;
			byte flags = (byte)((FormatVersion << 4) | BasicBlockFeature | DispatcherFlatteningFeature |
			                    (_settings.BytecodeCompress ? 1 : 0));
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
