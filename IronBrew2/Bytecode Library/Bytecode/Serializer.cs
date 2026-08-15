using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;

namespace IronBrew2.Bytecode_Library.Bytecode
{
	public class Serializer
	{
		private const byte FormatVersion = 2;
		private const uint IntegrityDomain = 0xA5C31F27u;

		private readonly ObfuscationContext _context;
		private readonly ObfuscationSettings _settings;
		private readonly Encoding _luaEncoding = Encoding.GetEncoding(28591);

		public Serializer(ObfuscationContext context, ObfuscationSettings settings)
		{
			_context = context;
			_settings = settings;
		}

		/// <summary>
		/// v2 顶层格式（固定 9 字节头）：
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
			byte flags = (byte)((FormatVersion << 4) | (_settings.BytecodeCompress ? 1 : 0));
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

			void WriteByte(byte value) => bytes.Add(value);
			void WriteUInt16Local(ushort value) => WriteUInt16(bytes, value);
			void WriteUInt32Local(uint value) => WriteUInt32(bytes, value);

			void WriteRaw(byte[] value, bool checkEndian = true)
			{
				if (!BitConverter.IsLittleEndian && checkEndian)
					value = value.Reverse().ToArray();
				bytes.AddRange(value);
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

			void SerializeInstruction(Instruction instruction, int zeroBasedIndex)
			{
				if (instruction.InstructionType == InstructionType.Data)
				{
					WriteByte(1);
					return;
				}

				instruction.UpdateRegisters();
				int opcode = (int)instruction.OpCode;
				if (instruction.CustomData != null)
				{
					var virtualOpcode = instruction.CustomData.Opcode;
					opcode = instruction.CustomData.WrittenOpcode?.VIndex ?? virtualOpcode.VIndex;
					virtualOpcode?.Mutate(instruction);
				}

				opcode = opcodeToLocal[opcode];

				int pc = zeroBasedIndex + 1;
				int type = (int)instruction.InstructionType;
				int constantMask = (int)instruction.ConstantMask;
				WriteByte((byte)((type << 1) | (constantMask << 3)));

				ushort storedOpcode = (ushort)((ushort)opcode ^ OpcodeMask(pc, k1, k2, k3));
				ushort storedA = (ushort)((ushort)instruction.A ^ OperandMask16(pc, k1, k2, k3, 1));
				WriteUInt16Local(storedOpcode);
				WriteUInt16Local(storedA);

				int b = instruction.B;
				int c = instruction.C;
				switch (instruction.InstructionType)
				{
					case InstructionType.AsBx:
						WriteUInt32Local(unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2));
						break;
					case InstructionType.AsBxC:
						WriteUInt32Local(unchecked((uint)(b + (1 << 16))) ^ OperandMask32(pc, k1, k2, k3, 2));
						WriteUInt16Local((ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3)));
						break;
					case InstructionType.ABC:
						WriteUInt16Local((ushort)((ushort)b ^ OperandMask16(pc, k1, k2, k3, 2)));
						WriteUInt16Local((ushort)((ushort)c ^ OperandMask16(pc, k1, k2, k3, 3)));
						break;
					case InstructionType.ABx:
						WriteUInt32Local(unchecked((uint)b) ^ OperandMask32(pc, k1, k2, k3, 2));
						break;
				}
			}

			chunk.UpdateMappings();

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
						for (int instructionIndex = 0; instructionIndex < chunk.Instructions.Count; instructionIndex++)
							SerializeInstruction(chunk.Instructions[instructionIndex], instructionIndex);
						break;
					case ChunkStep.Functions:
						WriteUInt32Local((uint)chunk.Functions.Count);
						foreach (Chunk child in chunk.Functions)
						{
							// Length framing lets the VM retain child prototypes as opaque byte
							// slices and deserialize each one only when OP_CLOSURE first needs it.
							byte[] childBody = SerializeBody(child);
							WriteUInt32Local((uint)childBody.Length);
							bytes.AddRange(childBody);
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
