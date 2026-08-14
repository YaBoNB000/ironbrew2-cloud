using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;

namespace IronBrew2.Bytecode_Library.Bytecode
{
	public class Serializer
	{
		private ObfuscationContext _context;
		private ObfuscationSettings _settings;
		private Random _r = new Random();
		private int _k1 = 1, _k2 = 1;
		private Encoding _fuckingLua = Encoding.GetEncoding(28591);

		public Serializer(ObfuscationContext context, ObfuscationSettings settings)
		{
			_context = context;
			_settings = settings;
		}

		/// <summary>
		/// 顶层序列化:明文 body → LZ77 压缩(加密前) → 流式 XOR 加密 → 拼 8 字节明文头(盐 + K1/K2)。
		/// VM 端:base91 解码 → 读盐派生种子 → 读 K1/K2 → 整体 XOR 解密 → LZ77 解压 → 解析。
		/// </summary>
		public byte[] SerializeLChunk(Chunk chunk)
		{
			// 指令流 opcode 加密密钥(VM 端主循环按 InstrPoint 逐条解密)
			_k1 = _r.Next(1, 65536);
			_k2 = _r.Next(1, 65536);

			// 1. 明文序列化 body(opcode 用 K1/K2 逐条加密,其余明文)
			byte[] plain = SerializeBody(chunk);

			// 2. 压缩(DEFLATE/RFC1951) —— 必须在加密前,加密后高熵无法压缩
			byte[] payload = _settings.BytecodeCompress ? Deflate(plain) : plain;

			// 3. 流式 XOR 加密
			uint state = _context.XorSeed;
			byte[] enc = new byte[payload.Length];
			for (int i = 0; i < payload.Length; i++)
			{
				enc[i] = (byte)(payload[i] ^ (byte)(state >> 24));
				state = state * 1664525u + 1013904223u;
			}

			// 4. 拼头(盐 4B + K1 2B + K2 2B + 压缩标志 1B,明文)+ 加密 body
			var outList = new List<byte>(enc.Length + 9);
			uint head = _settings.EnvironmentLock ? _context.Binder.Salt : _context.XorSeed;
			outList.Add((byte)head);
			outList.Add((byte)(head >> 8));
			outList.Add((byte)(head >> 16));
			outList.Add((byte)(head >> 24));
			outList.Add((byte)_k1);
			outList.Add((byte)(_k1 >> 8));
			outList.Add((byte)_k2);
			outList.Add((byte)(_k2 >> 8));
			// 压缩标志:1 = body 经 LZ77 压缩(VM 端需先解压),0 = 明文 body
			outList.Add((byte)(_settings.BytecodeCompress ? 1 : 0));
			outList.AddRange(enc);
			return outList.ToArray();
		}

		/// <summary>raw DEFLATE 压缩(RFC 1951,与 .NET DeflateStream / Python zlib / Java Deflater 兼容)。</summary>
		private static byte[] Deflate(byte[] data)
		{
			using (var ms = new MemoryStream())
			using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, true))
			{
				ds.Write(data, 0, data.Length);
				ds.Flush();
				ds.Close();
				return ms.ToArray();
			}
		}

		/// <summary>明文序列化(不含头、不 XOR),供 DEFLATE 压缩使用;递归子函数也走明文。</summary>
		private byte[] SerializeBody(Chunk chunk)
		{
			List<byte> bytes = new List<byte>();

			void WriteByte(byte b) =>
				bytes.Add(b);

			void Write(byte[] b, bool checkEndian = true)
			{
				if (!BitConverter.IsLittleEndian && checkEndian)
					b = b.Reverse().ToArray();

				foreach (byte x in b)
					bytes.Add(x);
			}

			void WriteInt32(int i) =>
				Write(BitConverter.GetBytes(i));

			void WriteInt16(short i) =>
				Write(BitConverter.GetBytes(i));

			void WriteNumber(double d) =>
				Write(BitConverter.GetBytes(d));

			void WriteString(string s)
			{
				byte[] sBytes = _fuckingLua.GetBytes(s);

				WriteInt32(sBytes.Length);
				Write(sBytes, false);
			}

			void WriteBool(bool b) =>
				Write(BitConverter.GetBytes(b));

			void SerializeInstruction(Instruction inst, int instIndex)
			{
				if (inst.InstructionType == InstructionType.Data)
				{
					WriteByte(1);
					return;
				}
				inst.UpdateRegisters();

				var cData = inst.CustomData;
				int opCode = (int)inst.OpCode;

				if (cData != null)
				{
					var virtualOpcode = cData.Opcode;

					opCode = cData.WrittenOpcode?.VIndex ?? virtualOpcode.VIndex;
					virtualOpcode?.Mutate(inst);
				}

				int t = (int)inst.InstructionType;
				int m = (int)inst.ConstantMask;
				WriteByte((byte)((t << 1) | (m << 3)));
				// 指令流运行时加密:opcode 按指令序号派生密钥异或(内存中无完整明文指令流,
				// VM 端主循环用 InstrPoint 逐条解密;序号用 instIndex+1 与 VM 的 InstrPoint(1-based)对齐)
				opCode ^= (int)(((long) (instIndex + 1) * _k1 + _k2) % 65536);
				WriteInt16((short)opCode);
				WriteInt16((short)inst.A);

				int b = inst.B;
				int c = inst.C;

				switch (inst.InstructionType)
				{
					case InstructionType.AsBx:
						b += 1 << 16;
						WriteInt32(b);
						break;
					case InstructionType.AsBxC:
						b += 1 << 16;
						WriteInt32(b);
						WriteInt16((short)c);
						break;
					case InstructionType.ABC:
						WriteInt16((short)b);
						WriteInt16((short)c);
						break;
					case InstructionType.ABx:
						WriteInt32(b);
						break;
				}
			}

			chunk.UpdateMappings();

			WriteInt32(chunk.Constants.Count);
			foreach (Constant c in chunk.Constants)
			{
				WriteByte((byte)_context.ConstantMapping[(int)c.Type]);
				switch (c.Type)
				{
					case ConstantType.Boolean:
						WriteBool(c.Data);
						break;
					case ConstantType.Number:
						WriteNumber(c.Data);
						break;
					case ConstantType.String:
						WriteString(c.Data);
						break;
				}
			}

			for (int i = 0; i < (int) ChunkStep.StepCount; i++)
			{
				switch (_context.ChunkSteps[i])
				{
					case ChunkStep.ParameterCount:
						WriteByte(chunk.ParameterCount);
						break;
					case ChunkStep.Instructions:
						WriteInt32(chunk.Instructions.Count);

						for (int instIdx = 0; instIdx < chunk.Instructions.Count; instIdx++)
							SerializeInstruction(chunk.Instructions[instIdx], instIdx);
						break;
					case ChunkStep.Functions:
						WriteInt32(chunk.Functions.Count);
						foreach (Chunk c in chunk.Functions)
							Write(SerializeBody(c));

						break;
					case ChunkStep.LineInfo when _settings.PreserveLineInfo:
						WriteInt32(chunk.Instructions.Count);
						foreach (var instr in chunk.Instructions)
							WriteInt32(instr.Line);
						break;
				}
			}

			return bytes.ToArray();
		}
	}
}
