using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Extensions;

namespace IronBrew2.Obfuscator
{
	public enum ChunkStep
	{
		ParameterCount,
		StringTable,
		Instructions,
		Functions,
		LineInfo,
		StepCount
	}

	public enum InstructionStep1
	{
		Type,
		A,
		B,
		C,
		StepCount
	}

	public enum InstructionStep2
	{
		Op,
		Bx,
		D,
		StepCount
	}
	
	public class ObfuscationContext
	{
		public Chunk HeadChunk;
		public InstructionStep1[] InstructionSteps1;
		public InstructionStep2[] InstructionSteps2;

		public Dictionary<Opcode, VOpcode> InstructionMapping = new Dictionary<Opcode, VOpcode>();

		// 在 VM opcode 收集和 shuffle 后由 Generator 设置，serializer 用它为每个
		// prototype 派生独立的 local-index -> canonical-index bank。
		public int VirtualOpcodeCount;

		// 流式 XOR 种子(32 位)。EnvironmentLock 开启时 = Hash(盐|attestation token)，
		// 序列化头部只写盐，VM 端严格探针成功后才派生同一种子。
		public uint XorSeed;

		// 环境绑定器：生成盐、attestation token 和 VM 端种子派生代码
		public EnvBinder Binder;
		
		public ObfuscationContext(Chunk chunk, ObfuscationSettings settings)
		{
			HeadChunk = chunk;
			
			InstructionSteps1 = Enumerable.Range(0, (int) InstructionStep1.StepCount).Select(i => (InstructionStep1) i).ToArray();
			InstructionSteps1.Shuffle();
			
			InstructionSteps2 = Enumerable.Range(0, (int) InstructionStep2.StepCount).Select(i => (InstructionStep2) i).ToArray();
			InstructionSteps2.Shuffle();

			Binder = new EnvBinder();

			if (settings.EnvironmentLock)
			{
				// 只有严格 executor guard 成功后才恢复同一 token 与 serializer seed。
				XorSeed = Binder.DeriveSeed(Binder.AttestationToken);
			}
			else
			{
				// 不绑定环境：安全随机种子，头部明文写种子（兼容 plain Lua 测试）。
				XorSeed = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(sizeof(uint)), 0);
			}
			if (XorSeed == 0)
				XorSeed = 0x9E3779B9;
		}
	}
}