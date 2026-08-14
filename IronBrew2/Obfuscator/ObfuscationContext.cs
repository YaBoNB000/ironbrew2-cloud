using System;
using System.Collections.Generic;
using System.Linq;
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
		public ChunkStep[] ChunkSteps;
		public InstructionStep1[] InstructionSteps1;
		public InstructionStep2[] InstructionSteps2;
		public int[] ConstantMapping;

		public Dictionary<Opcode, VOpcode> InstructionMapping = new Dictionary<Opcode, VOpcode>();

		public int PrimaryXorKey;
			
		public int IXorKey1;
		public int IXorKey2;

		// 流式 XOR 种子(32 位)。EnvironmentLock 开启时 = Hash(盐|环境指纹)，
		// 序列化头部只写"盐"，VM 端跑探针后才派生得到同一种子；否则头部明文写种子。
		public uint XorSeed;

		// 环境绑定器：生成盐、预期指纹、VM 端种子派生代码
		public EnvBinder Binder;
		
		public ObfuscationContext(Chunk chunk, ObfuscationSettings settings)
		{
			HeadChunk = chunk;
			ChunkSteps = Enumerable.Range(0, (int) ChunkStep.StepCount).Select(i => (ChunkStep) i).ToArray();
			ChunkSteps.Shuffle();
			
			InstructionSteps1 = Enumerable.Range(0, (int) InstructionStep1.StepCount).Select(i => (InstructionStep1) i).ToArray();
			InstructionSteps1.Shuffle();
			
			InstructionSteps2 = Enumerable.Range(0, (int) InstructionStep2.StepCount).Select(i => (InstructionStep2) i).ToArray();
			InstructionSteps2.Shuffle();
			
			ConstantMapping = Enumerable.Range(0, 4).ToArray();
			ConstantMapping.Shuffle();

			Random rand = new Random();
			
			PrimaryXorKey = rand.Next(0, 256);
			IXorKey1 = rand.Next(0, 256);
			IXorKey2 = rand.Next(0, 256);

			Binder = new EnvBinder();

			if (settings.EnvironmentLock)
			{
				// 种子 = Hash(盐 | 预期指纹)。真环境探针返回同指纹 → 种子一致。
				XorSeed = Binder.DeriveSeed(Binder.ExpectedFingerprint);
			}
			else
			{
				// 不绑定环境：随机种子，头部明文写种子（兼容 plain Lua 测试）。
				XorSeed = (uint) (rand.Next(1, int.MaxValue) ^ (rand.Next(1, int.MaxValue) << 1));
			}
			if (XorSeed == 0)
				XorSeed = 0x9E3779B9;
		}
	}
}