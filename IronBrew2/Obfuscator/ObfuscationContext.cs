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
		public InstructionStep1[] InstructionSteps1;
		public InstructionStep2[] InstructionSteps2;

		public Dictionary<Opcode, VOpcode> InstructionMapping = new Dictionary<Opcode, VOpcode>();

		// 在 VM opcode 收集和 shuffle 后由 Generator 设置，serializer 用它为每个
		// prototype 派生独立的 local-index -> canonical-index bank。
		public int VirtualOpcodeCount;
		public int VirtualOpcodeAliasCount;

		// 流式 XOR 种子(32 位)。EnvironmentLock 开启时 = Hash(盐|attestation token)，
		// 序列化头部只写盐，VM 端严格探针成功后才派生同一种子。
		public uint XorSeed;

		// 环境绑定器：生成盐、attestation token 和 VM 端种子派生代码
		public EnvBinder Binder;

		// One CSPRNG root drives purpose-separated streams for this entire build.
		// Serializer/runtime 共享的每 Build domain、record kind 与 permutation salt。
		// 它们不是秘密，但会让旧 Build 的固定解析坐标无法直接复用。
		public BuildSeed Seed;
		public BuildDomains Domains;
		public PayloadDerivationProfile PayloadDerivation;
		public PayloadFormatLayout PayloadFormat;
		
		public ObfuscationContext(Chunk chunk, ObfuscationSettings settings, BuildSeed seed)
		{
			HeadChunk = chunk;
			Seed = seed ?? throw new ArgumentNullException(nameof(seed));
			Domains = new BuildDomains(Seed.GetStream("payload.domains"));
			PayloadDerivation = new PayloadDerivationProfile(Domains);
			PayloadFormat = new PayloadFormatLayout(Domains);

			BuildRandom schemaRandom = Seed.GetStream("bytecode.schema");
			InstructionSteps1 = Enumerable.Range(0, (int) InstructionStep1.StepCount).Select(i => (InstructionStep1) i).ToArray();
			InstructionSteps1.Shuffle(schemaRandom);
			
			InstructionSteps2 = Enumerable.Range(0, (int) InstructionStep2.StepCount).Select(i => (InstructionStep2) i).ToArray();
			InstructionSteps2.Shuffle(schemaRandom);

			Binder = new EnvBinder(Seed.GetStream("environment.binding"), PayloadDerivation);

			if (settings.EnvironmentLock)
			{
				// 只有严格 executor guard 成功后才恢复同一 token 与 serializer seed。
				XorSeed = Binder.DeriveSeed(Binder.AttestationToken);
			}
			else
			{
				// 不绑定环境：由 Build Seed 的独立流产生，头部明文写种子。
				XorSeed = Seed.GetStream("payload.outer-seed").NextUInt32();
			}
			if (XorSeed == 0)
				XorSeed = 0x9E3779B9;
		}
	}
}