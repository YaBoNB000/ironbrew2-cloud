using System;
using System.Collections.Generic;
using System.Linq;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	public class OpMutated : VOpcode
	{
		public static Random rand = new Random(System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue));
		
		public VOpcode Mutated;
		public int[] Registers;

		public static string[] RegisterReplacements = {"OP__A", "OP__B", "OP__C"};
		
		public override bool IsInstruction(Instruction instruction) =>
			false;

		public bool CheckInstruction() =>
			rand.Next(1, 15) == 1;	
		
		public override string GetObfuscated(ObfuscationContext context)
		{
			string code = Mutated.GetObfuscated(context);

			// P2: 随机形态变形——把 Inst[OP_A/B/C] 提取成局部变量,改变 handler 代码形态
			int roll = rand.Next(4);
			if (roll == 0)
			{
				string lv = "_m" + rand.Next(1000, 9999);
				code = "local " + lv + "=Inst[OP_A];" + code.Replace("Inst[OP_A]", lv);
			}
			else if (roll == 1)
			{
				string lv = "_m" + rand.Next(1000, 9999);
				code = "local " + lv + "=Inst[OP_B];" + code.Replace("Inst[OP_B]", lv);
			}
			else if (roll == 2)
			{
				string lv = "_m" + rand.Next(1000, 9999);
				code = "local " + lv + "=Inst[OP_C];" + code.Replace("Inst[OP_C]", lv);
			}

			return code;
		}

		public override void Mutate(Instruction instruction)
		{
			Mutated.Mutate(instruction);
		}
	}
}