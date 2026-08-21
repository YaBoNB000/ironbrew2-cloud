using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	public class OpTailCall : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.TailCall && instruction.B > 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			"do return HandlerCall(" + context.CallModeTokens[(int)CallMode.TailFixedArguments] + ",Inst,Top);end;";

		public override void Mutate(Instruction instruction)
		{
			instruction.B += instruction.A - 1;
		}
	}

	public class OpTailCallB0 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.TailCall && instruction.B == 0;

		public override string GetObfuscated(ObfuscationContext context) =>
			"do return HandlerCall(" + context.CallModeTokens[(int)CallMode.TailTopArguments] + ",Inst,Top);end;";
	}

	public class OpTailCallB1 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.TailCall && instruction.B == 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			"do return HandlerCall(" + context.CallModeTokens[(int)CallMode.TailNoArguments] + ",Inst,Top);end;";
	}
}
