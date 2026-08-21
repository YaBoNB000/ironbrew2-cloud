using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	internal static class CallTrampoline
	{
		internal static string Emit(ObfuscationContext context, CallMode mode) =>
			"Top=HandlerCall(" + context.CallModeTokens[(int)mode] + ",Inst,Top);";
	}

	public class OpCall : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B > 2 && instruction.C > 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.FixedArgumentsFixedResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.B += instruction.A - 1;
			instruction.C += instruction.A - 2;
		}
	}

	public class OpCallB2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 2 && instruction.C > 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.SingleArgumentFixedResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.C += instruction.A - 2;
		}
	}

	public class OpCallB0 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 0 && instruction.C > 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.TopArgumentsFixedResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.C += instruction.A - 2;
		}
	}

	public class OpCallB1 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 1 && instruction.C > 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.NoArgumentsFixedResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.C += instruction.A - 2;
		}
	}

	public class OpCallC0 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B > 2 && instruction.C == 0;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.FixedArgumentsVariableResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.B += instruction.A - 1;
		}
	}

	public class OpCallC0B2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 2 && instruction.C == 0;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.SingleArgumentVariableResults);
	}

	public class OpCallC1 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B > 2 && instruction.C == 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.FixedArgumentsDiscardResults);

		public override void Mutate(Instruction instruction)
		{
			instruction.B += instruction.A - 1;
		}
	}

	public class OpCallC1B2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 2 && instruction.C == 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.SingleArgumentDiscardResults);
	}

	public class OpCallB0C0 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 0 && instruction.C == 0;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.TopArgumentsVariableResults);
	}

	public class OpCallB0C1 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 0 && instruction.C == 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.TopArgumentsDiscardResults);
	}

	public class OpCallB1C0 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 1 && instruction.C == 0;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.NoArgumentsVariableResults);
	}

	public class OpCallB1C1 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 1 && instruction.C == 1;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.NoArgumentsDiscardResults);
	}

	public class OpCallC2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B > 2 && instruction.C == 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.FixedArgumentsSingleResult);

		public override void Mutate(Instruction instruction)
		{
			instruction.B += instruction.A - 1;
		}
	}

	public class OpCallC2B2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 2 && instruction.C == 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.SingleArgumentSingleResult);
	}

	public class OpCallB0C2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 0 && instruction.C == 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.TopArgumentsSingleResult);
	}

	public class OpCallB1C2 : VOpcode
	{
		public override bool IsInstruction(Instruction instruction) =>
			instruction.OpCode == Opcode.Call && instruction.B == 1 && instruction.C == 2;

		public override string GetObfuscated(ObfuscationContext context) =>
			CallTrampoline.Emit(context, CallMode.NoArgumentsSingleResult);
	}
}
