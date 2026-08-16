using System;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	/// <summary>
	/// Build-local semantic alias. Several virtual opcode IDs may intentionally
	/// execute the same logical instruction, while Generator applies an independent
	/// handler data-flow/template variant to each ID. This makes opcode count and
	/// ID-to-semantics cardinality vary without changing source-language behavior.
	/// </summary>
	public sealed class OpAlias : VOpcode
	{
		public VOpcode Target { get; set; }

		public override bool IsInstruction(Instruction instruction) => false;

		public override string GetObfuscated(ObfuscationContext context) =>
			(Target ?? throw new InvalidOperationException("Opcode alias target was not initialized."))
			.GetObfuscated(context);

		public override void Mutate(Instruction instruction) =>
			(Target ?? throw new InvalidOperationException("Opcode alias target was not initialized."))
			.Mutate(instruction);
	}
}
