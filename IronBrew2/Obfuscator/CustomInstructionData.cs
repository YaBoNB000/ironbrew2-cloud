using System.Collections.Generic;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator
{
	public class CustomInstructionData
	{
		public VOpcode Opcode;
		public VOpcode WrittenOpcode;

		// An IR-native fusion keeps member IR nodes only on its physical head.
		// The serializer mutates supplemental members, lowers the sequence to one
		// record, and emits their combined operand/constant descriptor.
		public List<Instruction> FusedInstructions;
		public bool FusionContinuation;
	}
}