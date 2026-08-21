using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	public class OpSuperOperator : VOpcode
	{
		public VOpcode[] SubOpcodes;
		public bool CallInclusive;
		// Each semantic member now has two independent states. The select state
		// chooses a build-random physical operand slot; only its successor execute
		// state contains semantics. Branches for both phases are physically shuffled.
		public uint[] MemberTokens;
		public uint[] MemberExecuteTokens;
		public int[] MemberOperandSlots;
		public int[] MemberBranchOrder;

		public override bool IsInstruction(Instruction instruction) => false;

		public bool IsInstruction(List<Instruction> instructions)
		{
			if (instructions.Count != SubOpcodes.Length)
				return false;

			for (int i = 0; i < SubOpcodes.Length; i++)
			{
				if (SubOpcodes[i] is OpMutated mut)
				{
					if (!mut.Mutated.IsInstruction(instructions[i]))
						return false;
				}
				else if (!SubOpcodes[i].IsInstruction(instructions[i]))
					return false;
			}
			return true;
		}

		public override string GetObfuscated(ObfuscationContext context)
		{
			int memberCount = SubOpcodes.Length;
			if (MemberTokens == null || MemberTokens.Length != memberCount ||
			    MemberExecuteTokens == null || MemberExecuteTokens.Length != memberCount ||
			    MemberOperandSlots == null || MemberOperandSlots.Length != memberCount ||
			    MemberOperandSlots[0] != 0 ||
			    MemberOperandSlots.Skip(1).OrderBy(value => value).Where((value, index) => value != index + 1).Any() ||
			    MemberBranchOrder == null || MemberBranchOrder.Length != memberCount * 2 ||
			    MemberBranchOrder.OrderBy(value => value).Where((value, index) => value != index).Any())
				throw new InvalidOperationException("IR fusion member phase program was not initialized.");

			var locals = new List<string>();
			var memberBodies = new string[memberCount];
			for (int index = 0; index < memberCount; index++)
			{
				string body = Regex.Replace(SubOpcodes[index].GetObfuscated(context), @"\bStk\b", "FusedStack");
				Regex declarations = new Regex("local(.*?)[;=]");
				foreach (Match match in declarations.Matches(body))
				{
					string local = match.Groups[1].Value.Replace(" ", "");
					if (!locals.Contains(local)) locals.Add(local);
					if (!match.Value.Contains(";"))
						body = body.Replace($"local{match.Groups[1].Value}", local);
					else
						body = body.Replace($"local{match.Groups[1].Value};", "");
				}
				memberBodies[index] = body;
			}

			var output = new StringBuilder(
				"local FusedOperands=Inst[5];local FusedHead=Inst;" +
				"local FusedValues,FusedWritten={},{};" +
				"local FusedStack=Setmetatable({},{" +
				"__index=function(_,FusedKey)local FusedValue=RawGet(Stk,FusedKey);" +
				"if FusedWritten[FusedKey] and RawEqual(FusedValue,FusedValues[FusedKey]) then return FusedValues[FusedKey];end;" +
				"FusedWritten[FusedKey],FusedValues[FusedKey]=true,FusedValue;return FusedValue;end," +
				"__newindex=function(_,FusedKey,FusedValue)FusedWritten[FusedKey],FusedValues[FusedKey]=true,FusedValue;" +
				"RawSet(Stk,FusedKey,FusedValue);end});" +
				"local FusedProgramCounter=" + MemberTokens[0] + ";local FusedProgramStep=0;" +
				"while FusedProgramCounter~=0 do if FusedProgramStep>" + (memberCount * 2) + " then error('invalid protected payload',0);end;");
			for (int branch = 0; branch < MemberBranchOrder.Length; branch++)
			{
				int phase = MemberBranchOrder[branch];
				bool execute = phase >= memberCount;
				int member = execute ? phase - memberCount : phase;
				output.Append(branch == 0 ? "if " : "elseif ");
				if (!execute)
				{
					string operand = member == 0
						? "FusedHead"
						: "FusedOperands[" + MemberOperandSlots[member] + "]";
					output.Append("FusedProgramCounter==").Append(MemberTokens[member]).Append(" then ")
						.Append("Inst=").Append(operand).Append(';')
						.Append("FusedProgramStep=FusedProgramStep+1;FusedProgramCounter=")
						.Append(MemberExecuteTokens[member]).Append(';');
				}
				else
				{
					uint nextToken = member + 1 < memberCount ? MemberTokens[member + 1] : 0u;
					output.Append("FusedProgramCounter==").Append(MemberExecuteTokens[member]).Append(" then ")
						.Append(memberBodies[member])
						.Append("FusedProgramStep=FusedProgramStep+1;FusedProgramCounter=")
						.Append(nextToken).Append(';');
				}
			}
			output.Append("else error('invalid protected payload',0);end;end;");
			foreach (string local in locals)
				output.Insert(0, "local " + local + ';');
			return output.ToString();
		}
	}
}
