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
		public uint[] MemberTokens;
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
			if (MemberTokens == null || MemberTokens.Length != SubOpcodes.Length ||
			    MemberBranchOrder == null || MemberBranchOrder.Length != SubOpcodes.Length ||
			    MemberBranchOrder.OrderBy(value => value).Where((value, index) => value != index).Any())
				throw new InvalidOperationException("IR fusion member-token program was not initialized.");

			var locals = new List<string>();
			var memberBodies = new string[SubOpcodes.Length];
			for (int index = 0; index < SubOpcodes.Length; index++)
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
				uint nextToken = index + 1 < MemberTokens.Length ? MemberTokens[index + 1] : 0u;
				memberBodies[index] = (index == 0 ? "Inst=FusedHead;" : "Inst=FusedOperands[" + index + "];")
					+ body + "FusedProgramStep=FusedProgramStep+1;FusedProgramCounter=" + nextToken + ";";
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
				"while FusedProgramCounter~=0 do if FusedProgramStep>" + SubOpcodes.Length + " then error('invalid protected payload',0);end;");
			for (int branch = 0; branch < MemberBranchOrder.Length; branch++)
			{
				int member = MemberBranchOrder[branch];
				output.Append(branch == 0 ? "if " : "elseif ")
					.Append("FusedProgramCounter==").Append(MemberTokens[member]).Append(" then ")
					.Append(memberBodies[member]);
			}
			output.Append("else error('invalid protected payload',0);end;end;");
			foreach (string local in locals)
				output.Insert(0, "local " + local + ';');
			return output.ToString();
		}
	}
}
