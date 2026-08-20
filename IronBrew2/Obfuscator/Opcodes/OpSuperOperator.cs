using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
	public class OpSuperOperator : VOpcode
	{
		public VOpcode[] SubOpcodes;

		public override bool IsInstruction(Instruction instruction) =>
			false;

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
			string s = "local FusedOperands=Inst[5];" +
				"local FusedValues,FusedWritten={},{};" +
				"local FusedStack=Setmetatable({},{" +
				"__index=function(_,FusedKey)local FusedValue=RawGet(Stk,FusedKey);" +
				"if FusedWritten[FusedKey] and RawEqual(FusedValue,FusedValues[FusedKey]) then return FusedValues[FusedKey];end;" +
				"FusedWritten[FusedKey],FusedValues[FusedKey]=true,FusedValue;return FusedValue;end," +
				"__newindex=function(_,FusedKey,FusedValue)FusedWritten[FusedKey],FusedValues[FusedKey]=true,FusedValue;" +
				"RawSet(Stk,FusedKey,FusedValue);end});";
			List<string> locals = new List<string>();
			
			for (var index = 0; index < SubOpcodes.Length; index++)
			{
				var subOpcode = SubOpcodes[index];
				string s2 = Regex.Replace(subOpcode.GetObfuscated(context), @"\bStk\b", "FusedStack");
				
				Regex reg = new Regex("local(.*?)[;=]");
				foreach (Match m in reg.Matches(s2))
				{
					string loc = m.Groups[1].Value.Replace(" ", "");
					if (!locals.Contains(loc))
						locals.Add(loc);
					
					if (!m.Value.Contains(";"))
						s2 = s2.Replace($"local{m.Groups[1].Value}", loc);
					else 
						s2 = s2.Replace($"local{m.Groups[1].Value};", "");
				}

				s += s2;

				if (index + 1 < SubOpcodes.Length)
					s += "Inst=FusedOperands[" + (index + 1) + "];";
			}

			foreach (string l in locals)
				s = "local " + l + ';' + s;
				
			return s;
		}
	}
}