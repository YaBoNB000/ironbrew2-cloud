using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Text.RegularExpressions;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Extensions;
using IronBrew2.Obfuscator.AntiDump;
using IronBrew2.Obfuscator.Opcodes;

namespace IronBrew2.Obfuscator.VM_Generation
{
	public class Generator
	{
		private ObfuscationContext _context;
		
		public Generator(ObfuscationContext context) =>
			_context = context;

		public bool IsUsed(Chunk chunk, VOpcode virt)
		{
			bool isUsed = false;
			foreach (Instruction ins in chunk.Instructions)
				if (virt.IsInstruction(ins))
				{
					if (!_context.InstructionMapping.ContainsKey(ins.OpCode))
						_context.InstructionMapping.Add(ins.OpCode, virt);

					ins.CustomData = new CustomInstructionData {Opcode = virt};
					isUsed = true;
				}

			foreach (Chunk sChunk in chunk.Functions)
				isUsed |= IsUsed(sChunk, virt);

			return isUsed;
		}

		public static List<int> Compress(byte[] uncompressed)
		{
			// build the dictionary
			Dictionary<string, int> dictionary = new Dictionary<string, int>();
			for (int i = 0; i < 256; i++)
				dictionary.Add(((char)i).ToString(), i);
 
			string    w          = string.Empty;
			List<int> compressed = new List<int>();
 
			foreach (byte b in uncompressed)
			{
				string wc = w + (char)b;
				if (dictionary.ContainsKey(wc))
					w = wc;
				
				else
				{
					// write w to output
					compressed.Add(dictionary[w]);
					// wc is a new sequence; add it to the dictionary
					dictionary.Add(wc, dictionary.Count);
					w = ((char) b).ToString();
				}
			}
 
			// write remaining output if necessary
			if (!string.IsNullOrEmpty(w))
				compressed.Add(dictionary[w]);
 
			return compressed;
		}

		        public static string ToBase92(ulong value)
        {
            var sb = new StringBuilder(13);
            do
            {
                byte v = (byte)(value % 92);
                value /= 92;
                int c = v + 33;          // '!' = 33
                if (c >= 39) c++;        // skip single quote (39)
                if (c >= 92) c++;        // skip backslash (92)
                sb.Insert(0, (char)c);
            } while (value != 0);
            return sb.ToString();
        }

		internal static string[] SplitDataSegs(string data, Random r)
		{
			int n = Math.Max(2, Math.Min(6, data.Length / 200 + (r.Next(2) == 0 ? 1 : 0)));
			var segs = new List<string>();
			int baseLen = Math.Max(1, data.Length / n);
			int pos = 0;
			for (int i = 0; i < n; i++)
			{
				int len = (i == n - 1) ? data.Length - pos : baseLen;
				if (len <= 0) break;
				segs.Add(data.Substring(pos, len));
				pos += len;
			}
			if (segs.Count == 0)
				segs.Add(data);
			return segs.ToArray();
		}

		internal static string[] RandSegNames(int n, Random r)
		{
			var names = new string[n];
			var used = new HashSet<string>();
			for (int i = 0; i < n; i++)
			{
				string name;
				do { name = "s" + r.Next(100000, 999999); } while (used.Contains(name));
				used.Add(name);
				names[i] = name;
			}
			return names;
		}

		public static string CompressedToString(List<int> compressed)
		{
			StringBuilder sb = new StringBuilder();
			foreach (int i in compressed)
			{
				string n = ToBase92((ulong)i);
				
				sb.Append(ToBase92((ulong)n.Length));
				sb.Append(n);
			}

			return sb.ToString();
		}

		// Lua 单引号字符串转义，用于可配置的 dump 诱饵水印。
		private static string EscapeLuaString(string value) =>
			(value ?? "")
				.Replace("\\", "\\\\")
				.Replace("'", "\\'")
				.Replace("\r", "\\r")
				.Replace("\n", "\\n");

		// ==== base91 字节流编码(替换 LZW+base92)====
		// 字节码已经流式 XOR 加密(高熵),LZW 压缩率为负;base91 约 1.23x,且 VM 端解码器更小。
		private static char Base91Char(int v)
		{
			int c = v + 33;      // '!' = 33
			if (c >= 39) c++;    // 跳过单引号
			if (c >= 92) c++;    // 跳过反斜杠
			return (char)c;
		}

		public static string Base91Encode(byte[] data)
		{
			var sb = new StringBuilder();
			int b = 0, n = 0;
			foreach (byte x in data)
			{
				b |= x << n;
				n += 8;
				if (n > 13)
				{
					int v = b & 8191;
					if (v > 88)
					{
						b >>= 13;
						n -= 13;
					}
					else
					{
						v = b & 16383;
						b >>= 14;
						n -= 14;
					}
					sb.Append(Base91Char(v % 91));
					sb.Append(Base91Char(v / 91));
				}
			}
			if (n > 0)
			{
				sb.Append(Base91Char(b % 91));
				if (n > 7 || b > 90)
					sb.Append(Base91Char(b / 91));
			}
			return sb.ToString();
		}

		public List<OpMutated> GenerateMutations(List<VOpcode> opcodes)
		{
			Random r = new Random(System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue));
			List<OpMutated> mutated = new List<OpMutated>();

			foreach (VOpcode opc in opcodes)
			{
				if (opc is OpSuperOperator)
					continue;

				for (int i = 0; i < r.Next(35, 50); i++)
				{
					int[] rand = {0, 1, 2};
					rand.Shuffle();

					OpMutated mut = new OpMutated();

					mut.Registers = rand;
					mut.Mutated = opc;
						
					mutated.Add(mut);
				}
			}

			mutated.Shuffle();
			return mutated;
		}

		public void FoldMutations(List<OpMutated> mutations, HashSet<OpMutated> used, Chunk chunk)
		{
			bool[] skip = new bool[chunk.Instructions.Count + 1];
			
			for (int i = 0; i < chunk.Instructions.Count; i++)
			{
				Instruction opc = chunk.Instructions[i];

				switch (opc.OpCode)
				{
					case Opcode.Closure:
						for (int j = 1; j <= ((Chunk) opc.RefOperands[0]).UpvalueCount; j++)
							skip[i + j] = true;

						break;
				}
			}
			
			for (int i = 0; i < chunk.Instructions.Count; i++)
			{
				if (skip[i])
					continue;
				
				Instruction opc = chunk.Instructions[i];
				CustomInstructionData data = opc.CustomData;
				
				foreach (OpMutated mut in mutations)
					if (data.Opcode == mut.Mutated && data.WrittenOpcode == null)
					{
						if (!used.Contains(mut))
							used.Add(mut);

						data.Opcode = mut;
						break;
					}
			}
			
			foreach (Chunk _c in chunk.Functions)
				FoldMutations(mutations, used, _c);
		}

		public List<OpSuperOperator> GenerateSuperOperators(Chunk chunk, int maxSize, int minSize = 5)
		{
			List<OpSuperOperator> results = new List<OpSuperOperator>();
			Random                r       = new Random(System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue));

			bool[] skip = new bool[chunk.Instructions.Count + 1];

			for (int i = 0; i < chunk.Instructions.Count - 1; i++)
			{
				switch (chunk.Instructions[i].OpCode)
				{
					case Opcode.Closure:
					{
						skip[i] = true;
						for (int j = 0; j < ((Chunk) chunk.Instructions[i].RefOperands[0]).UpvalueCount; j++)
							skip[i + j + 1] = true;
							
						break;
					}

					case Opcode.Eq:
					case Opcode.Lt:
					case Opcode.Le:
					case Opcode.Test:
					case Opcode.TestSet:
					case Opcode.TForLoop:
					case Opcode.SetList:
					case Opcode.LoadBool when chunk.Instructions[i].C != 0:
						skip[i + 1] = true;
						break;

					case Opcode.ForLoop:
					case Opcode.ForPrep:
					case Opcode.Jmp:
						chunk.Instructions[i].UpdateRegisters();
						
						skip[i + 1] = true;
						skip[i + chunk.Instructions[i].B + 1] = true;
						break;
				}
				
				if (chunk.Instructions[i].CustomData.WrittenOpcode is OpSuperOperator su && su.SubOpcodes != null)
					for (int j = 0; j < su.SubOpcodes.Length; j++)
						skip[i + j] = true;
			}
			
			int c = 0;
			while (c < chunk.Instructions.Count)
			{
				int targetCount = maxSize;
				OpSuperOperator superOperator = new OpSuperOperator {SubOpcodes = new VOpcode[targetCount]};

				bool d     = true;
				int cutoff = targetCount;

				for (int j = 0; j < targetCount; j++)
					if (c + j > chunk.Instructions.Count - 1 || skip[c + j])
					{
						cutoff = j; 
						d = false;
						break;
					}

				if (!d)
				{
					if (cutoff < minSize)
					{
						c += cutoff + 1;	
						continue;
					}
						
					targetCount = cutoff;	
					superOperator = new OpSuperOperator {SubOpcodes = new VOpcode[targetCount]};
				}
				
				for (int j = 0; j < targetCount; j++)
					superOperator.SubOpcodes[j] =
						chunk.Instructions[c + j].CustomData.Opcode;

				results.Add(superOperator);
				c += targetCount + 1;
			}

			foreach (var _c in chunk.Functions)
				results.AddRange(GenerateSuperOperators(_c, maxSize));
			
			return results;
		}

		public void FoldAdditionalSuperOperators(Chunk chunk, List<OpSuperOperator> operators, ref int folded)
		{
			bool[] skip = new bool[chunk.Instructions.Count + 1];
			for (int i = 0; i < chunk.Instructions.Count - 1; i++)
			{
				switch (chunk.Instructions[i].OpCode)
				{
					case Opcode.Closure:
					{
						skip[i] = true;
						for (int j = 0; j < ((Chunk) chunk.Instructions[i].RefOperands[0]).UpvalueCount; j++)
							skip[i + j + 1] = true;
							
						break;
					}

					case Opcode.Eq:
					case Opcode.Lt:
					case Opcode.Le:
					case Opcode.Test:
					case Opcode.TestSet:
					case Opcode.TForLoop:
					case Opcode.SetList:
					case Opcode.LoadBool when chunk.Instructions[i].C != 0:
						skip[i + 1] = true;
						break;

					case Opcode.ForLoop:
					case Opcode.ForPrep:
					case Opcode.Jmp:
						chunk.Instructions[i].UpdateRegisters();
						skip[i + 1] = true;
						skip[i + chunk.Instructions[i].B + 1] = true;
						break;
				}
				
				if (chunk.Instructions[i].CustomData.WrittenOpcode is OpSuperOperator su && su.SubOpcodes != null)
					for (int j = 0; j < su.SubOpcodes.Length; j++)
						skip[i + j] = true;
			}
			
			int c = 0;
			while (c < chunk.Instructions.Count)
			{
				if (skip[c])
				{
					c++;
					continue;
				}

				bool used = false;

				foreach (OpSuperOperator op in operators)
				{
					int targetCount = op.SubOpcodes.Length;
					bool cu = true;
					for (int j = 0; j < targetCount; j++)
					{
						if (c + j > chunk.Instructions.Count - 1 || skip[c + j])
						{
							cu = false;
							break;
						}
					}

					if (!cu)
						continue;


					List<Instruction> taken = chunk.Instructions.Skip(c).Take(targetCount).ToList();
					if (op.IsInstruction(taken))
					{
						for (int j = 0; j < targetCount; j++)
						{
							skip[c + j] = true;
							chunk.Instructions[c + j].CustomData.WrittenOpcode = new OpSuperOperator {VIndex = 0};
						}

						chunk.Instructions[c].CustomData.WrittenOpcode = op;

						used = true;
						break;
					}
				}

				if (!used)
					c++;
				else
					folded++;
			}

			foreach (var _c in chunk.Functions)
				FoldAdditionalSuperOperators(_c, operators, ref folded);
		}
		
		private static bool TrySkipLuaLongBracket(string code, int start, out int end)
		{
			end = start;
			if (start >= code.Length || code[start] != '[')
				return false;

			int cursor = start + 1;
			while (cursor < code.Length && code[cursor] == '=')
				cursor++;
			if (cursor >= code.Length || code[cursor] != '[')
				return false;

			string closing = "]" + new string('=', cursor - start - 1) + "]";
			int closingStart = code.IndexOf(closing, cursor + 1, StringComparison.Ordinal);
			end = closingStart < 0 ? code.Length - 1 : closingStart + closing.Length - 1;
			return true;
		}

		/// <summary>
		/// Splits a Lua handler only at top-level semicolons. Unlike the old noise
		/// path's string.Split, this scanner preserves quoted/long strings, comments,
		/// table/index expressions and nested function/if/loop blocks. It is
		/// intentionally a small lexer rather than a regex-based source rewrite.
		/// </summary>
		private static List<string> SplitTopLevelLuaStatements(string code)
		{
			var statements = new List<string>();
			int start = 0;
			int parens = 0, braces = 0, brackets = 0;
			int blocks = 0, pendingLoopDo = 0;

			for (int i = 0; i < code.Length; i++)
			{
				char current = code[i];

				if (current == '\'' || current == '"')
				{
					char quote = current;
					for (i++; i < code.Length; i++)
					{
						if (code[i] == '\\')
						{
							i++;
							continue;
						}
						if (code[i] == quote)
							break;
					}
					continue;
				}

				if (current == '-' && i + 1 < code.Length && code[i + 1] == '-')
				{
					if (TrySkipLuaLongBracket(code, i + 2, out int commentEnd))
					{
						i = commentEnd;
						continue;
					}

					int newline = code.IndexOf('\n', i + 2);
					if (newline < 0)
						break;
					i = newline;
					continue;
				}

				if (current == '[' && TrySkipLuaLongBracket(code, i, out int longStringEnd))
				{
					i = longStringEnd;
					continue;
				}

				if (char.IsLetter(current) || current == '_')
				{
					int end = i + 1;
					while (end < code.Length && (char.IsLetterOrDigit(code[end]) || code[end] == '_'))
						end++;
					string token = code.Substring(i, end - i);

					switch (token)
					{
						case "function":
						case "if":
						case "repeat":
							blocks++;
							break;
						case "for":
						case "while":
							blocks++;
							pendingLoopDo++;
							break;
						case "do":
							if (pendingLoopDo > 0)
								pendingLoopDo--;
							else
								blocks++;
							break;
						case "end":
							if (blocks > 0)
								blocks--;
							break;
						case "until":
							if (blocks > 0)
								blocks--;
							break;
					}

					i = end - 1;
					continue;
				}

				switch (current)
				{
					case '(': parens++; break;
					case ')': if (parens > 0) parens--; break;
					case '{': braces++; break;
					case '}': if (braces > 0) braces--; break;
					case '[': brackets++; break;
					case ']': if (brackets > 0) brackets--; break;
					case ';' when parens == 0 && braces == 0 && brackets == 0 && blocks == 0:
					{
						string statement = code.Substring(start, i - start).Trim();
						if (statement.Length > 0)
							statements.Add(statement);
						start = i + 1;
						break;
					}
				}
			}

			string tail = code.Substring(start).Trim();
			if (tail.Length > 0)
				statements.Add(tail);
			return statements;
		}

		private static string JoinLuaStatements(IEnumerable<string> statements) =>
			string.Join("", statements.Select(statement => statement.Trim().TrimEnd(';') + ";"));

		private static bool StartsWithLuaKeyword(string statement, string keyword)
		{
			string value = statement.TrimStart();
			return value.StartsWith(keyword, StringComparison.Ordinal) &&
			       (value.Length == keyword.Length || !(char.IsLetterOrDigit(value[keyword.Length]) || value[keyword.Length] == '_'));
		}

		public string GenerateVM(ObfuscationSettings settings)
		{
			Random r = new Random(System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue));

			List<VOpcode> virtuals = Assembly.GetExecutingAssembly().GetTypes()
			                                 .Where(t => t.IsSubclassOf(typeof(VOpcode)))
			                                 .Select(Activator.CreateInstance)
			                                 .Cast<VOpcode>()
			                                 .Where(t => IsUsed(_context.HeadChunk, t))
			                                 .ToList();

			
			if (settings.Mutate)
			{
				List<OpMutated> muts = GenerateMutations(virtuals).Take(settings.MaxMutations).ToList();
				
				Console.WriteLine("Created " + muts.Count + " mutations.");
				
				HashSet<OpMutated> used = new HashSet<OpMutated>();
				FoldMutations(muts, used, _context.HeadChunk);
				
				Console.WriteLine("Used " + used.Count + " mutations.");
				
				virtuals.AddRange(used);
			}
			
			if (settings.SuperOperators)
			{
				int folded = 0;
				
				var megaOperators = GenerateSuperOperators(_context.HeadChunk, 80, 60).OrderBy(t => r.Next())
					.Take(settings.MaxMegaSuperOperators).ToList();
				
				Console.WriteLine("Created " + megaOperators.Count + " mega super operators.");
				
				virtuals.AddRange(megaOperators);
				
				FoldAdditionalSuperOperators(_context.HeadChunk, megaOperators, ref folded);
				
				var miniOperators = GenerateSuperOperators(_context.HeadChunk, 10).OrderBy(t => r.Next())
					.Take(settings.MaxMiniSuperOperators).ToList();
				
				Console.WriteLine("Created " + miniOperators.Count + " mini super operators.");
				
				virtuals.AddRange(miniOperators);
				
				FoldAdditionalSuperOperators(_context.HeadChunk, miniOperators, ref folded);
				
				Console.WriteLine("Folded " + folded + " instructions into super operators.");
			}
			
			virtuals.Shuffle();
			
			for (int i = 0; i < virtuals.Count; i++)
				virtuals[i].VIndex = i;

			_context.VirtualOpcodeCount = virtuals.Count;

			string vm = "";

			// ==== P1: 模板标识符随机化(每次混淆生成不同的 VM 结构名)====
			string[] identKeys = {
				"ByteString","InstrPoint","GetFEnv","Setmetatable","ToNumber","ConstCount","Deserialize",
				"Wrap","Upvalues","NewProto","Indexes","Concat","Insert","LDExp","Select","Unpack",
				"BitXOR","gBits32","gBits8","gBits16","gFloat","gSizet","gString","gInt","Byte","Char","Sub",
				"gBit","Instrs","Functions","Lines","Consts","Instr","Proto","Params","Top","Vararg","Args",
				"PCount","Lupvals","Stk","Inst","Enum","Chunk","decompress","Pos","Xs","Xd","_R","Env",
				"Varargsz","PCall","Loop","Const","RA","RB","K1","K2","K3","OpcodeKey","FieldKey","FieldKey32","U32",
				"DerivePermutation","Count","Domain","Values","State","Schema","StepIndex","Step","ConstTags","InstrCount","OpcodeBank",
				"GetProto","Index","Encoded","Decoded","SavedByteString","SavedPos","Length","Root","Blocks","BlockMap",
				"BlockCount","BlockIndex","BlockStart","Block","RefCount","References","ReferenceIndex","Offset","ConstCache",
				"Descriptor","Type","Mask","DecodeInstructionBlock","GetInstruction","InitialFlowKey","FlowKey","FlowVerifier",
				"BlockFieldKey","BlockFieldKey32","ComputeBlockIntegrity","Flow","EntryState","FromPC","ToPC","Value","Low","High","Hash",
				"Verifier","BlockTag","SuccessorCount","Successors","SuccessorIndex","SuccessorStart","WrappedState","LastIndex","CurrentBlock"
			};
			string[] luaKws = {"and","break","do","else","elseif","end","false","for","function","if","in","local","nil","not","or","repeat","return","then","true","until","while"};
			var idents = new Dictionary<string,string>();
			var usedNames = new HashSet<string>();
			foreach (string key in identKeys)
			{
				string nid;
				do
				{
					int len = 3 + r.Next(4);
					var ch = new char[len];
					ch[0] = (char)('a' + r.Next(26));
					for (int j = 1; j < len; j++)
						ch[j] = r.Next(2) == 0 ? (char)('a' + r.Next(26)) : (char)('0' + r.Next(10));
					nid = new string(ch);
				} while (usedNames.Contains(nid) || Array.IndexOf(luaKws, nid) >= 0);
				usedNames.Add(nid);
				idents[key] = nid;
			}

			string T(string s)
			{
				foreach (var kv in idents)
					s = Regex.Replace(s, "\\b" + kv.Key + "\\b", kv.Value);
				return s;
			}

			bool useRepeat = r.Next(2) == 0;

			// ==== ③ 常量打散:数字 → 等价运算表达式 ====
			string ScrambleNumber(int n)
			{
				switch (r.Next(6))
				{
					case 0: return "(" + n + "+0)";
					case 1: return "(" + n + "-0)";
					case 2: return "(" + n + "*1)";
					case 3: { int a = r.Next(0, n + 1); return "(" + a + "+" + (n - a) + ")"; }
					case 4: { int a = r.Next(1, n + 1); return "(" + (n + a) + "-" + a + ")"; }
					default: { int a = r.Next(1, Math.Max(2, n + 1)); return (n % a == 0) ? "(" + (n / a) + "*" + a + ")" : "(" + n + "+0)"; }
				}
			}

			// 把 handler 代码里的 OP_ENUM/OP_A/OP_B/OP_C 占位符打散成数字表达式
			string ScrambleOps(string code)
			{
				code = code.Replace("OP_ENUM", ScrambleNumber(1));
				code = code.Replace("OP_A", ScrambleNumber(2));
				code = code.Replace("OP_B", ScrambleNumber(3));
				code = code.Replace("OP_C", ScrambleNumber(4));
				return code;
			}

			// Handler 结构多态：先用词法 statement splitter 找到安全边界，再从
			// 原始块、do scope、恒真 guard 和 prefix/suffix 嵌套四种等价模板中选择。
			// prefix 位于外层，因此其 local 对 suffix 仍可见；不会反向移动语句。
			string ApplyHandlerTemplate(string code)
			{
				List<string> statements = SplitTopLevelLuaStatements(code);
				if (statements.Count == 0)
					return code;

				string joined = JoinLuaStatements(statements);
				int variant = r.Next(4);
				if (variant == 0)
					return joined;
				if (variant == 1)
					return "do " + joined + " end;";
				if (variant == 2)
					return "if Enum==Enum then " + joined + " end;";

				if (statements.Count > 1)
				{
					var splitCandidates = new List<int>();
					for (int split = 1; split < statements.Count; split++)
					{
						bool terminalInPrefix = statements.Take(split).Any(statement =>
							StartsWithLuaKeyword(statement, "return") || StartsWithLuaKeyword(statement, "break"));
						if (!terminalInPrefix)
							splitCandidates.Add(split);
					}

					if (splitCandidates.Count > 0)
					{
						int split = splitCandidates[r.Next(splitCandidates.Count)];
						string prefix = JoinLuaStatements(statements.Take(split));
						string suffix = JoinLuaStatements(statements.Skip(split));
						return "do " + prefix + " do " + suffix + " end;end;";
					}
				}

				return "do " + joined + " end;";
			}

			// ==== ① handler 内部平坦化:直线代码 → 状态机驱动 ====
			// 简单 handler(无嵌套块、无 local)分 2-3 片 + 垃圾状态;
			// 复杂 handler 整体包一层状态循环(状态到达才执行,前面空转)
			string FlattenCode(string code)
			{
				string sv = "t" + r.Next(1000, 9999);
				bool hasBlock = code.Contains("then") || code.Contains(" do ") || code.Contains("repeat") || code.Contains("while");
				bool hasLocal = code.Contains("local ");

				if (!hasBlock && !hasLocal)
				{
					var stmts = new List<string>();
					foreach (string p in code.Split(';'))
					{
						string s = p.Trim();
						if (s.Length > 0) stmts.Add(s);
					}
					if (stmts.Count > 2)
					{
						int nGroups = Math.Min(3, stmts.Count);
						int per = (stmts.Count + nGroups - 1) / nGroups;
						var groups = new List<string>();
						for (int i = 0; i < stmts.Count; i += per)
						{
							var g = new List<string>();
							for (int j = i; j < Math.Min(i + per, stmts.Count); j++) g.Add(stmts[j]);
							groups.Add(string.Join(";", g) + ";");
						}
						int nStates = groups.Count + (r.Next(2) == 0 ? 1 : 0);
						var sb = new StringBuilder();
						sb.Append("local " + sv + "=0;repeat " + sv + "=" + sv + "+1;");
						for (int i = 0; i < groups.Count; i++)
							sb.Append("if " + sv + "==" + (i + 1) + " then " + groups[i] + " end;");
						if (nStates > groups.Count)
							sb.Append("if " + sv + "==" + nStates + " then local " + sv + "j=0; end;");
						sb.Append("until " + sv + ">=" + nStates + ";");
						return sb.ToString();
					}
				}

				int k = 1 + r.Next(3);
				return "local " + sv + "=0;repeat " + sv + "=" + sv + "+1;if " + sv + "==" + k + " then " + code + " end;until " + sv + ">=" + k + ";";
			}

			byte[] bs = new Serializer(_context, settings).SerializeLChunk(_context.HeadChunk);

			
			vm += T(@"return(function()
local Byte         = string.byte;
local Char         = string.char;
local Sub          = string.sub;
local Concat       = table.concat;
local Insert       = table.insert;
local LDExp        = math.ldexp;
local GetFEnv      = getfenv or function() return _G end;
local Setmetatable = setmetatable;
local Select       = select;

local Unpack = unpack or table.unpack;
local ToNumber = tonumber;");

			// 数据切片:base92 字符串拆成 2-6 小段,以 local <随机名>='段' 形式散布在产物各处,
			// 最后统一拼接 —— 视觉上与代码交织,不再是一整块孤立的"数据区"
			// 注意:段声明必须全部位于最外层作用域(decompress 前/后 与 Deserialize 结束后的外层),
			// 若放进 Deserialize 等函数体内,luasrcdiet --opt-locals 重命名会造成声明/引用不一致
			// 数据总是 base91 编码;LZ77 压缩与否已由 Serializer 写入 header 的 flag,VM 端按 flag 决定是否解压
			string data = Base91Encode(bs);

			string[] segs = SplitDataSegs(data, r);
			string[] segNames = RandSegNames(segs.Length, r);
			vm += "local " + segNames[0] + "='" + segs[0] + "';\n";

			vm += T("local function decompress(b)local out={}local v=-1;local acc=0;local bits=0;for i=1,#b do local z=Byte(Sub(b,i,i));local d=z-33;if z>39 then d=d-1 end;if z>92 then d=d-1 end;if d>=0 and d<=90 then if v<0 then v=d else v=v+d*91;acc=acc+v*(2^bits);if(v%8192)>88 then bits=bits+13 else bits=bits+14 end;while bits>=8 do out[#out+1]=Char(acc%256);acc=(acc-acc%256)/256;bits=bits-8 end;v=-1 end end end;if v>=0 then acc=acc+v*(2^bits);bits=bits+7;while bits>=8 do out[#out+1]=Char(acc%256);acc=(acc-acc%256)/256;bits=bits-8 end end;return Concat(out)end;");

			vm += "local " + segNames[1] + "='" + segs[1] + "';\n";

			for (int i = 2; i < segs.Length; i++)
				vm += "local " + segNames[i] + "='" + segs[i] + "';\n";

			vm += T("local ByteString=decompress(") + string.Join("..", segNames) + T(");\n");

			int maxConstants = 0;

			void ComputeConstants(Chunk c)
			{
				if (c.Constants.Count > maxConstants)
					maxConstants = c.Constants.Count;
				
				foreach (Chunk _c in c.Functions)
					ComputeConstants(_c);
			}
			
			ComputeConstants(_context.HeadChunk);

			vm += T(VMStrings.VMP1
				// 环境绑定：注入种子派生代码（读盐 → 跑探针 → Hash 派生 Xs）
				.Replace("__IB2_SEED__", settings.EnvironmentLock ? _context.Binder.SeedDeriveLua : EnvBinder.PlainSeedLua)
				.Replace("__IB2_WATERMARK__", EscapeLuaString(settings.Watermark))
				.Replace("__IB2_OPCODE_COUNT__", virtuals.Count.ToString()));
			
			// 每个 prototype 根据自身 K1/K2/K3 派生独立字段顺序。
			// 指令字段只读取 block framing；常量恢复后再把引用绑定到各 opaque block。
			vm += T(@"local Schema = DerivePermutation(5, K1, K2, K3, 113);
for StepIndex = 1, 5 do
    local Step = Schema[StepIndex];
    if (Step == 0) then
        Chunk[3] = gBits8();
    elseif (Step == 1) then
        for Idx = 1, gBits32() do
            local Type = gBits8();
            local Cons;
            if (Type == ConstTags[1]) then Cons = nil;
            elseif (Type == ConstTags[2]) then Cons = (gBits8() ~= 0);
            elseif (Type == ConstTags[3]) then Cons = gFloat();
            elseif (Type == ConstTags[4]) then Cons = gString(nil, Idx, K1, K2, K3);
            end;
            Consts[Idx] = Cons;
        end;
    elseif (Step == 2) then
        InstrCount = gBits32();
        BlockCount = gBits32();
        Chunk[11] = BlockCount;
        Chunk[12] = gBits32();
        for BlockIndex = 1, BlockCount do
            local BlockStart = gBits32();
            local Count = gBits32();
            local RefCount = gBits32();
            local References = {};
            for ReferenceIndex = 1, RefCount do References[ReferenceIndex] = gBits32(); end;
            local Verifier = gBits32();
            local BlockTag = gBits32();
            local SuccessorCount = gBits32();
            local Successors = {};
            for SuccessorIndex = 1, SuccessorCount do
                local SuccessorStart = gBits32();
                Successors[SuccessorStart] = gBits32();
            end;
            local Length = gBits32();
            local Block = {BlockStart, Count, Sub(ByteString, Pos, Pos + Length - 1), References, Successors, Verifier, BlockTag};
            Pos = Pos + Length;
            Blocks[BlockIndex] = Block;
            for Offset = 0, Count - 1 do BlockMap[BlockStart + Offset] = Block; end;
        end;
    elseif (Step == 3) then
        for Idx = 1, gBits32() do
            local Length = gBits32();
            Functions[Idx - 1] = Sub(ByteString, Pos, Pos + Length - 1);
            Pos = Pos + Length;
        end;");

			if (settings.PreserveLineInfo)
				vm += T(@"    elseif (Step == 4) then
        for Idx = 1, gBits32() do Lines[Idx] = gBits32(); end;");

			vm += T(@"    end;
end;

for BlockIndex = 1, BlockCount do
    local Block = Blocks[BlockIndex];
    local References = Block[4];
    local ConstCache = {};
    for ReferenceIndex = 1, #References do
        local Index = References[ReferenceIndex];
        ConstCache[Index] = Consts[Index];
    end;
    Block[4] = ConstCache;
end;
-- Constants are retained only by the opaque blocks that reference them.
Consts = nil;");

			vm += T("return Chunk;end;");

			vm += T(@"
local function GetProto(Proto, Index)
    local Encoded = Proto[Index];
    if type(Encoded) == 'string' then
        local SavedByteString, SavedPos = ByteString, Pos;
        ByteString, Pos = Encoded, 1;
        local Decoded = Deserialize();
        ByteString, Pos = SavedByteString, SavedPos;
        Proto[Index] = Decoded;
        return Decoded;
    end;
    return Encoded;
end;

local function DecodeInstructionBlock(Chunk, Block, EntryState)
    local SavedByteString, SavedPos = ByteString, Pos;
    local K1, K2, K3 = Chunk[5], Chunk[6], Chunk[7];
    if ComputeBlockIntegrity(Block[3], EntryState, Block[1], Block[2], K1, K2, K3) ~= Block[7] then
        error('invalid protected payload', 0);
    end;
    ByteString, Pos = Block[3], 1;
    local Instrs = Chunk[1];
    local ConstCache = Block[4];
    for Offset = 0, Block[2] - 1 do
        local Index = Block[1] + Offset;
        local Descriptor = BitXOR(gBits8(), BlockFieldKey(EntryState, Index, 7, K1, K2, K3));
        if (gBit(Descriptor, 1, 1) == 0) then
            local Type = gBit(Descriptor, 2, 3);
            local Mask = gBit(Descriptor, 4, 6);
            local Inst =
            {
                gBits16(),
                BitXOR(BitXOR(gBits16(), FieldKey(Index, 1, K1, K2, K3)), BlockFieldKey(EntryState, Index, 1, K1, K2, K3)),
                nil,
                nil
            };

            if (Type == 0) then
                Inst[OP_B] = BitXOR(BitXOR(gBits16(), FieldKey(Index, 2, K1, K2, K3)), BlockFieldKey(EntryState, Index, 2, K1, K2, K3));
                Inst[OP_C] = BitXOR(BitXOR(gBits16(), FieldKey(Index, 3, K1, K2, K3)), BlockFieldKey(EntryState, Index, 3, K1, K2, K3));
            elseif (Type == 1) then
                Inst[OP_B] = U32(BitXOR(BitXOR(gBits32(), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3)));
            elseif (Type == 2) then
                Inst[OP_B] = U32(BitXOR(BitXOR(gBits32(), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3))) - (2 ^ 16);
            elseif (Type == 3) then
                Inst[OP_B] = U32(BitXOR(BitXOR(gBits32(), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3))) - (2 ^ 16);
                Inst[OP_C] = BitXOR(BitXOR(gBits16(), FieldKey(Index, 3, K1, K2, K3)), BlockFieldKey(EntryState, Index, 3, K1, K2, K3));
            end;

            if (gBit(Mask, 1, 1) == 1) then Inst[OP_A] = ConstCache[Inst[OP_A]]; end;
            if (gBit(Mask, 2, 2) == 1) then Inst[OP_B] = ConstCache[Inst[OP_B]]; end;
            if (gBit(Mask, 3, 3) == 1) then Inst[OP_C] = ConstCache[Inst[OP_C]]; end;
            Instrs[Index] = Inst;
        end;
    end;
    ByteString, Pos = SavedByteString, SavedPos;
    Block[3], Block[4], Block[7] = nil, nil, nil;
    Chunk[11] = Chunk[11] - 1;
    if Chunk[11] == 0 then Chunk[9] = nil; end;
end;

local function GetInstruction(Chunk, Index, Flow)
    local BlockMap = Chunk[10];
    local Block = BlockMap and BlockMap[Index];
    if not Block then error('invalid protected payload', 0); end;

    local LastIndex = Flow[1];
    local CurrentBlock = Flow[2];
    local EntryState;
    if not CurrentBlock then
        if Index ~= 1 then error('invalid protected payload', 0); end;
        EntryState = U32(BitXOR(Chunk[12], InitialFlowKey(Chunk[5], Chunk[6], Chunk[7])));
    elseif CurrentBlock ~= Block or Index ~= LastIndex + 1 then
        if Index ~= Block[1] then error('invalid protected payload', 0); end;
        local WrappedState = CurrentBlock[5][Block[1]];
        if not WrappedState then error('invalid protected payload', 0); end;
        EntryState = U32(BitXOR(WrappedState, FlowKey(Flow[3], LastIndex, Block[1], Chunk[5], Chunk[6], Chunk[7])));
    else
        EntryState = Flow[3];
    end;

    if FlowVerifier(EntryState, Block[1], Chunk[5], Chunk[6], Chunk[7]) ~= Block[6] then
        error('invalid protected payload', 0);
    end;
    Flow[1], Flow[2], Flow[3] = Index, Block, EntryState;

    local Inst = Chunk[1][Index];
    if Inst then return Inst; end;
    DecodeInstructionBlock(Chunk, Block, EntryState);
    Inst = Chunk[1][Index];
    if not Inst then error('invalid protected payload', 0); end;
    return Inst;
end;");

			vm += T(settings.PreserveLineInfo ? (useRepeat ? VMStrings.VMP2_LI_R : VMStrings.VMP2_LI) : (useRepeat ? VMStrings.VMP2_R : VMStrings.VMP2));

			if (settings.Noise)
				vm += T(AntiDumpGenerator.GenerateLoopNoise());

			int maxFunc = 0;

			void ComputeFuncs(Chunk c)
			{
				if (c.Functions.Count > maxFunc)
					maxFunc = c.Functions.Count;
				
				foreach (Chunk _c in c.Functions)
					ComputeFuncs(_c);
			}
			
			ComputeFuncs(_context.HeadChunk);

			int maxInstrs = 0;

			void ComputeInstrs(Chunk c)
			{
				if (c.Instructions.Count > maxInstrs)
					maxInstrs = c.Instructions.Count;
				
				foreach (Chunk _c in c.Functions)
					ComputeInstrs(_c);
			}
			
			ComputeInstrs(_context.HeadChunk);

			string BuildHandler(int opcodeIndex)
			{
				string code = ApplyHandlerTemplate(virtuals[opcodeIndex].GetObfuscated(_context));
				code = T(code);
				code = ScrambleOps(code);
				if (settings.Noise)
					code = FlattenCode(code);
				return code;
			}
			
			string GetStr(List<int> opcodes)
			{
				string str = "";
				
				if (opcodes.Count == 1)
				{
					str += BuildHandler(opcodes[0]);
					if (settings.Noise)
						str += AntiDumpGenerator.GenerateHandlerNoise();
				}

				else if (opcodes.Count == 2) 
				{
					// A leaf deliberately owns two canonical handlers. This is dispatch
					// structure polymorphism only: it does not fuse bytecode instructions
					// and therefore is not a Phase 3 superoperator.
					string h0 = BuildHandler(opcodes[0]);
					string h1 = BuildHandler(opcodes[1]);
					if (settings.Noise)
					{
						h0 += AntiDumpGenerator.GenerateHandlerNoise();
						h1 += AntiDumpGenerator.GenerateHandlerNoise();
					}

					string enumName = T("Enum");
					string v0 = ScrambleNumber(virtuals[opcodes[0]].VIndex);
					string v1 = ScrambleNumber(virtuals[opcodes[1]].VIndex);
					switch (r.Next(4))
					{
						case 0:
							str += "if " + enumName + " > " + v0 + " then " + h1 + "else " + h0 + "end;";
							break;
						case 1:
							str += "if " + enumName + " == " + v0 + " then " + h0 + "else " + h1 + "end;";
							break;
						case 2:
							str += "if " + enumName + " ~= " + v0 + " then " + h1 + "else " + h0 + "end;";
							break;
						default:
							// Must start with "if": recursive parents concatenate "else" +
							// the right child into a valid Lua "elseif" chain.
							str += "if " + enumName + " == " + enumName + " then if " + enumName + " == " + v1 + " then " + h1 + "else " + h0 + "end;end;";
							break;
					}
				}
				else
				{
					List<int> ordered = opcodes.OrderBy(o => o).ToList();
					var sorted = new[] { ordered.Take(ordered.Count / 2).ToList(), ordered.Skip(ordered.Count / 2).ToList() };
					
					str += T("if Enum <= ") + ScrambleNumber(sorted[0].Last()) + " then ";
					str += GetStr(sorted[0]);
					str += " else";
					str += GetStr(sorted[1]);
				}

				return str;
			}

			vm += GetStr(Enumerable.Range(0, virtuals.Count).ToList());
			vm += T(settings.PreserveLineInfo ? (useRepeat ? VMStrings.VMP3_LI_R : VMStrings.VMP3_LI) : (useRepeat ? VMStrings.VMP3_R : VMStrings.VMP3));

			vm = vm.Replace("OP_ENUM", "1")
				.Replace("OP_A", "2")
				.Replace("OP_B", "3")
				.Replace("OP_C", "4");

			
			return vm;
		}
	}
}
