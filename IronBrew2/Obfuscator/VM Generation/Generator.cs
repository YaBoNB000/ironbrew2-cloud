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

		private sealed class ContinuationNode
		{
			public int OpcodeIndex;
			public int Depth;
			public int Lane;
			public uint Token;
			public uint NextToken;
			public int NextLane;
			public string Handler;
			public bool Terminal => Handler != null;
		}
		
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
			Random r = _context.Seed.GetStream("opcode.mutations");
			List<OpMutated> mutated = new List<OpMutated>();

			foreach (VOpcode opc in opcodes)
			{
				if (opc is OpSuperOperator)
					continue;

				for (int i = 0; i < r.Next(35, 50); i++)
				{
					int[] rand = {0, 1, 2};
					rand.Shuffle(r);

					OpMutated mut = new OpMutated {Random = r};

					mut.Registers = rand;
					mut.Mutated = opc;
						
					mutated.Add(mut);
				}
			}

			mutated.Shuffle(r);
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

		private static void CollectAliasableInstructions(Chunk chunk, List<Instruction> output)
		{
			for (int index = 0; index < chunk.Instructions.Count; index++)
			{
				Instruction instruction = chunk.Instructions[index];
				output.Add(instruction);
				// CLOSURE's following MOVE/GETUPVAL words are an inline binding ABI,
				// not independently dispatched instructions. OpClosure compares their
				// canonical base VIndex, so assigning an alias would change that ABI.
				if (instruction.OpCode == Opcode.Closure && instruction.RefOperands[0] is Chunk prototype)
					index += prototype.UpvalueCount;
			}
			foreach (Chunk child in chunk.Functions)
				CollectAliasableInstructions(child, output);
		}

		/// <summary>
		/// Adds build-local many-to-one opcode aliases and assigns real instructions
		/// to them. Each alias later receives an independently transformed handler,
		/// so opcode cardinality and implementation shape vary for the same source.
		/// </summary>
		private void AddOpcodeAliases(List<VOpcode> virtuals, Random random)
		{
			var instructions = new List<Instruction>();
			CollectAliasableInstructions(_context.HeadChunk, instructions);
			List<VOpcode> candidates = virtuals
				.Where(opcode => opcode is not OpAlias && opcode is not OpMutated && opcode is not OpSuperOperator)
				.Where(opcode => instructions.Any(instruction =>
					instruction.CustomData?.Opcode == opcode && instruction.CustomData.WrittenOpcode == null))
				.ToList();
			candidates.Shuffle(random);
			if (candidates.Count == 0)
				throw new InvalidOperationException("No virtual opcodes were available for build-local aliases.");

			int minimum = Math.Max(3, (candidates.Count + 5) / 6);
			int maximum = Math.Max(minimum, (candidates.Count * 2 + 4) / 5);
			int targetCount = random.Next(minimum, maximum + 1);
			int added = 0;
			foreach (VOpcode target in candidates.Take(targetCount))
			{
				List<Instruction> occurrences = instructions
					.Where(instruction => instruction.CustomData?.Opcode == target &&
					                      instruction.CustomData.WrittenOpcode == null)
					.ToList();
				occurrences.Shuffle(random);
				int aliasCount = occurrences.Count >= 4 && random.Next(4) == 0 ? 2 : 1;
				var aliases = Enumerable.Range(0, aliasCount)
					.Select(_ => new OpAlias {Target = target})
					.ToArray();
				virtuals.AddRange(aliases);
				added += aliases.Length;

				// Every emitted alias is live. Remaining occurrences choose between the
				// original and aliases, preventing one semantic ID per build.
				for (int index = 0; index < occurrences.Count; index++)
				{
					if (index < aliases.Length || random.Next(100) < 55)
						occurrences[index].CustomData.Opcode = aliases[random.Next(aliases.Length)];
				}
			}
			_context.VirtualOpcodeAliasCount = added;
			ValidateClosureBindingOpcodeAbi(_context.HeadChunk);
		}

		private void ValidateClosureBindingOpcodeAbi(Chunk chunk)
		{
			for (int index = 0; index < chunk.Instructions.Count; index++)
			{
				Instruction instruction = chunk.Instructions[index];
				if (instruction.OpCode != Opcode.Closure || instruction.RefOperands[0] is not Chunk prototype)
					continue;
				for (int offset = 1; offset <= prototype.UpvalueCount; offset++)
				{
					Instruction binding = chunk.Instructions[index + offset];
					if (!_context.InstructionMapping.TryGetValue(binding.OpCode, out VOpcode canonical) ||
					    binding.CustomData?.Opcode != canonical || binding.CustomData.WrittenOpcode != null)
						throw new InvalidOperationException("Opcode alias changed the CLOSURE binding ABI.");
				}
			}
			foreach (Chunk child in chunk.Functions)
				ValidateClosureBindingOpcodeAbi(child);
		}

		public string GenerateVM(ObfuscationSettings settings)
		{
			if (settings.EnvironmentLock && !settings.AntiDump)
				throw new InvalidOperationException("EnvironmentLock requires the VM-integrated AntiDump attestation guard.");

			Random r = _context.Seed.GetStream("vm.generator");
			BuildRandom dispatcherRandom = _context.Seed.GetStream("dispatcher.template");
			BuildRandom layoutRandom = _context.Seed.GetStream("vm.layout");
			Random guardRandom = _context.Seed.GetStream("runtime.guard");
			VMLayout vmLayout = VMLayoutSelector.Select(layoutRandom);

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

			AddOpcodeAliases(virtuals, r);
			Console.WriteLine("Added " + _context.VirtualOpcodeAliasCount + " build-local opcode aliases.");
			virtuals.Shuffle(r);
			
			for (int i = 0; i < virtuals.Count; i++)
				virtuals[i].VIndex = i;

			_context.VirtualOpcodeCount = virtuals.Count;

			string vm = "";

			// ==== P1: 模板标识符随机化(每次混淆生成不同的 VM 结构名)====
			string[] identKeys = {
				"ByteString","InstrPoint","GetFEnv","Setmetatable","Getmetatable","RawGet","RawSet","RawEqual","Next","ToNumber","ToString","ConstCount","Deserialize",
				"Wrap","Upvalues","NewProto","Indexes","Concat","Insert","LDExp","Select","Unpack",
				"BitXOR","gBits32","gBits8","gBits16","gFloat","gSizet","gString","gInt","Byte","Char","Sub",
				"gBit","Instrs","Functions","Lines","Consts","ConstCapsules","Capsule","Instr","Proto","Params","Top","Vararg","Args",
				"PCount","Lupvals","Stk","Inst","Enum","Chunk","decompress","Pos","Xs","Xd","_R","Env",
				"Varargsz","PCall","Loop","Const","RA","RB","K1","K2","K3","OpcodeKey","FieldKey","FieldKey32","U32",
				"DerivePermutation","DeriveBlockPermutation","Count","Domain","Values","State","Identity","Schema","StepIndex","Step","ConstTags","InstrCount","OpcodeBank",
				"Columns","ColumnOrder","ColumnPositions","ColumnRead8","ColumnRead16","ColumnRead32","ColumnData","ColumnPosition","PhysicalSlot","Role",
				"ComputePrototypeIntegrity","PrototypeLength","PrototypeTag","ComputeConstantIntegrity","ConstantMaskState","StoredTag","EncodedBody","RawParts","Raw","Cons","PreviousReference","Reference",
				"GetProto","Index","Encoded","Decoded","SavedByteString","SavedPos","Length","Root","Blocks","BlockMap",
				"BlockCount","BlockIndex","BlockStart","Block","RefCount","References","ReferenceIndex","Offset","ConstCache",
				"Descriptor","Type","Mask","DecodeInstructionBlock","GetInstruction","InitialFlowKey","FlowKey","FlowVerifier",
				"BlockFieldKey","BlockFieldKey32","ComputeBlockIntegrity","Flow","EntryState","FromPC","ToPC","Value","Low","High","Hash",
				"Verifier","BlockTag","SuccessorCount","Successors","SuccessorRecords","SuccessorRecord","SuccessorBlock","PreviousSuccessor","SuccessorIndex","SuccessorStart","WrappedState","LastIndex","CurrentBlock",
				"Dispatcher","RouteCount","InitialRouteToken","RouteToken","ResolveInstructionPoint","NextInstructionPoint","Routed","NextBlock",
				"DispatchMask","DispatchSalt","DispatchState","DispatchLane","DispatchActive","DispatchSteps","DispatchStepMask","DispatchMatched",
				"GuardString","GuardTable","GuardMath","GuardDebug","GuardGetInfo","GuardInfo","GuardInspector",
				"GuardUnpack","GuardTableUnpack","GuardGetFEnvGlobal","GuardEnvOK","GuardEnvironment","GuardEnvironmentRead","GuardGetGenV",
				"GuardReadEnvironment","GuardReadKey","GuardReadValue","GuardReadOK","GuardIndexedValue","GuardCapOK","GuardCapEnv","GuardCapabilityEnvironment","GuardIsC","GuardIsL","GuardCounter","GuardNextProbe",
				"GuardEpoch","GuardState","GuardSeal","GuardTripped","GuardFaultWord","GuardLuaProbe","GuardProbeValue","GuardFunction",
				"GuardProbe","Force","GuardScore","GuardHeavy",
				"GuardCurrentIsC","GuardCurrentIsL","GuardNativeMisses","GuardOK1","GuardOK2","GuardOK3","GuardOK4",
				"GuardC1","GuardC2","GuardC3","GuardC4","GuardL1","GuardL2","GuardL3","GuardLuaOK","GuardLuaIsC","GuardLuaIsL",
				"GuardKnown","GuardNative","GuardBehaviorOK","GuardBehaviorResult","GuardBehaviorTable","GuardBehaviorMeta",
				"GuardBehaviorKey","GuardFirstKey","GuardDecoy","GuardValue","GuardIndex","DecodedInstrs","FlowCache","IsSequential",
				"GuardAttestation","GuardAttested","GuardBXor","GuardCBody","GuardCValue","GuardCaller","GuardCallerOK","GuardChangedOK","GuardCheckCaller",
				"GuardClassOK1","GuardClassOK2","GuardClassOK3","GuardClassOK4","GuardCompileOK","GuardConstantProbe","GuardConstants","GuardConstantsOK",
				"GuardCurrentEnvOK","GuardCurrentEnvironment","GuardCurrentIdentity","GuardExpected","GuardGame","GuardGetConstants","GuardGetProto","GuardGetProtos",
				"GuardGetUpvalues","GuardHostOK","GuardHostResult","GuardIdOK1","GuardIdOK2","GuardIdentify","GuardInstance","GuardLaneA","GuardLaneB","GuardLaneC",
				"GuardLeft","GuardLeftBit","GuardLoadSource","GuardLoadString","GuardLoaded","GuardLoadedC","GuardLoadedCOK","GuardLoadedConstants","GuardLoadedConstantsOK",
				"GuardLoadedL","GuardLoadedLOK","GuardLoadedOK","GuardLoadedValue","GuardLookup","GuardLookupKey","GuardLookupValue","GuardLuaByte","GuardLuaProbeResult",
				"GuardName1","GuardName2","GuardNativeByte","GuardNativeProbe","GuardNewC","GuardPlayers","GuardProtoCallOK","GuardProtoCallResult","GuardProtoCandidate",
				"GuardProtoChild","GuardProtoClassOK","GuardProtoIsL","GuardProtoItem","GuardProtoKey","GuardProtoOK","GuardProtoProbe","GuardProtoResult","GuardProtoValue",
				"GuardProtos","GuardProtosOK","GuardRestoreOK","GuardRight","GuardRightBit","GuardRoute","GuardSetOK","GuardSetupValue","GuardStrictChallenge",
				"GuardTableContains","GuardTableEmpty","GuardTask","GuardTranscript","GuardTranscriptValue","GuardTranscriptWord","GuardTypeOf","GuardUpvalue","GuardUpvalueProbe","GuardUpvalues",
				"GuardUpvaluesOK","GuardValid","GuardValueItem","GuardValueKey","GuardValues","GuardVector","GuardVector3","GuardVersion1","GuardVersion2","GuardWrapOK",
				"GuardWrapped","GuardWrappedC","GuardWrappedCOK","GuardWrappedL","GuardWrappedLOK","GuardWrappedOK","GuardWrappedValue","GuardXorBit","GuardXorIndex","GuardXorValue",
				"GuardActivated","GuardActivatedOK","GuardActivatedValid","GuardActiveCallOK","GuardActiveCallResult","GuardActiveProto","GuardCConstantsOK","GuardCOK","GuardCProtoOK",
				"GuardCProtosOK","GuardCResult","GuardCSetupOK","GuardCUpvalues","GuardCUpvaluesOK","GuardCapabilityMarker","GuardCapabilityOld","GuardClassifies","GuardExpectedC",
				"GuardInactiveCallOK","GuardInactiveCallResult","GuardInactiveProto","GuardInactiveProtoOK","GuardInactiveType","GuardInvalidError","GuardInvalidFunction","GuardInvalidOK","GuardInvalidSource","GuardLOK","GuardLResult",
				"GuardPersistent","GuardProtoConstants","GuardProtoConstantsOK","GuardProtosValid","GuardReject","GuardRepeatEnvironment","GuardRepeatOK","GuardReportOnly","GuardSawInactiveProto","GuardSeparated",
				"GuardThreadMarker","GuardThreadOld","GuardCanaryOK","GuardCapabilityRestoreOK","GuardThreadRestoreOK","GuardWrappedUpvalues","GuardWrappedUpvaluesOK",
				"GuardPrimitiveIndex","GuardPrimitives",
				"PayloadRejectA","PayloadRejectB","PayloadRejectC","PayloadRejectD",
				"PayloadRejectVoidA","PayloadRejectVoidB","PayloadRejectVoidC","PayloadRejectVoidD",
				"PayloadRejectCodeA","PayloadRejectCodeB","PayloadRejectCodeC","PayloadRejectCodeD",
				"PayloadHead","PayloadTag","PayloadFlags","PayloadFeatures","PayloadVersion","OuterSeed","PayloadHash","PayloadIndex","PayloadDecoded","PayloadByte","PayloadKey",
				"EnvelopePos","EnvelopeRead32","EnvelopeRealLength","EnvelopeEntropyLength","EnvelopeRecordCount","EnvelopeDataCount","EnvelopeEntropyCount","EnvelopeNonce","EnvelopeDigest","EnvelopeTag","EnvelopeExpected",
				"EnvelopeHash","EnvelopeIndex","EnvelopeDataRecords","EnvelopeEntropyRecords","EnvelopeDataLength","EnvelopeEntropySeenLength","EnvelopeKind","EnvelopeOrdinal","EnvelopeLength","EnvelopeRecord",
				"EntropyHash","EnvelopeByteIndex","EnvelopeState","EnvelopeBody","EnvelopeBodyIndex","EnvelopeKey",
				"LayoutFrameA","LayoutFrameB","LayoutFrameC"
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

			int[] GenerateRuntimeSlotPermutation(int count, Random random = null)
			{
				random ??= r;
				int[] slots = Enumerable.Range(1, count).ToArray();
				for (int index = slots.Length - 1; index > 0; index--)
				{
					int swapIndex = random.Next(index + 1);
					(slots[index], slots[swapIndex]) = (slots[swapIndex], slots[index]);
				}
				// Never emit the legacy identity layout, even in the unlikely event that
				// Fisher-Yates produced it. This guarantees fixed-index dumpers fail.
				if (slots.Select((value, index) => value == index + 1).All(value => value))
					(slots[0], slots[1]) = (slots[1], slots[0]);
				return slots;
			}

			string ApplyRuntimeSlotPermutation(string code, string identifier, int[] slots)
			{
				string pattern = "\\b" + Regex.Escape(identifier) + @"\s*\[\s*(\d+)\s*\]";
				string RewriteCode(string segment) => Regex.Replace(segment, pattern, match =>
				{
					int oldSlot = int.Parse(match.Groups[1].Value);
					return oldSlot >= 1 && oldSlot <= slots.Length
						? identifier + "[" + slots[oldSlot - 1] + "]"
						: match.Value;
				});

				// Do not let an identifier-looking sequence inside a base91 payload,
				// watermark, quoted literal, long string or comment mutate protected data.
				// Only executable Lua spans are eligible for numeric ABI rewriting.
				var rewritten = new StringBuilder(code.Length);
				int plainStart = 0;
				int index = 0;

				int LongBracketLevel(int at)
				{
					if (at >= code.Length || code[at] != '[') return -1;
					int cursor = at + 1;
					while (cursor < code.Length && code[cursor] == '=') cursor++;
					return cursor < code.Length && code[cursor] == '[' ? cursor - at - 1 : -1;
				}

				int LongBracketEnd(int at, int level)
				{
					string close = "]" + new string('=', level) + "]";
					int contentStart = at + level + 2;
					int closeAt = code.IndexOf(close, contentStart, StringComparison.Ordinal);
					return closeAt < 0 ? code.Length : closeAt + close.Length;
				}

				void Preserve(int start, int end)
				{
					rewritten.Append(RewriteCode(code.Substring(plainStart, start - plainStart)));
					rewritten.Append(code, start, end - start);
					plainStart = end;
					index = end;
				}

				while (index < code.Length)
				{
					char current = code[index];
					if (current == '\'' || current == '"')
					{
						char quote = current;
						int end = index + 1;
						while (end < code.Length)
						{
							if (code[end] == '\\')
							{
								end = Math.Min(code.Length, end + 2);
								continue;
							}
							if (code[end++] == quote) break;
						}
						Preserve(index, end);
						continue;
					}

					if (current == '-' && index + 1 < code.Length && code[index + 1] == '-')
					{
						int commentBody = index + 2;
						int level = LongBracketLevel(commentBody);
						int end = level >= 0 ? LongBracketEnd(commentBody, level) : code.IndexOf('\n', commentBody);
						if (end < 0) end = code.Length;
						Preserve(index, end);
						continue;
					}

					if (current == '[')
					{
						int level = LongBracketLevel(index);
						if (level >= 0)
						{
							Preserve(index, LongBracketEnd(index, level));
							continue;
						}
					}
					index++;
				}

				rewritten.Append(RewriteCode(code.Substring(plainStart)));
				return rewritten.ToString();
			}

			string ApplyVMLayout(string code, VMLayout layout)
			{
				// These are the invocation-mutable values shared by the VM loop and its
				// in-scope opcode handlers. Layouts alter their actual carriers rather
				// than merely renaming locals or permuting a pre-existing table.
				string[] stateKeys = {
					"InstrPoint", "Flow", "Top", "Vararg", "Lupvals", "Stk", "Varargsz", "Inst", "Enum"
				};
				string[] frameKeys = {"LayoutFrameA", "LayoutFrameB", "LayoutFrameC"};
				int[] capacities;
				var candidates = new List<string>();
				switch (layout)
				{
					case VMLayout.DualPartitioned:
						capacities = new[] {4, 5};
						candidates.AddRange(stateKeys);
						break;
					case VMLayout.TieredPartitioned:
						capacities = new[] {2, 3, 4};
						candidates.AddRange(stateKeys);
						break;
					case VMLayout.HybridLocals:
						capacities = new[] {3, 3};
						// Invocation-only vararg/upvalue state stays lexical while the six hot
						// cursor, flow, stack and decode values move through two frames.
						candidates.AddRange(new[] {"InstrPoint", "Flow", "Top", "Stk", "Inst", "Enum"});
						break;
					default:
						throw new InvalidOperationException("Unknown VM layout template.");
				}

				candidates.Shuffle(layoutRandom);
				var replacements = new Dictionary<string, string>();
				var frameNames = new List<string>();
				int candidateOffset = 0;
				for (int frameIndex = 0; frameIndex < capacities.Length; frameIndex++)
				{
					string frameName = idents[frameKeys[frameIndex]];
					frameNames.Add(frameName);
					List<string> group = candidates.Skip(candidateOffset).Take(capacities[frameIndex])
						.OrderBy(key => Array.IndexOf(stateKeys, key)).ToList();
					candidateOffset += capacities[frameIndex];
					int[] slots = GenerateRuntimeSlotPermutation(group.Count, layoutRandom);
					for (int roleIndex = 0; roleIndex < group.Count; roleIndex++)
						replacements[idents[group[roleIndex]]] = frameName + "[" + slots[roleIndex] + "]";
				}
				if (candidateOffset != candidates.Count)
					throw new InvalidOperationException("VM layout did not assign every selected state role.");

				Match wrapMatch = Regex.Match(code,
					@"\blocal\s+function\s+" + Regex.Escape(idents["Wrap"]) + @"\s*\(");
				if (!wrapMatch.Success)
					throw new InvalidOperationException("VM layout could not locate the Wrap closure.");
				Match rootMatch = Regex.Match(code.Substring(wrapMatch.Index),
					@"\blocal\s+" + Regex.Escape(idents["Root"]) + @"\s*=\s*" +
					Regex.Escape(idents["Deserialize"]) + @"\s*\(\s*\)\s*;");
				if (!rootMatch.Success)
					throw new InvalidOperationException("VM layout could not locate the root-deserialization boundary.");
				int wrapEnd = wrapMatch.Index + rootMatch.Index;
				string wrap = code.Substring(wrapMatch.Index, wrapEnd - wrapMatch.Index);

				// Declarations must become keyed assignments before identifier accesses
				// are rewritten. In particular, bare `local Inst;` cannot become a table
				// expression statement in Lua 5.1.
				foreach (string identifier in replacements.Keys)
				{
					string escaped = Regex.Escape(identifier);
					wrap = Regex.Replace(wrap, @"\blocal\s+" + escaped + @"\s*;", identifier + "=nil;");
					wrap = Regex.Replace(wrap, @"\blocal\s+" + escaped + @"\s*=", identifier + "=");
				}
				foreach (KeyValuePair<string, string> replacement in replacements)
					wrap = Regex.Replace(wrap, @"\b" + Regex.Escape(replacement.Key) + @"\b", replacement.Value);

				// Declaration order is independent from role partitioning and slot order.
				// All frames remain invocation-local and therefore die with the closure.
				frameNames.Shuffle(layoutRandom);
				string frameInit = string.Concat(frameNames.Select(name => "local " + name + "={};"));
				var closureAnchor = new Regex(@"\breturn\s+function\s*\(\s*\.\.\.\s*\)");
				Match closureMatch = closureAnchor.Match(wrap);
				if (!closureMatch.Success)
					throw new InvalidOperationException("VM layout could not locate the invocation closure.");
				wrap = wrap.Insert(closureMatch.Index + closureMatch.Length, frameInit);

				foreach (KeyValuePair<string, string> replacement in replacements)
				{
					if (Regex.IsMatch(wrap, @"\blocal\s+" + Regex.Escape(replacement.Key) + @"\b") ||
					    !wrap.Contains(replacement.Value, StringComparison.Ordinal))
						throw new InvalidOperationException("VM layout left a selected state role in its original carrier.");
				}
				return code.Substring(0, wrapMatch.Index) + wrap + code.Substring(wrapEnd);
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

			// Continuation tokens occupy the full unsigned 32-bit range. Keep every
			// arithmetic form below exact in Lua's double representation while avoiding
			// one canonical decimal spelling for the dispatch graph.
			string ScrambleUInt(uint n)
			{
				ulong value = n;
				switch (r.Next(5))
				{
					case 0: return "(" + value + "+0)";
					case 1: return "(" + value + "-0)";
					case 2: return "(" + value + "*1)";
					case 3:
					{
						ulong left = (ulong)r.NextInt64(0, (long)value + 1);
						return "(" + left + "+" + (value - left) + ")";
					}
					default:
					{
						ulong extra = (ulong)r.Next(1, 1 << 20);
						return "(" + (value + extra) + "-" + extra + ")";
					}
				}
			}

			string ApplyBuildDomains(string code)
			{
				BuildDomains domains = _context.Domains;
				var replacements = new Dictionary<string, string>
				{
					["__IB2_DOMAIN_INTEGRITY__"] = domains.IntegrityDomain.ToString(),
					["__IB2_DOMAIN_BLOCK_INTEGRITY__"] = domains.BlockIntegrityDomain.ToString(),
					["__IB2_DOMAIN_FLOW__"] = domains.FlowDomain.ToString(),
					["__IB2_DOMAIN_ENVELOPE_INTEGRITY__"] = domains.EnvelopeIntegrityDomain.ToString(),
					["__IB2_DOMAIN_ENTROPY_DIGEST__"] = domains.EntropyDigestDomain.ToString(),
					["__IB2_DOMAIN_ENVELOPE_MASK__"] = domains.EnvelopeMaskDomain.ToString(),
					["__IB2_DOMAIN_CONSTANT_INTEGRITY__"] = domains.ConstantIntegrityDomain.ToString(),
					["__IB2_DOMAIN_CONSTANT_MASK__"] = domains.ConstantMaskDomain.ToString(),
					["__IB2_DOMAIN_PROTOTYPE_INTEGRITY__"] = domains.PrototypeIntegrityDomain.ToString(),
					["__IB2_DOMAIN_OPCODE_PERMUTATION__"] = domains.OpcodePermutationDomain.ToString(),
					["__IB2_DOMAIN_SCHEMA_PERMUTATION__"] = domains.SchemaPermutationDomain.ToString(),
					["__IB2_DOMAIN_CONSTANT_TAG_PERMUTATION__"] = domains.ConstantTagPermutationDomain.ToString(),
					["__IB2_DOMAIN_BLOCK_COLUMN__"] = domains.BlockColumnDomain.ToString(),
					["__IB2_BLOCK_FIELD_STRIDE__"] = domains.BlockFieldStride.ToString(),
					["__IB2_FLOW_VERIFIER_MASK__"] = domains.FlowVerifierMask.ToString(),
					["__IB2_ENTROPY_RECORD_KIND__"] = domains.EntropyRecordKind.ToString(),
					["__IB2_DATA_RECORD_KIND__"] = domains.DataRecordKind.ToString()
				};
				foreach (KeyValuePair<string, string> replacement in replacements)
					code = code.Replace(replacement.Key, replacement.Value);
				if (Regex.IsMatch(code, @"__IB2_(?:DOMAIN|BLOCK_FIELD|FLOW_VERIFIER|ENTROPY_RECORD|DATA_RECORD)"))
					throw new InvalidOperationException("A per-build runtime domain placeholder was not replaced.");
				return code;
			}

			string[] payloadRejectKeys = {"PayloadRejectA", "PayloadRejectB", "PayloadRejectC", "PayloadRejectD"};
			string[] payloadRejectVoidKeys = {"PayloadRejectVoidA", "PayloadRejectVoidB", "PayloadRejectVoidC", "PayloadRejectVoidD"};
			string[] payloadRejectCodeKeys = {"PayloadRejectCodeA", "PayloadRejectCodeB", "PayloadRejectCodeC", "PayloadRejectCodeD"};

			// Payload authentication failures deliberately enter one of four native
			// runtime-fault shapes. Randomized identifiers and per-site encoded values
			// avoid both a stable diagnostic and a repeated direct error(...) signature.
			string BuildPayloadRejectRuntime()
			{
				string[] bodies = {
					"return {VOID}[{CODE}];",
					"return {VOID}({CODE});",
					"return {CODE}+{VOID};",
					"return #{VOID}+{CODE};"
				};
				bodies = bodies.OrderBy(_ => r.Next()).ToArray();
				var runtime = new StringBuilder();
				for (int i = 0; i < payloadRejectKeys.Length; i++)
				{
					string body = bodies[i]
						.Replace("{VOID}", payloadRejectVoidKeys[i])
						.Replace("{CODE}", payloadRejectCodeKeys[i]);
					runtime.Append("local function ").Append(payloadRejectKeys[i]).Append('(').Append(payloadRejectCodeKeys[i]).Append(')')
						.Append("local ").Append(payloadRejectVoidKeys[i]).Append(';').Append(body).Append("end;");
				}
				return T(runtime.ToString());
			}

			string RewritePayloadRejects(string code)
			{
				const string pattern = @"error\s*\(\s*(['""])invalid protected payload\1\s*,\s*0\s*\)";
				int replacementCount = 0;
				int rejectOffset = r.Next(payloadRejectKeys.Length);
				code = Regex.Replace(code, pattern, _ =>
				{
					int rejectIndex = replacementCount < payloadRejectKeys.Length
						? (rejectOffset + replacementCount) % payloadRejectKeys.Length
						: r.Next(payloadRejectKeys.Length);
					replacementCount++;
					string rejectName = idents[payloadRejectKeys[rejectIndex]];
					uint rejectCode = (uint)r.NextInt64(0, 1L << 32);
					return rejectName + "(" + ScrambleUInt(rejectCode) + ")";
				});
				if (replacementCount == 0 || code.Contains("invalid protected payload", StringComparison.Ordinal))
					throw new InvalidOperationException("Payload rejection diagnostics were not fully rewritten.");
				return code;
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

			// Handler 语义实现多态：对最常见的 VM register 写回，在不改变
			// operand 求值顺序的前提下，随机选择直接写回、结果暂存、destination
			// 提前解析或 destination 延后解析的数据流。它改变的是 handler 的
			// def-use graph，而不只是套一层无效控制流。
			int semanticLocalSerial = 0;
			string ApplySemanticPolymorphism(string code)
			{
				const string target = @"Stk\s*\[\s*Inst\s*\[\s*OP_A\s*\]\s*\]";
				string pattern = @"(?<target>" + target + @")\s*=(?!=)\s*(?<value>[^;]+);";
				return Regex.Replace(code, pattern, match =>
				{
					int variant = r.Next(4);
					if (variant == 0)
						return match.Value;

					string value = match.Groups["value"].Value.Trim();
					string serial = (semanticLocalSerial++).ToString();
					string result = "_sv" + serial;
					if (variant == 1)
						return "local " + result + "=" + value + ";Stk[Inst[OP_A]]=" + result + ";";

					string destination = "_sd" + serial;
					if (variant == 2)
						return "local " + destination + "=Inst[OP_A];local " + result + "=" + value + ";Stk[" + destination + "]=" + result + ";";

					return "local " + result + "=" + value + ";local " + destination + "=Inst[OP_A];Stk[" + destination + "]=" + result + ";";
				});
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
local Getmetatable = getmetatable;
local RawGet       = rawget;
local RawSet       = rawset;
local RawEqual     = rawequal;
local Next         = next;
local Select       = select;
local PCall        = pcall;
local Type         = type;
local ToString     = tostring;

local Unpack = unpack or table.unpack;
local ToNumber = tonumber;");

			if (settings.AntiDump)
				vm += T(AntiDumpGenerator.GenerateRuntimeGuard(
					37 + r.Next(36),
					(uint) r.Next(1, int.MaxValue),
					_context.Binder.AttestationToken,
					guardRandom));

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

			vm += BuildPayloadRejectRuntime();
			vm += T(ApplyBuildDomains(VMStrings.VMP1
				// 环境绑定：注入种子派生代码（读盐 → 跑探针 → Hash 派生 Xs）
				.Replace("__IB2_SEED__", settings.EnvironmentLock ? _context.Binder.SeedDeriveLua : EnvBinder.PlainSeedLua)
				.Replace("__IB2_WATERMARK__", EscapeLuaString(settings.Watermark))
				.Replace("__IB2_OPCODE_COUNT__", virtuals.Count.ToString())));
			
				// 每个 prototype 根据自身 K1/K2/K3 派生独立字段顺序。
				// 常量在这里仅按 capsule framing 切片；认证和明文恢复延迟到 block 进入时。
				vm += T(ApplyBuildDomains(@"local Schema = DerivePermutation(5, K1, K2, K3, __IB2_DOMAIN_SCHEMA_PERMUTATION__);
	for StepIndex = 1, 5 do
	    local Step = Schema[StepIndex];
	    if (Step == 0) then
	        Chunk[3] = gBits8();
	    elseif (Step == 1) then
	        local ConstCount = gBits32();
	        for Idx = 1, ConstCount do
	            local Length = gBits32();
	            if Length < 5 or Pos + Length - 1 > PrototypeLength then error('invalid protected payload', 0); end;
	            ConstCapsules[Idx] = Sub(ByteString, Pos, Pos + Length - 1);
	            Pos = Pos + Length;
	        end;
	    elseif (Step == 2) then
        InstrCount = gBits32();
        BlockCount = gBits32();
        Chunk[11] = BlockCount;
        Chunk[12] = gBits32();
        InitialRouteToken = U32(BitXOR(gBits32(), OuterSeed));
	        for BlockIndex = 1, BlockCount do
	            local BlockStart = gBits32();
	            local Count = gBits32();
	            local RouteToken = gBits32();
	            if BlockStart < 1 or Count < 1 or BlockStart + Count - 1 > InstrCount then error('invalid protected payload', 0); end;
	            local RefCount = gBits32();
	            local References = {};
	            local PreviousReference = 0;
	            for ReferenceIndex = 1, RefCount do
	                local Reference = gBits32();
	                if Reference <= PreviousReference then error('invalid protected payload', 0); end;
	                References[ReferenceIndex], PreviousReference = Reference, Reference;
	            end;
	            local Verifier = gBits32();
	            local BlockTag = gBits32();
	            local SuccessorCount = gBits32();
	            local Successors = {};
	            local SuccessorRecords = {};
	            local PreviousSuccessor = 0;
	            for SuccessorIndex = 1, SuccessorCount do
	                local SuccessorStart = gBits32();
	                local WrappedState = gBits32();
	                if SuccessorStart <= PreviousSuccessor then error('invalid protected payload', 0); end;
	                Successors[SuccessorStart] = WrappedState;
	                SuccessorRecords[SuccessorIndex] = {SuccessorStart, WrappedState};
	                PreviousSuccessor = SuccessorStart;
	            end;
	            local Length = gBits32();
	            if Length < 21 or Pos + Length - 1 > PrototypeLength then error('invalid protected payload', 0); end;
	            local Block = {};
	            Block[1] = BlockStart;
	            Block[2] = Count;
	            Block[3] = Sub(ByteString, Pos, Pos + Length - 1);
	            Block[4] = References;
	            Block[5] = Successors;
	            Block[6] = Verifier;
	            Block[7] = BlockTag;
	            Block[8] = RouteToken;
	            Block[9] = SuccessorRecords;
	            Pos = Pos + Length;
	            Blocks[BlockIndex] = Block;
	            if RouteToken ~= 0 then
	                if RouteToken <= InstrCount or Dispatcher[RouteToken] then error('invalid protected payload', 0); end;
	                Dispatcher[RouteToken] = BlockStart;
	                RouteCount = RouteCount + 1;
	            end;
	            for Offset = 0, Count - 1 do
	                if BlockMap[BlockStart + Offset] then error('invalid protected payload', 0); end;
	                BlockMap[BlockStart + Offset] = Block;
	            end;
	        end;
	    elseif (Step == 3) then
	        for Idx = 1, gBits32() do
	            local Length = gBits32();
	            if Length < 10 or Pos + Length - 1 > PrototypeLength then error('invalid protected payload', 0); end;
	            Functions[Idx - 1] = Sub(ByteString, Pos, Pos + Length - 1);
	            Pos = Pos + Length;
	        end;"));

			if (settings.PreserveLineInfo)
				vm += T(@"    elseif (Step == 4) then
        for Idx = 1, gBits32() do Lines[Idx] = gBits32(); end;");

				vm += T(@"    end;
	end;

	if Pos ~= PrototypeLength + 1 or Chunk[3] == nil then error('invalid protected payload', 0); end;
	if InitialRouteToken ~= 0 then
	    if RouteCount ~= BlockCount or Dispatcher[InitialRouteToken] ~= 1 then error('invalid protected payload', 0); end;
	    Chunk[13], Chunk[14] = Dispatcher, InitialRouteToken;
	elseif RouteCount ~= 0 then
	    error('invalid protected payload', 0);
	end;

	for Index = 1, InstrCount do if not BlockMap[Index] then error('invalid protected payload', 0); end; end;
	for BlockIndex = 1, BlockCount do
	    local Block = Blocks[BlockIndex];
	    local References = Block[4];
	    for ReferenceIndex = 1, #References do
	        if type(ConstCapsules[References[ReferenceIndex]]) ~= 'string' then error('invalid protected payload', 0); end;
	    end;
	    local SuccessorRecords = Block[9];
	    for SuccessorIndex = 1, #SuccessorRecords do
	        local SuccessorStart = SuccessorRecords[SuccessorIndex][1];
	        local SuccessorBlock = BlockMap[SuccessorStart];
	        if not SuccessorBlock or SuccessorBlock[1] ~= SuccessorStart then error('invalid protected payload', 0); end;
	    end;
	end;");

			vm += T("return Chunk;end;");

			string blockRuntime = @"
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

local function DecodeConstantCapsule(Capsule, Index, K1, K2, K3, ConstTags)
    local SavedByteString, SavedPos = ByteString, Pos;
    ByteString, Pos = Capsule, 1;
    local StoredTag = gBits32();
    local EncodedBody = Sub(Capsule, 5);
    if ComputeConstantIntegrity(EncodedBody, Index, K1, K2, K3) ~= StoredTag then error('invalid protected payload', 0); end;
    local State = ConstantMaskState(Index, K1, K2, K3);
    local RawParts = {};
    for I = 1, #EncodedBody do
        local Mask = (State - State % 16777216) / 16777216;
        RawParts[I] = Char(BitXOR(Byte(EncodedBody, I, I), Mask));
        State = (State * 1664525 + 1013904223) % 4294967296;
    end;
    local Raw = Concat(RawParts);
    ByteString, Pos = Raw, 1;
    local Type = gBits8();
    local Cons;
    if Type == ConstTags[1] then
        Cons = nil;
    elseif Type == ConstTags[2] then
        local Value = gBits8();
        if Value > 1 then error('invalid protected payload', 0); end;
        Cons = Value ~= 0;
    elseif Type == ConstTags[3] then
        Cons = gFloat();
    elseif Type == ConstTags[4] then
        local Length = gBits32();
        if Pos + Length - 1 > #Raw then error('invalid protected payload', 0); end;
        Cons = Sub(Raw, Pos, Pos + Length - 1);
        Pos = Pos + Length;
    else
        error('invalid protected payload', 0);
    end;
    if Pos ~= #Raw + 1 then error('invalid protected payload', 0); end;
    ByteString, Pos = SavedByteString, SavedPos;
    return Cons;
end;

local function DecodeInstructionBlock(Chunk, Block, EntryState)
    local SavedByteString, SavedPos = ByteString, Pos;
    local K1, K2, K3 = Chunk[5], Chunk[6], Chunk[7];
    local References = Block[4];
    local ConstCapsules = Chunk[15];
    if ComputeBlockIntegrity(Block[3], EntryState, Block[1], Block[2], Block[8], References, ConstCapsules, Block[6], Block[9], K1, K2, K3) ~= Block[7] then
        error('invalid protected payload', 0);
    end;
    local ConstTags = DerivePermutation(4, K1, K2, K3, __IB2_DOMAIN_CONSTANT_TAG_PERMUTATION__);
    local ConstCache = {};
    for ReferenceIndex = 1, #References do
        local Index = References[ReferenceIndex];
        ConstCache[Index] = DecodeConstantCapsule(ConstCapsules[Index], Index, K1, K2, K3, ConstTags);
    end;
    -- Authenticate first, then split all five length-framed physical pages and
    -- recover their logical descriptor/opcode/A/B/C roles from this block's state.
    ByteString, Pos = Block[3], 1;
    local ColumnOrder = DeriveBlockPermutation(5, EntryState, K1, K2, K3, __IB2_DOMAIN_BLOCK_COLUMN__);
    local Columns = {};
    for PhysicalSlot = 1, 5 do
        if Pos + 3 > #ByteString then error('invalid protected payload', 0); end;
        local Length = gBits32();
        if Length > #ByteString - Pos + 1 then error('invalid protected payload', 0); end;
        local Role = ColumnOrder[PhysicalSlot] + 1;
        if Columns[Role] ~= nil then error('invalid protected payload', 0); end;
        Columns[Role] = Sub(ByteString, Pos, Pos + Length - 1);
        Pos = Pos + Length;
    end;
    if Pos ~= #ByteString + 1 then error('invalid protected payload', 0); end;
    ByteString, Pos = SavedByteString, SavedPos;

    local ColumnPositions = {1, 1, 1, 1, 1};
    local function ColumnRead8(Role)
        local ColumnData = Columns[Role];
        local ColumnPosition = ColumnPositions[Role];
        if type(ColumnData) ~= 'string' or ColumnPosition > #ColumnData then error('invalid protected payload', 0); end;
        ColumnPositions[Role] = ColumnPosition + 1;
        return Byte(ColumnData, ColumnPosition, ColumnPosition);
    end;
    local function ColumnRead16(Role)
        local ColumnData = Columns[Role];
        local ColumnPosition = ColumnPositions[Role];
        if type(ColumnData) ~= 'string' or ColumnPosition + 1 > #ColumnData then error('invalid protected payload', 0); end;
        ColumnPositions[Role] = ColumnPosition + 2;
        return Byte(ColumnData, ColumnPosition, ColumnPosition) + Byte(ColumnData, ColumnPosition + 1, ColumnPosition + 1) * 256;
    end;
    local function ColumnRead32(Role)
        local ColumnData = Columns[Role];
        local ColumnPosition = ColumnPositions[Role];
        if type(ColumnData) ~= 'string' or ColumnPosition + 3 > #ColumnData then error('invalid protected payload', 0); end;
        ColumnPositions[Role] = ColumnPosition + 4;
        return Byte(ColumnData, ColumnPosition, ColumnPosition) + Byte(ColumnData, ColumnPosition + 1, ColumnPosition + 1) * 256 +
               Byte(ColumnData, ColumnPosition + 2, ColumnPosition + 2) * 65536 + Byte(ColumnData, ColumnPosition + 3, ColumnPosition + 3) * 16777216;
    end;

    __IB2_DECODE_TARGET__
    for Offset = 0, Block[2] - 1 do
        local Index = Block[1] + Offset;
        local Descriptor = BitXOR(ColumnRead8(1), BlockFieldKey(EntryState, Index, 7, K1, K2, K3) % 256);
        if Descriptor >= 64 then error('invalid protected payload', 0); end;
        if (gBit(Descriptor, 1, 1) == 0) then
            local Type = gBit(Descriptor, 2, 3);
            local Mask = gBit(Descriptor, 4, 6);
            local Inst =
            {
                ColumnRead16(2),
                BitXOR(BitXOR(ColumnRead16(3), FieldKey(Index, 1, K1, K2, K3)), BlockFieldKey(EntryState, Index, 1, K1, K2, K3)),
                nil,
                nil
            };

            if (Type == 0) then
                Inst[OP_B] = BitXOR(BitXOR(ColumnRead16(4), FieldKey(Index, 2, K1, K2, K3)), BlockFieldKey(EntryState, Index, 2, K1, K2, K3));
                Inst[OP_C] = BitXOR(BitXOR(ColumnRead16(5), FieldKey(Index, 3, K1, K2, K3)), BlockFieldKey(EntryState, Index, 3, K1, K2, K3));
            elseif (Type == 1) then
                Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3)));
            elseif (Type == 2) then
                Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3))) - (2 ^ 16);
            elseif (Type == 3) then
                Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(Index, 2, K1, K2, K3)), BlockFieldKey32(EntryState, Index, 2, K1, K2, K3))) - (2 ^ 16);
                Inst[OP_C] = BitXOR(BitXOR(ColumnRead16(5), FieldKey(Index, 3, K1, K2, K3)), BlockFieldKey(EntryState, Index, 3, K1, K2, K3));
            end;

            if (gBit(Mask, 1, 1) == 1) then Inst[OP_A] = ConstCache[Inst[OP_A]]; end;
            if (gBit(Mask, 2, 2) == 1) then Inst[OP_B] = ConstCache[Inst[OP_B]]; end;
            if (gBit(Mask, 3, 3) == 1) then Inst[OP_C] = ConstCache[Inst[OP_C]]; end;
            Instrs[Index] = Inst;
        elseif Descriptor ~= 1 then
            error('invalid protected payload', 0);
        end;
    end;
    for Role = 1, 5 do
        if type(Columns[Role]) ~= 'string' or ColumnPositions[Role] ~= #Columns[Role] + 1 then error('invalid protected payload', 0); end;
    end;
    __IB2_DECODE_FINALIZE__
end;

local function GetInstruction(Chunk, Index, Flow)
    local BlockMap = Chunk[10];
    local Block = BlockMap and BlockMap[Index];
    if not Block then error('invalid protected payload', 0); end;

    local LastIndex = Flow[1];
    local CurrentBlock = Flow[2];
    __IB2_CACHE_SEQUENTIAL__
    local EntryState;
    if not CurrentBlock then
        if Index ~= 1 then error('invalid protected payload', 0); end;
        __IB2_FIRST_BLOCK_CHECK__
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

    __IB2_INSTRUCTION_LOOKUP__
end;

-- For selected prototypes InstrPoint is a random route token at every basic-
-- block boundary. Sequential execution remains linear only inside one block.
local function ResolveInstructionPoint(Chunk, Value, Flow)
    local Dispatcher = Chunk[13];
    if not Dispatcher then return Value; end;
    local Routed = Dispatcher[Value];
    if Routed then return Routed; end;
    local Block = Chunk[10] and Chunk[10][Value];
    if Block and Block == Flow[2] and Value == Flow[1] + 1 then return Value; end;
    error('invalid protected payload', 0);
end;

local function NextInstructionPoint(Chunk, Index, Flow)
    local Dispatcher = Chunk[13];
    if not Dispatcher then return Index; end;
    local NextBlock = Chunk[10] and Chunk[10][Index];
    if not NextBlock then error('invalid protected payload', 0); end;
    if NextBlock ~= Flow[2] or Index ~= Flow[1] + 1 then
        local RouteToken = NextBlock[8];
        if not RouteToken or Dispatcher[RouteToken] ~= NextBlock[1] then error('invalid protected payload', 0); end;
        return RouteToken;
    end;
    return Index;
end;";

			if (settings.AntiDump)
			{
				blockRuntime = blockRuntime
					.Replace("__IB2_DECODE_TARGET__", "local Instrs = {};")
					.Replace("__IB2_DECODE_FINALIZE__", "return Instrs;")
					.Replace("__IB2_FIRST_BLOCK_CHECK__", "if GuardProbe(true) then Chunk[2], Chunk[15], Flow[4] = {}, {}, nil; return GuardDecoy(); end;")
					.Replace("__IB2_CACHE_SEQUENTIAL__", "local IsSequential = CurrentBlock ~= nil and CurrentBlock == Block and Index == LastIndex + 1;")
						.Replace("__IB2_INSTRUCTION_LOOKUP__", @"local FlowCache = Flow[4];
    if not IsSequential or not FlowCache or FlowCache[1] ~= Block or FlowCache[2] ~= EntryState then
        local DecodedInstrs = DecodeInstructionBlock(Chunk, Block, EntryState);
        FlowCache = {};
        FlowCache[1] = Block;
        FlowCache[2] = EntryState;
        FlowCache[3] = DecodedInstrs;
        Flow[4] = FlowCache;
    end;
    local Inst = FlowCache[3][Index];
    if not Inst then error('invalid protected payload', 0); end;
    return Inst;");
			}
			else
			{
				blockRuntime = blockRuntime
					.Replace("__IB2_DECODE_TARGET__", "local Instrs = Chunk[1];")
					.Replace("__IB2_DECODE_FINALIZE__", "Block[3], Block[4], Block[7], Block[9] = nil, nil, nil, nil; Chunk[11] = Chunk[11] - 1; if Chunk[11] == 0 then Chunk[9], Chunk[15] = nil, nil; end;")
					.Replace("__IB2_FIRST_BLOCK_CHECK__", "")
					.Replace("__IB2_CACHE_SEQUENTIAL__", "")
					.Replace("__IB2_INSTRUCTION_LOOKUP__", "local Inst = Chunk[1][Index]; if Inst then return Inst; end; DecodeInstructionBlock(Chunk, Block, EntryState); Inst = Chunk[1][Index]; if not Inst then error('invalid protected payload', 0); end; return Inst;");
			}
			vm += T(ApplyBuildDomains(blockRuntime));

			string loopRuntime = settings.PreserveLineInfo ? (useRepeat ? VMStrings.VMP2_LI_R : VMStrings.VMP2_LI) : (useRepeat ? VMStrings.VMP2_R : VMStrings.VMP2);
			loopRuntime = loopRuntime.Replace("__IB2_GUARD_CHECK__", settings.AntiDump
				? "GuardProbe(false);"
				: "");
			vm += T(loopRuntime);

			if (settings.Noise)
				vm += T(AntiDumpGenerator.GenerateLoopNoise(guardRandom));

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
				string code = ApplySemanticPolymorphism(virtuals[opcodeIndex].GetObfuscated(_context));
				code = ApplyHandlerTemplate(code);
				code = T(code);
				code = ScrambleOps(code);
				if (settings.Noise)
					code = FlattenCode(code);
				return code;
			}
			
			// The opcode tree no longer owns handler bodies. It selects a masked entry
			// token, then a build-random 3-5 lane continuation graph reaches the handler
			// through 2-4 state transitions. Handlers stay in this Wrap lexical scope,
			// preserving top-level return and direct InstrPoint/Top updates.
			int laneCount = 3 + r.Next(3);
			var usedContinuationTokens = new HashSet<uint>();
			uint NewContinuationToken()
			{
				uint token;
				do token = unchecked((uint)r.NextInt64(1L, 4294967296L));
				while (!usedContinuationTokens.Add(token));
				return token;
			}

			var continuationChains = new Dictionary<int, List<ContinuationNode>>();
			var allContinuationNodes = new List<ContinuationNode>();
			int[] firstLaneCoverage = Enumerable.Range(0, laneCount).ToArray();
			firstLaneCoverage.Shuffle(r);
			for (int opcodeIndex = 0; opcodeIndex < virtuals.Count; opcodeIndex++)
			{
				int nodeCount = 3 + r.Next(3);
				if (opcodeIndex == 0)
					nodeCount = Math.Max(nodeCount, laneCount);
				var chain = new List<ContinuationNode>();
				int previousLane = -1;
				for (int depth = 0; depth < nodeCount; depth++)
				{
					int lane;
					if (opcodeIndex == 0 && depth < laneCount)
						lane = firstLaneCoverage[depth];
					else
					{
						do lane = r.Next(laneCount); while (lane == previousLane);
					}

					var node = new ContinuationNode
					{
						OpcodeIndex = opcodeIndex,
						Depth = depth,
						Lane = lane,
						Token = NewContinuationToken()
					};
					chain.Add(node);
					allContinuationNodes.Add(node);
					previousLane = lane;
				}

				for (int depth = 0; depth < chain.Count - 1; depth++)
				{
					chain[depth].NextToken = chain[depth + 1].Token;
					chain[depth].NextLane = chain[depth + 1].Lane;
				}
				string handler = BuildHandler(opcodeIndex);
				if (settings.Noise)
					handler += AntiDumpGenerator.GenerateHandlerNoise(guardRandom);
				chain[chain.Count - 1].Handler = handler;
				continuationChains[opcodeIndex] = chain;
			}

			string dispatchMaskName = T("DispatchMask");
			string dispatchSaltName = T("DispatchSalt");
			string dispatchStateName = T("DispatchState");
			string dispatchLaneName = T("DispatchLane");
			string dispatchActiveName = T("DispatchActive");
			string dispatchStepsName = T("DispatchSteps");
			string dispatchStepMaskName = T("DispatchStepMask");
			string dispatchMatchedName = T("DispatchMatched");
			string bitXorName = T("BitXOR");
			string u32Name = T("U32");
			string enumName = T("Enum");
			DispatcherTemplate dispatcherTemplate = DispatcherTemplateSelector.Select(dispatcherRandom);
			// State updates have three dependency-safe orders. This varies the def-use
			// shape even when two builds select the same outer dispatcher template.
			int transitionLayout = r.Next(3);

			string EncodedState(uint token, string mask) =>
				u32Name + "(" + bitXorName + "(" + ScrambleUInt(token) + "," + mask + "))";

			string EntryAssignment(int opcodeIndex)
			{
				ContinuationNode entry = continuationChains[opcodeIndex][0];
				string state = dispatchStateName + "=" + EncodedState(entry.Token, dispatchMaskName) + ";";
				string lane = dispatchLaneName + "=" + ScrambleNumber(entry.Lane) + ";";
				return transitionLayout == 1 ? lane + state : state + lane;
			}

			string BuildOpcodeSelector(List<int> opcodes)
			{
				if (opcodes.Count == 1)
					return EntryAssignment(opcodes[0]);
				if (opcodes.Count == 2)
				{
					int first = opcodes[0];
					int second = opcodes[1];
					string firstValue = ScrambleNumber(virtuals[first].VIndex);
					switch (r.Next(3))
					{
						case 0:
							return "if " + enumName + "==" + firstValue + " then " + EntryAssignment(first) + "else " + EntryAssignment(second) + "end;";
						case 1:
							return "if " + enumName + "~=" + firstValue + " then " + EntryAssignment(second) + "else " + EntryAssignment(first) + "end;";
						default:
							return "if " + enumName + ">" + firstValue + " then " + EntryAssignment(second) + "else " + EntryAssignment(first) + "end;";
					}
				}

				// Every threshold and leaf comparison is expressed in virtual-opcode
				// space. Sorting by the source list index would silently misroute a
				// randomized VIndex permutation.
				List<int> ordered = opcodes.OrderBy(opcode => virtuals[opcode].VIndex).ToList();
				int middle = ordered.Count / 2;
				List<int> left = ordered.Take(middle).ToList();
				List<int> right = ordered.Skip(middle).ToList();
				int threshold = virtuals[left.Last()].VIndex;
				return "if " + enumName + "<=" + ScrambleNumber(threshold) + " then " +
				       BuildOpcodeSelector(left) + "else " + BuildOpcodeSelector(right) + "end;";
			}

			string DecodedState() => settings.AntiDump
				? u32Name + "(" + bitXorName + "(" + bitXorName + "(" + dispatchStateName + "," + dispatchStepMaskName + ")," + T("GuardFaultWord") + "))"
				: u32Name + "(" + bitXorName + "(" + dispatchStateName + "," + dispatchStepMaskName + "))";

			string TokenCondition(ContinuationNode node)
			{
				string decoded = DecodedState();
				string token = ScrambleUInt(node.Token);
				switch (r.Next(3))
				{
					case 0: return decoded + "==" + token;
					case 1: return "not(" + decoded + "~=" + token + ")";
					default: return decoded + "<=" + token + " and " + decoded + ">=" + token;
				}
			}

			string Transition(ContinuationNode node)
			{
				string step = dispatchStepsName + "=" + dispatchStepsName + "+1;";
				string mask = dispatchStepMaskName + "=" + u32Name + "(" + bitXorName + "(" + dispatchMaskName + ",(" +
				              dispatchStepsName + "*" + dispatchSaltName + ")%4294967296));";
				string state = dispatchStateName + "=" + EncodedState(node.NextToken, dispatchStepMaskName) + ";";
				string lane = dispatchLaneName + "=" + ScrambleNumber(node.NextLane) + ";";
				return transitionLayout switch
				{
					0 => step + mask + state + lane,
					1 => lane + step + mask + state,
					_ => step + mask + lane + state
				};
			}

			string NodeBody(ContinuationNode node)
			{
				string body = dispatchMatchedName + "=true;";
				if (node.Terminal)
					return body + node.Handler + dispatchActiveName + "=false;";
				return body + Transition(node);
			}

			string NodeChain(IEnumerable<ContinuationNode> nodes, bool inlineLane)
			{
				var ordered = nodes.ToList();
				var result = new StringBuilder();
				for (int index = 0; index < ordered.Count; index++)
				{
					ContinuationNode node = ordered[index];
					string condition = TokenCondition(node);
					if (inlineLane)
						condition = dispatchLaneName + "==" + ScrambleNumber(node.Lane) + " and (" + condition + ")";
					result.Append(index == 0 ? "if " : "elseif ")
					      .Append(condition).Append(" then ").Append(NodeBody(node));
				}
				result.Append("end;");
				return result.ToString();
			}

			uint dispatchSaltFactor = (uint)(1 + r.Next(1, 32768) * 2);
			uint dispatchSaltAddend = unchecked((uint)r.NextInt64(1L, 4294967296L));
			vm += "local " + dispatchMaskName + "=" + u32Name + "(" + bitXorName + "(" + bitXorName + "(" + T("Flow") + "[3]," +
			      T("OpcodeKey") + "(" + T("InstrPoint") + "," + T("K1") + "," + T("K2") + "," + T("K3") + "))," +
			      T("BlockFieldKey") + "(" + T("Flow") + "[3]," + T("InstrPoint") + ",6," + T("K1") + "," + T("K2") + "," + T("K3") + ")));";
			vm += "local " + dispatchSaltName + "=(" + T("BlockFieldKey") + "(" + T("Flow") + "[3]," + T("InstrPoint") +
			      ",11," + T("K1") + "," + T("K2") + "," + T("K3") + ")*" + ScrambleUInt(dispatchSaltFactor) + "+" +
			      ScrambleUInt(dispatchSaltAddend) + ")%4294967296;";
			vm += "local " + dispatchStateName + "," + dispatchLaneName + "," + dispatchStepMaskName + ";" +
			      "local " + dispatchActiveName + "=true;local " + dispatchStepsName + "=0;local " + dispatchMatchedName + ";";
			vm += BuildOpcodeSelector(Enumerable.Range(0, virtuals.Count).ToList());

			int maximumDepth = continuationChains.Values.Max(chain => chain.Count - 1);
			string depthGuard = "if " + dispatchStepsName + ">" + ScrambleNumber(maximumDepth) + " then error('invalid protected payload',0);end;";
			string stepMask = dispatchStepMaskName + "=" + u32Name + "(" + bitXorName + "(" + dispatchMaskName + ",(" +
			                  dispatchStepsName + "*" + dispatchSaltName + ")%4294967296));";
			string loopPrefix;
			switch (transitionLayout)
			{
				case 0: loopPrefix = depthGuard + stepMask + dispatchMatchedName + "=false;"; break;
				case 1: loopPrefix = dispatchMatchedName + "=false;" + depthGuard + stepMask; break;
				default: loopPrefix = stepMask + depthGuard + dispatchMatchedName + "=false;"; break;
			}

			if (dispatcherTemplate == DispatcherTemplate.LanePartitioned)
			{
				// Template A: an outer continuation loop selects a lane first, then a
				// lane-local token chain. Lane and node orders are independently shuffled.
				vm += "while " + dispatchActiveName + " do " + loopPrefix;
				int[] laneOrder = Enumerable.Range(0, laneCount).ToArray();
				laneOrder.Shuffle(r);
				for (int laneOrderIndex = 0; laneOrderIndex < laneOrder.Length; laneOrderIndex++)
				{
					int lane = laneOrder[laneOrderIndex];
					vm += (laneOrderIndex == 0 ? "if " : "elseif ") + dispatchLaneName + "==" + ScrambleNumber(lane) + " then ";
					vm += NodeChain(allContinuationNodes.Where(node => node.Lane == lane).OrderBy(_ => r.Next()), false);
				}
				vm += "end;if not " + dispatchMatchedName + " then error('invalid protected payload',0);end;end;";
			}
			else if (dispatcherTemplate == DispatcherTemplate.TokenThreaded)
			{
				// Template B: token and lane checks share one flat threaded state chain.
				// A repeat terminator replaces the active-condition loop header.
				vm += "repeat " + loopPrefix;
				vm += NodeChain(allContinuationNodes.OrderBy(_ => r.Next()), true);
				vm += "if not " + dispatchMatchedName + " then error('invalid protected payload',0);end;until not " + dispatchActiveName + ";";
			}
			else
			{
				// Template C: continuation depth is the first state-machine layer; each
				// layer then selects a lane and finally a token. This is intentionally
				// distinct from both the lane-first and flat token-threaded CFGs.
				vm += "while " + dispatchActiveName + " do " + loopPrefix;
				int[] depthOrder = Enumerable.Range(0, maximumDepth + 1).ToArray();
				depthOrder.Shuffle(r);
				for (int depthOrderIndex = 0; depthOrderIndex < depthOrder.Length; depthOrderIndex++)
				{
					int depth = depthOrder[depthOrderIndex];
					vm += (depthOrderIndex == 0 ? "if " : "elseif ") + dispatchStepsName + "==" + ScrambleNumber(depth) + " then ";
					int[] depthLanes = allContinuationNodes.Where(node => node.Depth == depth).Select(node => node.Lane).Distinct().ToArray();
					depthLanes.Shuffle(r);
					for (int laneIndex = 0; laneIndex < depthLanes.Length; laneIndex++)
					{
						int lane = depthLanes[laneIndex];
						vm += (laneIndex == 0 ? "if " : "elseif ") + dispatchLaneName + "==" + ScrambleNumber(lane) + " then ";
						vm += NodeChain(allContinuationNodes.Where(node => node.Depth == depth && node.Lane == lane).OrderBy(_ => r.Next()), false);
					}
					vm += "end;";
				}
				vm += "end;if not " + dispatchMatchedName + " then error('invalid protected payload',0);end;end;";
			}
			string finalRuntime = settings.PreserveLineInfo ? (useRepeat ? VMStrings.VMP3_LI_R : VMStrings.VMP3_LI) : (useRepeat ? VMStrings.VMP3_R : VMStrings.VMP3);
			if (settings.AntiDump)
			{
				const string rootDeserialize = "local Root = Deserialize();";
				if (!finalRuntime.Contains(rootDeserialize))
					throw new InvalidOperationException("VM root deserialization anchor is missing.");
				finalRuntime = finalRuntime.Replace(rootDeserialize,
					rootDeserialize + "\nif GuardProbe(true) then Root, ByteString = nil, nil; return GuardDecoy(); end;");
			}
			vm += T(finalRuntime);
			vm = RewritePayloadRejects(vm);

			vm = vm.Replace("OP_ENUM", "1")
				.Replace("OP_A", "2")
				.Replace("OP_B", "3")
				.Replace("OP_C", "4");

			// Build-wide runtime ABI randomization. All table constructors above use
			// explicit keyed assignments, so these independent permutations cover every
			// Chunk/Block/Flow/cache access, including opcode handlers after T().
			int[] chunkSlots = GenerateRuntimeSlotPermutation(15);
			int[] blockSlots = GenerateRuntimeSlotPermutation(9);
			int[] flowSlots = GenerateRuntimeSlotPermutation(4);
			int[] flowCacheSlots = GenerateRuntimeSlotPermutation(3);
			vm = ApplyRuntimeSlotPermutation(vm, idents["Chunk"], chunkSlots);
			foreach (string blockAlias in new[] {"Block", "CurrentBlock", "NextBlock", "SuccessorBlock"})
				vm = ApplyRuntimeSlotPermutation(vm, idents[blockAlias], blockSlots);
			vm = ApplyRuntimeSlotPermutation(vm, idents["Flow"], flowSlots);
			vm = ApplyRuntimeSlotPermutation(vm, idents["FlowCache"], flowCacheSlots);

			// Apply the selected carrier topology only after the nested Flow ABI was
			// permuted, so accesses such as Frame[x][flowSlot] stay consistent with
			// helper functions that still receive Flow as a direct parameter.
			vm = ApplyVMLayout(vm, vmLayout);

			return vm;
		}
	}
}
