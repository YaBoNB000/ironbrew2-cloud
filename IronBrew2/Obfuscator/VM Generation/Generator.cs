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
using IronBrew2.Obfuscator.Control_Flow;
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

		private sealed class TableWriteOrderStats
		{
			public int Groups;
			public int Writes;
			public uint Signature = 2166136261u;
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

		private sealed class PayloadCarrierPlan
		{
			public string Prelude { get; init; }
			public string[] StageAssignments { get; init; }
			public string Assembly { get; init; }
			public int SegmentCount { get; init; }
			public int CarrierTopology { get; init; }
			public int AssemblyTopology { get; init; }
			public int[] StageCounts { get; init; }
		}

		internal static string[] SplitDataSegs(string data, Random r)
		{
			if (data == null) throw new ArgumentNullException(nameof(data));
			if (r == null) throw new ArgumentNullException(nameof(r));
			if (data.Length == 0) return new[] {string.Empty};

			// Production payloads use 7-14 deliberately uneven pieces. The small-input
			// fallback only lowers that range when there are not enough characters to
			// keep every segment non-empty.
			int maximum = Math.Min(14, data.Length);
			int minimum = Math.Min(7, maximum);
			int count = minimum == maximum ? minimum : r.Next(minimum, maximum + 1);
			var weights = Enumerable.Range(0, count).Select(_ => r.Next(37, 181)).ToArray();
			if (count > 1)
			{
				weights[0] = r.Next(37, 55);
				weights[1] = r.Next(165, 181);
				weights.Shuffle(r);
			}
			var segments = new List<string>(count);
			int position = 0;
			int weightLeft = weights.Sum();
			for (int index = 0; index < count; index++)
			{
				int slotsLeft = count - index - 1;
				int remaining = data.Length - position;
				int length = slotsLeft == 0
					? remaining
					: Math.Max(1, Math.Min(remaining - slotsLeft,
						(int)Math.Round((double)remaining * weights[index] / weightLeft)));
				segments.Add(data.Substring(position, length));
				position += length;
				weightLeft -= weights[index];
			}
			return segments.ToArray();
		}

		private static string PayloadName(Random random, HashSet<string> used)
		{
			string name;
			do name = "p" + random.Next(100000, 999999); while (!used.Add(name));
			return name;
		}

		private static int[] RandomSlots(int count, Random random, int scale = 4)
		{
			var slots = new HashSet<int>();
			while (slots.Count < count) slots.Add(random.Next(2, Math.Max(4, count * scale + 3)));
			int[] result = slots.ToArray();
			result.Shuffle(random);
			return result;
		}

		private static PayloadCarrierPlan BuildPayloadCarrierPlan(string data, Random random)
		{
			string[] segments = SplitDataSegs(data, random);
			int count = segments.Length;
			int carrierTopology = random.Next(4);
			int assemblyTopology = random.Next(4);
			var usedNames = new HashSet<string>();
			var prelude = new StringBuilder();
			var references = new string[count];
			var assignments = new string[count];

			if (carrierTopology == 0)
			{
				string carrier = PayloadName(random, usedNames);
				int[] slots = RandomSlots(count, random);
				prelude.Append("local ").Append(carrier).Append("={};\n");
				for (int index = 0; index < count; index++)
				{
					references[index] = carrier + "[" + slots[index] + "]";
					assignments[index] = references[index] + "='" + segments[index] + "';\n";
				}
			}
			else if (carrierTopology == 1)
			{
				string[] carriers = {PayloadName(random, usedNames), PayloadName(random, usedNames)};
				prelude.Append("local ").Append(carriers[0]).Append(",").Append(carriers[1]).Append("={},{};\n");
				int[] lanes = Enumerable.Range(0, count).Select(index => index % 2).ToArray();
				lanes.Shuffle(random);
				int[][] slots = {RandomSlots(lanes.Count(lane => lane == 0), random), RandomSlots(lanes.Count(lane => lane == 1), random)};
				int[] lanePositions = {0, 0};
				for (int index = 0; index < count; index++)
				{
					int lane = lanes[index];
					int slot = slots[lane][lanePositions[lane]++];
					references[index] = carriers[lane] + "[" + slot + "]";
					assignments[index] = references[index] + "='" + segments[index] + "';\n";
				}
			}
			else if (carrierTopology == 2)
			{
				string carrier = PayloadName(random, usedNames);
				int laneCount = 2 + random.Next(3);
				int[] laneKeys = RandomSlots(laneCount, random, 3);
				prelude.Append("local ").Append(carrier).Append("={");
				for (int lane = 0; lane < laneCount; lane++)
					prelude.Append("[").Append(laneKeys[lane]).Append("]={},");
				prelude.Append("};\n");
				int[] lanes = Enumerable.Range(0, count).Select(index => index % laneCount).ToArray();
				lanes.Shuffle(random);
				var laneSlots = Enumerable.Range(0, laneCount)
					.Select(lane => RandomSlots(lanes.Count(value => value == lane), random)).ToArray();
				var lanePositions = new int[laneCount];
				for (int index = 0; index < count; index++)
				{
					int lane = lanes[index];
					int slot = laneSlots[lane][lanePositions[lane]++];
					references[index] = carrier + "[" + laneKeys[lane] + "][" + slot + "]";
					assignments[index] = references[index] + "='" + segments[index] + "';\n";
				}
			}
			else
			{
				string carrier = PayloadName(random, usedNames);
				string writer = PayloadName(random, usedNames);
				int[] slots = RandomSlots(count, random);
				prelude.Append("local ").Append(carrier).Append("={};local ").Append(writer)
					.Append("=function(k,v)").Append(carrier).Append("[k]=v;end;\n");
				for (int index = 0; index < count; index++)
				{
					references[index] = carrier + "[" + slots[index] + "]";
					assignments[index] = writer + "(" + slots[index] + ",'" + segments[index] + "');\n";
				}
			}

			// Every guard stage receives a contiguous logical run, preserving a simple
			// source-order fallback for authenticated test rewriting while the physical
			// slots and runtime reads remain independently randomized.
			int[] stageCounts = Enumerable.Repeat(1, 5).ToArray();
			for (int remaining = count - stageCounts.Length; remaining > 0; remaining--)
				stageCounts[random.Next(stageCounts.Length)]++;
			var stageAssignments = Enumerable.Range(0, 5).Select(_ => new StringBuilder()).ToArray();
			int segmentIndex = 0;
			for (int stage = 0; stage < stageAssignments.Length; stage++)
				for (int item = 0; item < stageCounts[stage]; item++)
					stageAssignments[stage].Append(assignments[segmentIndex++]);

			string assembly;
			if (assemblyTopology == 0)
			{
				assembly = "local PayloadCiphertext,PayloadLength=decompress({" + string.Join(",", references) + "});\n";
			}
			else if (assemblyTopology == 2)
			{
				string Balanced(int start, int length)
				{
					if (length == 1) return references[start];
					int left = length / 2;
					return "{" + Balanced(start, left) + "," + Balanced(start + left, length - left) + "}";
				}
				assembly = "local PayloadCiphertext,PayloadLength=decompress(" + Balanced(0, count) + ");\n";
			}
			else
			{
				int[] slots = Enumerable.Range(1, count).ToArray();
				slots.Shuffle(random);
				int[] sourceOrder = Enumerable.Range(0, count).ToArray();
				sourceOrder.Shuffle(random);
				var staged = new StringBuilder("local PayloadCiphertext,PayloadLength;do local EncodedParts={};");
				foreach (int index in sourceOrder)
					staged.Append("EncodedParts[").Append(slots[index]).Append("]=").Append(references[index]).Append(";");
				string orderedReads = string.Join(",", Enumerable.Range(0, count).Select(index => "EncodedParts[" + slots[index] + "]"));
				if (assemblyTopology == 1)
					staged.Append("PayloadCiphertext,PayloadLength=decompress({").Append(orderedReads).Append("});end;\n");
				else
					staged.Append("local EncodedPage={").Append(orderedReads).Append("};")
						.Append("PayloadCiphertext,PayloadLength=decompress({EncodedPage});EncodedPage=nil;end;\n");
				assembly = staged.ToString();
			}

			return new PayloadCarrierPlan
			{
				Prelude = prelude.ToString(),
				StageAssignments = stageAssignments.Select(value => value.ToString()).ToArray(),
				Assembly = assembly,
				SegmentCount = count,
				CarrierTopology = carrierTopology,
				AssemblyTopology = assemblyTopology,
				StageCounts = stageCounts
			};
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

		private TableWriteOrderStats RandomizeFreshTableWrites(Chunk chunk, Random random)
		{
			var stats = new TableWriteOrderStats();
			for (int index = 0; index < chunk.Instructions.Count; index++)
			{
				Instruction create = chunk.Instructions[index];
				if (create.OpCode != Opcode.NewTable)
					continue;
				var writes = new List<Instruction>();
				var keys = new HashSet<Constant>();
				for (int cursor = index + 1; cursor < chunk.Instructions.Count; cursor++)
				{
					Instruction write = chunk.Instructions[cursor];
					if (write.OpCode != Opcode.SetTable || write.A != create.A || write.B <= 255
					    || write.RefOperands[0] is not Constant key || !keys.Add(key))
						break;
					if (write.BackReferences.Count != 0)
					{ writes.Clear(); break; }
					writes.Add(write);
				}
				if (writes.Count < 3)
					continue;
				foreach (Instruction write in writes) write.FreshTableWrite = true;
				Instruction[] shuffled = writes.ToArray();
				shuffled.Shuffle(random);
				if (shuffled.SequenceEqual(writes))
					(shuffled[0], shuffled[1]) = (shuffled[1], shuffled[0]);
				for (int offset = 0; offset < shuffled.Length; offset++)
				{
					chunk.Instructions[index + 1 + offset] = shuffled[offset];
					int original = writes.IndexOf(shuffled[offset]);
					stats.Signature = (stats.Signature ^ (uint)(original + 1 + offset * 17)) * 16777619u;
				}
				stats.Groups++;
				stats.Writes += writes.Count;
				index += writes.Count;
			}
			foreach (Chunk child in chunk.Functions)
			{
				TableWriteOrderStats childStats = RandomizeFreshTableWrites(child, random);
				stats.Groups += childStats.Groups;
				stats.Writes += childStats.Writes;
				stats.Signature = (stats.Signature ^ childStats.Signature) * 16777619u;
			}
			chunk.UpdateMappings();
			return stats;
		}

		private bool[] BuildSuperOperatorBarrierMap(Chunk chunk)
		{
			var barriers = new bool[chunk.Instructions.Count + 1];
			void Mark(int index)
			{
				if (index >= 0 && index < chunk.Instructions.Count)
					barriers[index] = true;
			}

			// Treat both semantic CFG entries and serializer-imposed bounded-block cuts
			// as hard fusion boundaries. Marking the preceding instruction still allows
			// a new fusion to begin at the destination block.
			ControlFlowGraph graph = ControlFlowGraph.Build(chunk, _context.MaxBlockInstructions);
			foreach (ControlFlowBlock block in graph.Blocks)
				if (block.Start > 0) Mark(block.Start - 1);

			for (int index = 0; index < chunk.Instructions.Count; index++)
			{
				Instruction instruction = chunk.Instructions[index];
				if (instruction.InstructionType == InstructionType.Data || instruction.FreshTableWrite)
					Mark(index);

				switch (instruction.OpCode)
				{
					case Opcode.Closure:
					case Opcode.Close:
						Mark(index);
						if (instruction.OpCode == Opcode.Closure && instruction.RefOperands.Length > 0 && instruction.RefOperands[0] is Chunk child)
							for (int binding = 1; binding <= child.UpvalueCount; binding++) Mark(index + binding);
						break;
					case Opcode.Eq:
					case Opcode.Lt:
					case Opcode.Le:
					case Opcode.Test:
					case Opcode.TestSet:
					case Opcode.TForLoop:
					case Opcode.SetList:
						Mark(index);
						Mark(index + 1);
						break;
					case Opcode.LoadBool when instruction.C != 0:
						Mark(index);
						Mark(index + 1);
						break;
					case Opcode.ForLoop:
					case Opcode.ForPrep:
					case Opcode.Jmp:
						instruction.UpdateRegisters();
						Mark(index);
						Mark(index + 1);
						Mark(index + instruction.B + 1);
						break;
					case Opcode.Call:
					case Opcode.PushStack:
					case Opcode.VarArg when instruction.B == 0:
					case Opcode.Return:
					case Opcode.TailCall:
						Mark(index);
						Mark(index + 1);
						break;
				}

				if (instruction.CustomData?.WrittenOpcode is OpSuperOperator existing && existing.SubOpcodes != null)
					for (int member = 0; member < existing.SubOpcodes.Length; member++) Mark(index + member);
			}
			return barriers;
		}

		public List<OpSuperOperator> GenerateSuperOperators(Chunk chunk, int maxSize, int minSize = 5)
		{
			List<OpSuperOperator> results = new List<OpSuperOperator>();

			bool[] skip = BuildSuperOperatorBarrierMap(chunk);

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
				results.AddRange(GenerateSuperOperators(_c, maxSize, minSize));
			
			return results;
		}

		public void FoldAdditionalSuperOperators(Chunk chunk, List<OpSuperOperator> operators, ref int folded)
		{
			bool[] skip = BuildSuperOperatorBarrierMap(chunk);

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
							chunk.Instructions[c + j].CustomData.FusionContinuation = j != 0;
						}

						chunk.Instructions[c].CustomData.WrittenOpcode = op;
						chunk.Instructions[c].CustomData.FusedInstructions = taken;

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
			Random payloadCarrierRandom = _context.Seed.GetStream("payload.carrier");
			VMLayout vmLayout = VMLayoutSelector.Select(layoutRandom);
			Console.WriteLine("Synthetic micro-block limit: " + _context.MaxBlockInstructions + ".");
			TableWriteOrderStats tableWriteOrder = RandomizeFreshTableWrites(_context.HeadChunk, r);
			Console.WriteLine("Fresh table write order: groups=" + tableWriteOrder.Groups
				+ "; writes=" + tableWriteOrder.Writes + "; signature=" + tableWriteOrder.Signature.ToString("x8") + ".");

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
				// IR-native fusions deliberately stay inside straight-line regions. The barrier
				// map excludes every control-flow edge, CLOSURE binding word and SETLIST
				// data word, while the small cap prevents giant recognizable handlers.
				int folded = 0;
				int operatorLimit = Math.Min(settings.MaxMiniSuperOperators, 24);
				var shortOperators = GenerateSuperOperators(_context.HeadChunk, 6, 2)
					.OrderBy(_ => r.Next()).Take(operatorLimit).ToList();
				var usedMemberTokens = new HashSet<uint>();
				uint memberTokenSignature = 2166136261u;
				int memberTokenCount = 0;
				foreach (OpSuperOperator superOperator in shortOperators)
				{
					superOperator.MemberTokens = new uint[superOperator.SubOpcodes.Length];
					for (int member = 0; member < superOperator.MemberTokens.Length; member++)
					{
						uint token;
						do token = unchecked((uint)r.NextInt64(1L, 4294967296L)); while (!usedMemberTokens.Add(token));
						superOperator.MemberTokens[member] = token;
						memberTokenSignature = (memberTokenSignature ^ token) * 16777619u;
						memberTokenCount++;
					}
					superOperator.MemberBranchOrder = Enumerable.Range(0, superOperator.SubOpcodes.Length).ToArray();
					superOperator.MemberBranchOrder.Shuffle(r);
					foreach (int branch in superOperator.MemberBranchOrder)
						memberTokenSignature = (memberTokenSignature ^ (uint)(branch + 1)) * 16777619u;
				}
				virtuals.AddRange(shortOperators);
				FoldAdditionalSuperOperators(_context.HeadChunk, shortOperators, ref folded);
				uint structureSignature = 2166136261u;
				foreach (OpSuperOperator superOperator in shortOperators)
				{
					structureSignature = (structureSignature ^ (uint)superOperator.SubOpcodes.Length) * 16777619u;
					foreach (VOpcode subOpcode in superOperator.SubOpcodes)
					{
						VOpcode semanticOpcode = subOpcode is OpMutated mutated ? mutated.Mutated : subOpcode;
						foreach (char character in semanticOpcode.GetType().Name)
							structureSignature = (structureSignature ^ character) * 16777619u;
					}
				}
				string lengthProfile = string.Join(",", shortOperators.GroupBy(op => op.SubOpcodes.Length)
					.OrderBy(group => group.Key).Select(group => group.Key + ":" + group.Count()));
				Console.WriteLine("Created " + shortOperators.Count + " IR-native super operators; folded " + folded
					+ " sequences; lengths " + lengthProfile + "; structure " + structureSignature.ToString("x8") + ".");
				Console.WriteLine("Fused member tokens: operators=" + shortOperators.Count + "; members=" + memberTokenCount
					+ "; signature=" + memberTokenSignature.ToString("x8") + ".");
			}

			// Four synthetic replay leaves back the invocation-local instruction overlay.
			// They are never assigned to serialized source instructions; GetInstruction
			// selects one from prototype keys after materializing the real instruction.
			var materializerOpcodes = Enumerable.Range(0, 4)
				.Select(mode => new OpMaterialize {Mode = mode})
				.ToArray();
			virtuals.AddRange(materializerOpcodes);

			AddOpcodeAliases(virtuals, r);
			Console.WriteLine("Added " + _context.VirtualOpcodeAliasCount + " build-local opcode aliases and "
				+ materializerOpcodes.Length + " prototype-selectable materializer modes.");
			virtuals.Shuffle(r);
			
			for (int i = 0; i < virtuals.Count; i++)
				virtuals[i].VIndex = i;

			_context.VirtualOpcodeCount = virtuals.Count;

			string vm = "";

			// ==== P1: 模板标识符随机化(每次混淆生成不同的 VM 结构名)====
			string[] identKeys = {
				"ByteString","InstrPoint","InternalError","GetFEnv","Setmetatable","Getmetatable","RawGet","RawSet","RawEqual","Next","ToNumber","ToString","ConstCount","Deserialize",
				"DisabledGlobalFunction","DisabledGlobalEnvironment","DisabledEnvironmentOK","DisabledEnvironmentCandidate","DisabledEnvironmentRead","DisabledEnvironmentValue","DisabledIndexedOK","DisabledIndexedValue","DisabledGlobalTargets","DisableGlobalTarget","DisabledGlobalIndex","DisabledGlobalCandidate","DisabledPrintKey","DisabledErrorKey","DisabledWarnKey","DisabledGetGenVKey","DisabledRootKey","DisabledGetGenV","DisabledGetGenVOK",
				"PayloadParts","ConsumePayloadPart","PayloadChunks","PayloadLength","EmitPayloadByte","PayloadByteAt","PayloadChunk","PayloadChunkIndex","PayloadChunkOffset",
				"Wrap","Upvalues","NewProto","NewPrototypeRecord","Layout","Storage","Proxy","Key","Slot","Indexes","Concat","Insert","LDExp","Select","Unpack",
				"BitXOR","gBits32","gBits8","gBits16","gFloat","gSizet","gString","gInt","Byte","Char","Sub",
				"gBit","Instrs","Functions","Lines","Consts","ConstCapsules","Capsule","Instr","Proto","Params","Top","Vararg","Args",
				"PCount","Lupvals","Stk","Inst","Enum","Chunk","decompress","Pos","Xs","Xd","_R","Env",
				"Varargsz","PCall","Loop","Const","RA","RB","K1","K2","K3","OpcodeKey","FieldKey","FieldKey32","U32","U32Mul","Xi",
				"OuterIntegrityText","OuterIntegrityState","OuterIntegrityIndex",
				"DerivePermutation","DeriveBlockPermutation","DeriveCodeDataPermutation","Count","Domain","Values","State","Identity","Schema","StepIndex","Step","ConstTags","InstrCount","OpcodeBank","InstructionCount","ConstantCount","StateValue","SawData","Interleaved",
				"Columns","ColumnOrder","ColumnPositions","ColumnRead8","ColumnRead16","ColumnRead32","ColumnData","ColumnPosition","PhysicalSlot","Role",
				"PrototypeDecoderMode","DecodePrototypeColumn","DecoderMode","Output","Shift","Divisor",
				"Body","BodyPosition","FragmentCount","FragmentOrder","FragmentSpans","LogicalSlot","MinimumLength","ReadFragment","TargetSlot","Record","ReferenceSlots","HeaderWords","HeaderIndex",
				"ComputePrototypeIntegrity","PrototypeLength","PrototypeTag","ComputeConstantIntegrity","ConstantMaskState","BeginConstantChain","AdvanceConstantChain","ConstantChainState","StringShardState","DecodeConstantCapsule","StoredTag","EncodedBody","RawParts","Raw","Cons","StringParts","ShardCount","ShardOrder","ShardIndex","ShardOffset","ShardLength","ShardPosition","ShardByte","ExpectedShardLength","PreviousReference","Reference","ResolvedConstants","ResolvedConstantFlags",
				"GetProto","Index","Encoded","Decoded","SavedByteString","SavedPos","Length","Root","Blocks","BlockMap",
				"BlockCount","BlockIndex","BlockStart","Block","RefCount","References","ReferenceIndex","Offset","ConstCache",
				"Descriptor","Type","Mask","DecodeInstructionBlock","GetInstruction","InitialFlowKey","FlowKey","FlowVerifier","CurrentChunkState",
				"InstructionDigest","BeginInstructionState","AdvanceInstructionState","InstructionStateSeal","PreviousInstructionState","CurrentInstructionState","CurrentInstructionSeal","Digest",
				"BeginOpcodeState","AdvanceOpcodeState","OpcodeStateKey","OpcodeStateSeal","PreviousOpcodeState","CurrentOpcodeState","CurrentOpcodeSeal",
				"BlockFieldKey","BlockFieldKey32","ComputeBlockIntegrity","Flow","EntryState","FromPC","ToPC","Value","Low","High","Hash",
				"Verifier","BlockTag","SuccessorCount","Successors","SuccessorRecords","SuccessorRecord","SuccessorBlock","PreviousSuccessor","SuccessorIndex","SuccessorStart","WrappedState","LastIndex","CurrentBlock",
				"Dispatcher","RouteCount","InitialRouteToken","RouteToken","ResolveInstructionPoint","NextInstructionPoint","Routed","NextBlock",
				"DispatchMask","DispatchSalt","DispatchState","DispatchLane","DispatchActive","DispatchSteps","DispatchStepMask","DispatchMatched","HandlerReadStack","HandlerReadEnvironment","HandlerWriteStack","HandlerTableWrite","HandlerTableAcquireKey","HandlerTableAcquireValue","HandlerTableCommit","HandlerTableCommitA","HandlerTableCommitB","HandlerTableCommitC","HandlerTableCommitD","HandlerTableCommitMode","HandlerTableSlot","HandlerTableResult","HandlerTableFresh","HandlerTableDecoyKey","HandlerTableDecoyValue","HandlerTableTarget","HandlerTableKey","HandlerTableValue","HandlerTableMode","HandlerBinary","HandlerUnary","HandlerPc","HandlerFragmentIndex","HandlerFragmentValue","HandlerFragmentMode","HandlerFragmentLeft","HandlerFragmentRight","HandlerFragmentCurrent","HandlerFragmentTarget",
				"GuardString","GuardTable","GuardMath","GuardDebug","GuardGetInfo","GuardInfo","GuardInspector",
				"GuardUnpack","GuardTableUnpack","GuardGetFEnvGlobal","GuardEnvOK","GuardEnvironment","GuardEnvironmentRead","GuardGetGenV",
				"GuardReadEnvironment","GuardReadKey","GuardReadValue","GuardReadOK","GuardIndexedValue","GuardCapOK","GuardCapEnv","GuardCapabilityEnvironment","GuardIsC","GuardIsL","GuardCounter","GuardNextProbe",
				"GuardEpoch","GuardState","GuardSeal","GuardSealA","GuardSealB","GuardSealC","GuardTripped","GuardFaultWord","GuardLuaProbe","GuardProbeValue","GuardFunction",
				"GuardKeyBytes","GuardKeyMeta","GuardKeyCache","GuardKey","GuardKeyRecord","GuardKeyParts","GuardKeyIndex",
				"GuardPayloadState","GuardPayloadSeal","GuardPayloadActive","GuardPayloadExpectedSeal","GuardBindPayload","GuardPayloadLow","GuardPayloadHigh",
				"GuardVMState","GuardChunkState","GuardEntryState","GuardInstructionPoint","GuardVMLow","GuardVMHigh","GuardChunkLow","GuardChunkHigh","GuardEntryLow","GuardEntryHigh","GuardOpcodeState","GuardOpcodeSeal","GuardOpcodeLow","GuardOpcodeHigh",
				"GuardProbe","GuardValidateCallTarget","GuardDynamicCalls","GuardDynamicChallenge","GuardDynamicSource","GuardDynamicCompileOK","GuardDynamicLoaded","GuardDynamicRunOK","GuardDynamicResult","GuardDynamicConstantsOK","GuardDynamicConstants","GuardCurrentLoader","Force","GuardScore","GuardHeavy",
				"GuardCurrentIsC","GuardCurrentIsL","GuardNativeMisses","GuardOK1","GuardOK2","GuardOK3","GuardOK4",
				"GuardC1","GuardC2","GuardC3","GuardC4","GuardL1","GuardL2","GuardL3","GuardLuaOK","GuardLuaIsC","GuardLuaIsL",
				"GuardKnown","GuardNative","GuardBehaviorOK","GuardBehaviorResult","GuardBehaviorTable","GuardBehaviorMeta",
				"GuardBehaviorKey","GuardFirstKey","GuardDecoy","GuardValue","GuardIndex","DecodedInstrs","FlowCache","IsSequential",
				"AllowMaterializer","MaterializeIndexSlot","MaterializeOpcodeSlot","MaterializeASlot","MaterializeBSlot","MaterializeCSlot","MaterializeStageSlot","MaterializeConstantFieldsSlot","MaterializeConstantResolverSlot","MaterializeFusedSlot","MaterializeFreshTableSlot","MaterializeStage","MaterializeMode","MaterializeEnum","SelectMaterializerEnum","MaterializeTarget","MaterializeDelta","MaterializedInstruction","MaterializedFields","MaterializedConstantFields","MaterializedConstantResolver",
				"BindInstructionOperands","InstructionFields","InstructionConstantFields","InstructionConstantResolver","InstructionDecodedFields","InstructionDecodedValues","InstructionRemainingConstants","InstructionFieldKey","InstructionConstantIndex","FusedOperands","FusedHead","FusedProgramCounter","FusedProgramStep","FusedValues","FusedWritten","FusedStack","FusedKey","FusedValue","FusedInstructionFields","FusedConstantFields","FusedInstruction","FusedDescriptor","FusedCount","FusedIndex","FusedType","FusedMask","FusedInstructionConstants","IsFused","IsFreshTableWrite",
				"GuardEvidenceFold","GuardEvidenceA","GuardEvidenceB","GuardEvidenceC","GuardEvidenceD","GuardCompatibility","GuardAttested","GuardKeyA","GuardKeyB","GuardKeyC","GuardKeyD","GuardPayloadBinding","BinderRotate16","SeedByte","GuardBXor","GuardCBody","GuardCValue","GuardCaller","GuardCallerOK","GuardChangedOK","GuardCheckCaller",
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
				"GuardPersistent","GuardProtoConstants","GuardProtoConstantsOK","GuardProtosValid","GuardReject","GuardRejectA","GuardRejectB","GuardRejectC","GuardRejectD","GuardRepeatEnvironment","GuardRepeatOK","GuardReportOnly","GuardSawInactiveProto","GuardSeparated",
				"GuardThreadMarker","GuardThreadOld","GuardCanaryOK","GuardCapabilityRestoreOK","GuardThreadRestoreOK","GuardWrappedUpvalues","GuardWrappedUpvaluesOK",
				"GuardPrimitiveIndex","GuardPrimitives",
				"PrimitiveEnvironmentReader","PrimitiveEnvironment","PrimitiveEnvironmentLookup","PrimitiveMemberLookup","PrimitiveValue","PrimitiveRawGet","PrimitiveString","PrimitiveTable","PrimitiveMath","PrimitiveDebug","PrimitiveGlobalUnpack","PrimitiveTableUnpack","PrimitiveBootstrapChar",
				"PrimitiveKeyBytes","PrimitiveKeyMeta","PrimitiveKeyCache","PrimitiveDecode","PrimitiveToken","PrimitiveRecord","PrimitiveText","PrimitiveIndex","PrimitiveLookup","PrimitiveRoot","PrimitiveMember","PrimitiveParent",
				"PayloadRejectA","PayloadRejectB","PayloadRejectC","PayloadRejectD",
				"PayloadRejectVoidA","PayloadRejectVoidB","PayloadRejectVoidC","PayloadRejectVoidD",
				"PayloadRejectCodeA","PayloadRejectCodeB","PayloadRejectCodeC","PayloadRejectCodeD",
				"PayloadHead","PayloadTag","PayloadFlags","PayloadFeatures","PayloadVersion","OuterSeed","PayloadHash","PayloadIndex","PayloadDecoded","PayloadByte","PayloadKey",
				"PayloadRotate16","PayloadLow","PayloadAuthA","PayloadAuthB","PayloadMix",
				"EnvelopePos","EnvelopeRead32","EnvelopeRealLength","EnvelopeEntropyLength","EnvelopeRecordCount","EnvelopeDataCount","EnvelopeEntropyCount","EnvelopeNonce","EnvelopeDigest","EnvelopeTag","EnvelopeExpected",
				"EnvelopeHash","EnvelopeIndex","EnvelopeDataRecords","EnvelopeEntropyRecords","EnvelopeDataLength","EnvelopeEntropySeenLength","EnvelopeKind","EnvelopeOrdinal","EnvelopeLength","EnvelopeRecord",
				"EntropyHash","EnvelopeByteIndex","EnvelopeState","EnvelopeBody","EnvelopeBodyIndex","EnvelopeKey",
				"PayloadCiphertext","PayloadAttestation","EnvelopeCipherPos","EnvelopeCipherState","EnvelopePlainPos","EnvelopeRead8","PayloadPageDescriptors","EntropyDescriptors",
				"DescriptorState","DescriptorOffset","EnvelopeMaskState","PayloadSourceLength","PageOrdinal","PayloadPageOrdinal","PayloadPage","PayloadPagePosition","LoadPayloadPage",
				"SourceRead8","SourceReadBytes","ActiveSourceLength","SourceIsPaged","ActivePrototypeHash","ActivePrototypeRight","ActivePrototypeCounter","PrototypeAbsorb","FinalizePrototypeIntegrity","TrackPrototypeByte","FramedLength","EncodedParts","EncodedPage",
				"PageByteIndex","FramingIndex","MaskState","InnerKey","OuterKey","NestedByte","PlainByte","RawLength","Multiplier","SavedSourceLength","SavedSourceMode",
				"CipherByte","KeyByte","EnvelopeReadWidth","Width","FieldIndex","LengthOffset","EncodedIndex","Left","Right","Counter","Word","Mixed","Absorb","PipelineState","PipelineIndex","TransformedByte","EncodedPartIndex",
				"ChunkState","InitialChunkKey","ChunkChainKey","SourceChunkState","SourceEntryState","CurrentChunkState","WrappedChunkState","ChunkSuccessors",
				"TargetIndex","TargetInstruction","ReferencedConstants","ResolveConstant","ReferenceSlot","PreviousCapsule","BeginPrototypeIntegrity","Words","WordIndex","Word",
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
				PayloadDerivationProfile derivation = _context.PayloadDerivation;
				PayloadFormatLayout format = _context.PayloadFormat;
				string EnvelopeTarget(EnvelopeHeaderField field) => field switch
				{
					EnvelopeHeaderField.FramedLength => "EnvelopeRealLength",
					EnvelopeHeaderField.EntropyLength => "EnvelopeEntropyLength",
					EnvelopeHeaderField.RecordCount => "EnvelopeRecordCount",
					EnvelopeHeaderField.DataCount => "EnvelopeDataCount",
					EnvelopeHeaderField.EntropyCount => "EnvelopeEntropyCount",
					EnvelopeHeaderField.Nonce => "EnvelopeNonce",
					EnvelopeHeaderField.EntropyDigest => "EnvelopeDigest",
					EnvelopeHeaderField.Integrity => "EnvelopeTag",
					_ => throw new InvalidOperationException("Unknown envelope header field.")
				};
				string RecordRead(EnvelopeRecordField field) => field switch
				{
					EnvelopeRecordField.Kind => "EnvelopeKind = EnvelopeRead8();",
					EnvelopeRecordField.Ordinal => $"EnvelopeOrdinal = EnvelopeReadWidth({format.RecordOrdinalWidth});",
					EnvelopeRecordField.Length => $"EnvelopeLength = EnvelopeReadWidth({format.RecordLengthWidth});",
					_ => throw new InvalidOperationException("Unknown envelope record field.")
				};
				var replacements = new Dictionary<string, string>
				{
					["__IB2_DOMAIN_INTEGRITY__"] = domains.IntegrityDomain.ToString(),
					["__IB2_DOMAIN_BLOCK_INTEGRITY__"] = domains.BlockIntegrityDomain.ToString(),
					["__IB2_DOMAIN_FLOW__"] = domains.FlowDomain.ToString(),
					["__IB2_DOMAIN_CHUNK_STATE__"] = domains.ChunkStateDomain.ToString(),
					["__IB2_DOMAIN_INSTRUCTION_STATE__"] = domains.InstructionStateDomain.ToString(),
					["__IB2_DOMAIN_OPCODE_STATE__"] = domains.OpcodeStateDomain.ToString(),
					["__IB2_DOMAIN_PAYLOAD_FORMAT__"] = domains.PayloadFormatDomain.ToString(),
					["__IB2_DOMAIN_DECODE_PIPELINE__"] = domains.DecodePipelineDomain.ToString(),
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
					["__IB2_DOMAIN_CODE_DATA_PERMUTATION__"] = domains.CodeDataPermutationDomain.ToString(),
					["__IB2_BLOCK_FIELD_STRIDE__"] = domains.BlockFieldStride.ToString(),
					["__IB2_FLOW_VERIFIER_MASK__"] = domains.FlowVerifierMask.ToString(),
					["__IB2_ENTROPY_RECORD_KIND__"] = domains.EntropyRecordKind.ToString(),
					["__IB2_DATA_RECORD_KIND__"] = domains.DataRecordKind.ToString(),
					["__IB2_OUTER_HEAD_OFFSET__"] = (format.OuterHeadOffset + 1).ToString(),
					["__IB2_OUTER_TAG_OFFSET__"] = (format.OuterIntegrityOffset + 1).ToString(),
					["__IB2_OUTER_FLAGS_OFFSET__"] = (format.OuterFlagsOffset + 1).ToString(),
					["__IB2_ENVELOPE_INTEGRITY_START__"] = (format.EnvelopeIntegrityOffset + 1).ToString(),
					["__IB2_ENVELOPE_INTEGRITY_END__"] = (format.EnvelopeIntegrityOffset + 4).ToString(),
					["__IB2_ENVELOPE_HEADER_READS__"] = string.Join("\n", format.EnvelopeHeaderOrder.Select(field => EnvelopeTarget(field) + " = EnvelopeRead32();")),
					["__IB2_RECORD_HEADER_WIDTH__"] = format.RecordHeaderWidth.ToString(),
					["__IB2_RECORD_FIELD_READS__"] = string.Join("\n    ", format.EnvelopeRecordOrder.Select(RecordRead)),
					["__IB2_PAGE_MIN_FRAME__"] = (format.PageLengthWidth + 1).ToString(),
					["__IB2_PAGE_LENGTH_WIDTH__"] = format.PageLengthWidth.ToString(),
					["__IB2_PAGE_LENGTH_OFFSET__"] = format.PageLengthSuffix ? $"Descriptor[2] - {format.PageLengthWidth}" : "0",
					["__IB2_PAGE_PIPELINE__"] = format.PipelineVariant.ToString(),
					["__IB2_PAGE_BYTE_TRANSFORM__"] = format.ByteTransformVariant.ToString(),
					["__IB2_PAGE_BYTE_PARAMETER__"] = format.ByteTransformParameter.ToString(),
					["__IB2_STREAM_MULTIPLIER__"] = derivation.StreamMultiplier.ToString(),
					["__IB2_STREAM_INCREMENT__"] = derivation.StreamIncrement.ToString()
				};
				foreach (KeyValuePair<string, string> replacement in replacements)
					code = code.Replace(replacement.Key, replacement.Value);
				if (Regex.IsMatch(code, @"__IB2_(?:DOMAIN|BLOCK_FIELD|FLOW_VERIFIER|ENTROPY_RECORD|DATA_RECORD|OUTER_|ENVELOPE_|RECORD_|PAGE_|STREAM_)"))
					throw new InvalidOperationException("A per-build runtime layout or domain placeholder was not replaced.");
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
			int[] semanticWriteVariants = new int[6];
			int semanticRawStackReads = 0;
			int semanticRawEnvironmentReads = 0;
			string ApplySemanticPolymorphism(string code)
			{
				const string target = @"Stk\s*\[\s*Inst\s*\[\s*OP_A\s*\]\s*\]";
				string pattern = @"(?<target>" + target + @")\s*=(?!=)\s*(?<value>[^;]+);";
				code = Regex.Replace(code, pattern, match =>
				{
					int variant = r.Next(6);
					semanticWriteVariants[variant]++;
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
					if (variant == 3)
						return "local " + result + "=" + value + ";local " + destination + "=Inst[OP_A];Stk[" + destination + "]=" + result + ";";
					if (variant == 4)
						return "RawSet(Stk,Inst[OP_A]," + value + ");";
					return "local " + result + "=" + value + ";RawSet(Stk,Inst[OP_A]," + result + ");";
				});

				// Replace common register/global reads with captured raw accessors. Direct
				// assignment targets are retained; every other occurrence independently
				// chooses table syntax or a function-call dataflow.
				const string stackRead = @"Stk\s*\[\s*Inst\s*\[\s*OP_[ABC]\s*\]\s*\]";
				code = Regex.Replace(code, stackRead, match =>
				{
					int cursor = match.Index + match.Length;
					while (cursor < code.Length && char.IsWhiteSpace(code[cursor])) cursor++;
					if (cursor < code.Length && code[cursor] == '=' &&
					    (cursor + 1 >= code.Length || code[cursor + 1] != '='))
						return match.Value;
					Match operand = Regex.Match(match.Value, @"OP_[ABC]");
					if (r.Next(2) == 0 || !operand.Success)
						return match.Value;
					semanticRawStackReads++;
					return "RawGet(Stk,Inst[" + operand.Value + "])";
				});
				code = Regex.Replace(code,
					@"Env\s*\[\s*Inst\s*\[\s*OP_B\s*\]\s*\]",
					match =>
					{
						int cursor = match.Index + match.Length;
						while (cursor < code.Length && char.IsWhiteSpace(code[cursor])) cursor++;
						if (cursor < code.Length && code[cursor] == '=' &&
						    (cursor + 1 >= code.Length || code[cursor + 1] != '='))
							return match.Value;
						if (r.Next(2) == 0) return "Env[Inst[OP_B]]";
						semanticRawEnvironmentReads++;
						return "RawGet(Env,Inst[OP_B])";
					});
				return code;
			}

			// Handler fragment sharing: common operand acquisition, arithmetic,
			// destination writeback and PC transitions are emitted once per dispatch
			// scope. Terminal leaves retain only a composition of these fragments,
			// rather than repeating one complete semantic dataflow per virtual opcode.
			string[] binaryOperators = {"+", "-", "*", "/", "%", "^", ".."};
			string[] unaryOperators = {"-", "not", "#"};
			var usedFragmentTokens = new HashSet<uint>();
			uint NewFragmentToken()
			{
				uint token;
				do token = unchecked((uint)r.NextInt64(1L, 4294967296L));
				while (!usedFragmentTokens.Add(token));
				return token;
			}
			var binaryFragmentTokens = binaryOperators.ToDictionary(op => op, _ => NewFragmentToken());
			var unaryFragmentTokens = unaryOperators.ToDictionary(op => op, _ => NewFragmentToken());
			_context.TableWriteTokens = Enumerable.Range(0, 4).Select(_ => NewFragmentToken()).ToArray();
			_context.TableCommitTokens = Enumerable.Range(0, 4).Select(_ => NewFragmentToken()).ToArray();
			uint[] tableCommitRoute = _context.TableCommitTokens.OrderBy(_ => r.Next()).ToArray();
			bool[] tableWriteValueFirst = Enumerable.Range(0, 4).Select(_ => r.Next(2) == 0).ToArray();
			int handlerFragmentReadCalls = 0;
			int handlerFragmentEnvironmentCalls = 0;
			int handlerFragmentWriteCalls = 0;
			int handlerFragmentBinaryCalls = 0;
			int handlerFragmentUnaryCalls = 0;
			int handlerFragmentPcCalls = 0;

			string ApplyHandlerFragmentSharing(string code)
			{
				const string instructionField = @"Inst\s*\[\s*OP_[ABC]\s*\]";
				string stackOperand = @"Stk\s*\[\s*" + instructionField + @"\s*\]";
				string scalarOperand = "(?:" + stackOperand + "|" + instructionField + ")";

				// Joint operation fragments are selected by build-random 32-bit tokens.
				// Operand acquisition is fragmented separately in a later pass.
				string binaryPattern = @"(?<left>" + scalarOperand + @")\s*(?<operator>\.\.|[+\-*/%^])\s*(?<right>" + scalarOperand + ")";
				code = Regex.Replace(code, binaryPattern, match =>
				{
					string op = match.Groups["operator"].Value;
					if (!binaryFragmentTokens.TryGetValue(op, out uint token))
						return match.Value;
					handlerFragmentBinaryCalls++;
					return "HandlerBinary(" + ScrambleUInt(token) + "," +
					       match.Groups["left"].Value + "," + match.Groups["right"].Value + ")";
				});
				string unaryPattern = @"(?<operator>not\s+|[-#])(?<value>" + scalarOperand + ")";
				code = Regex.Replace(code, unaryPattern, match =>
				{
					string op = match.Groups["operator"].Value.Trim();
					if (op == "-")
					{
						int previous = match.Index - 1;
						while (previous >= 0 && char.IsWhiteSpace(code[previous])) previous--;
						if (previous >= 0 && (char.IsLetterOrDigit(code[previous]) ||
						    code[previous] == '_' || code[previous] == ']' || code[previous] == ')'))
							return match.Value;
					}
					if (!unaryFragmentTokens.TryGetValue(op, out uint token))
						return match.Value;
					handlerFragmentUnaryCalls++;
					return "HandlerUnary(" + ScrambleUInt(token) + "," + match.Groups["value"].Value + ")";
				});

				string simpleIndex = "(?:" + instructionField + @"|[A-Za-z_]\w*(?:\s*[+\-]\s*\d+)?)";
				// Restrict regex-based writeback extraction to scalar values. Complex
				// expressions may contain nested function/table bodies with semicolons;
				// result-temporary lowering still routes those through this shared sink.
				string directWriteValue = @"(?:[A-Za-z_]\w*|" + instructionField + @")";
				string directWrite = @"Stk\s*\[\s*(?<index>" + simpleIndex + @")\s*\]\s*=(?!=)\s*(?<value>" + directWriteValue + @")\s*;";
				code = Regex.Replace(code, directWrite, match =>
				{
					handlerFragmentWriteCalls++;
					return "HandlerWriteStack(" + match.Groups["index"].Value + "," +
					       match.Groups["value"].Value.Trim() + "," + ScrambleNumber(r.Next(2)) + ");";
				});
				// Only rewrite RawSet forms whose value is already a scalar temporary or
				// instruction field. A regex must not consume nested call parentheses;
				// complex direct RawSet forms remain valid and still share read fragments.
				string rawWriteValue = @"(?:[A-Za-z_]\w*|" + instructionField + @")";
				string rawWrite = @"RawSet\s*\(\s*Stk\s*,\s*(?<index>" + simpleIndex + @")\s*,\s*(?<value>" + rawWriteValue + @")\s*\)\s*;";
				code = Regex.Replace(code, rawWrite, match =>
				{
					handlerFragmentWriteCalls++;
					return "HandlerWriteStack(" + match.Groups["index"].Value + "," +
					       match.Groups["value"].Value.Trim() + "," + ScrambleNumber(r.Next(2)) + ");";
				});

				string stackRead = @"Stk\s*\[\s*(?<index>" + simpleIndex + @")\s*\]";
				code = Regex.Replace(code, stackRead, match =>
				{
					int cursor = match.Index + match.Length;
					while (cursor < code.Length && char.IsWhiteSpace(code[cursor])) cursor++;
					if (cursor < code.Length && code[cursor] == '=' &&
					    (cursor + 1 >= code.Length || code[cursor + 1] != '='))
						return match.Value;
					handlerFragmentReadCalls++;
					return "HandlerReadStack(" + match.Groups["index"].Value + "," + ScrambleNumber(r.Next(2)) + ")";
				});
				string rawStackRead = @"RawGet\s*\(\s*Stk\s*,\s*(?<index>" + simpleIndex + @")\s*\)";
				code = Regex.Replace(code, rawStackRead, match =>
				{
					handlerFragmentReadCalls++;
					return "HandlerReadStack(" + match.Groups["index"].Value + "," + ScrambleNumber(r.Next(2)) + ")";
				});

				string environmentRead = @"Env\s*\[\s*(?<index>" + simpleIndex + @")\s*\]";
				code = Regex.Replace(code, environmentRead, match =>
				{
					int cursor = match.Index + match.Length;
					while (cursor < code.Length && char.IsWhiteSpace(code[cursor])) cursor++;
					if (cursor < code.Length && code[cursor] == '=' &&
					    (cursor + 1 >= code.Length || code[cursor + 1] != '='))
						return match.Value;
					handlerFragmentEnvironmentCalls++;
					return "HandlerReadEnvironment(" + match.Groups["index"].Value + "," + ScrambleNumber(r.Next(2)) + ")";
				});
				string rawEnvironmentRead = @"RawGet\s*\(\s*Env\s*,\s*(?<index>" + simpleIndex + @")\s*\)";
				code = Regex.Replace(code, rawEnvironmentRead, match =>
				{
					handlerFragmentEnvironmentCalls++;
					return "HandlerReadEnvironment(" + match.Groups["index"].Value + "," + ScrambleNumber(r.Next(2)) + ")";
				});

				code = Regex.Replace(code, @"InstrPoint\s*=\s*InstrPoint\s*\+\s*(\d+)\s*;", match =>
				{
					handlerFragmentPcCalls++;
					return "InstrPoint=HandlerPc(InstrPoint," + match.Groups[1].Value + "," + ScrambleNumber(2) + ");";
				});
				code = Regex.Replace(code, @"InstrPoint\s*=\s*InstrPoint\s*-\s*(\d+)\s*;", match =>
				{
					handlerFragmentPcCalls++;
					return "InstrPoint=HandlerPc(InstrPoint,-" + match.Groups[1].Value + "," + ScrambleNumber(2) + ");";
				});
				code = Regex.Replace(code, @"InstrPoint\s*=\s*Inst\s*\[\s*OP_B\s*\]\s*;", _ =>
				{
					handlerFragmentPcCalls++;
					return "InstrPoint=HandlerPc(InstrPoint,Inst[OP_B]," + ScrambleNumber(1) + ");";
				});
				return code;
			}

			string BuildHandlerFragmentRuntime()
			{
				var fragment = new StringBuilder();
				fragment.Append("local function HandlerReadStack(HandlerFragmentIndex,HandlerFragmentMode)")
				        .Append("if HandlerFragmentMode==").Append(ScrambleNumber(0))
				        .Append(" then return Stk[HandlerFragmentIndex];end;return RawGet(Stk,HandlerFragmentIndex);end;");
				fragment.Append("local function HandlerReadEnvironment(HandlerFragmentIndex,HandlerFragmentMode)")
				        .Append("if HandlerFragmentMode==").Append(ScrambleNumber(0))
				        .Append(" then return Env[HandlerFragmentIndex];end;local HandlerFragmentValue=RawGet(Env,HandlerFragmentIndex);")
				        .Append("if HandlerFragmentValue~=nil then return HandlerFragmentValue;end;return Env[HandlerFragmentIndex];end;");
				fragment.Append("local function HandlerWriteStack(HandlerFragmentIndex,HandlerFragmentValue,HandlerFragmentMode)")
				        .Append("if HandlerFragmentMode==").Append(ScrambleNumber(0))
				        .Append(" then Stk[HandlerFragmentIndex]=HandlerFragmentValue;else RawSet(Stk,HandlerFragmentIndex,HandlerFragmentValue);end;")
				        .Append("return HandlerFragmentValue;end;");

				fragment.Append("local function HandlerTableAcquireKey(HandlerTableMode,InstructionFields)")
				        .Append("if HandlerTableMode==").Append(ScrambleUInt(_context.TableWriteTokens[0]))
				        .Append(" or HandlerTableMode==").Append(ScrambleUInt(_context.TableWriteTokens[2]))
				        .Append(" then return HandlerReadStack(InstructionFields[3],").Append(ScrambleNumber(r.Next(2))).Append(");end;")
				        .Append("return InstructionFields[3];end;");
				fragment.Append("local function HandlerTableAcquireValue(HandlerTableMode,InstructionFields)")
				        .Append("if HandlerTableMode==").Append(ScrambleUInt(_context.TableWriteTokens[0]))
				        .Append(" or HandlerTableMode==").Append(ScrambleUInt(_context.TableWriteTokens[1]))
				        .Append(" then return HandlerReadStack(InstructionFields[4],").Append(ScrambleNumber(r.Next(2))).Append(");end;")
				        .Append("return InstructionFields[4];end;");
				fragment.Append("local function HandlerTableCommitA(HandlerTableTarget,HandlerTableKey,HandlerTableValue)HandlerTableTarget[HandlerTableKey]=HandlerTableValue;return HandlerTableValue;end;");
				fragment.Append("local function HandlerTableCommitB(HandlerTableTarget,HandlerTableKey,HandlerTableValue)local HandlerTableSlot=HandlerTableTarget;HandlerTableSlot[HandlerTableKey]=HandlerTableValue;return HandlerTableValue;end;");
				fragment.Append("local function HandlerTableCommitC(HandlerTableTarget,HandlerTableKey,HandlerTableValue)local HandlerTableResult=HandlerTableValue;HandlerTableTarget[HandlerTableKey]=HandlerTableResult;return HandlerTableResult;end;");
				fragment.Append("local function HandlerTableCommitD(HandlerTableTarget,HandlerTableKey,HandlerTableValue)do HandlerTableTarget[HandlerTableKey]=HandlerTableValue;end;return HandlerTableValue;end;");
				fragment.Append("local function HandlerTableCommit(HandlerTableCommitMode,HandlerTableTarget,HandlerTableKey,HandlerTableValue)");
				string[] commitLeaves = {"HandlerTableCommitA", "HandlerTableCommitB", "HandlerTableCommitC", "HandlerTableCommitD"};
				for (int index = 0; index < commitLeaves.Length; index++)
					fragment.Append(index == 0 ? "if " : "elseif ").Append("HandlerTableCommitMode==")
					        .Append(ScrambleUInt(_context.TableCommitTokens[index])).Append(" then return ")
					        .Append(commitLeaves[index]).Append("(HandlerTableTarget,HandlerTableKey,HandlerTableValue);");
				fragment.Append("else error('invalid protected payload',0);end;end;");
				fragment.Append("local function HandlerTableWrite(HandlerTableMode,InstructionFields)")
				        .Append("local HandlerTableTarget=HandlerReadStack(InstructionFields[2],").Append(ScrambleNumber(r.Next(2))).Append(");")
				        .Append("local HandlerTableKey,HandlerTableValue,HandlerTableCommitMode;local HandlerTableFresh=InstructionFields[6];")
				        .Append("local HandlerTableDecoyKey,HandlerTableDecoyValue;if HandlerTableFresh then HandlerTableDecoyKey={};HandlerTableDecoyValue=")
				        .Append(ScrambleUInt(NewFragmentToken())).Append(";HandlerTableCommit(").Append(ScrambleUInt(_context.TableCommitTokens[r.Next(4)]))
				        .Append(",HandlerTableTarget,HandlerTableDecoyKey,HandlerTableDecoyValue);end;");
				for (int index = 0; index < _context.TableWriteTokens.Length; index++)
				{
					fragment.Append(index == 0 ? "if " : "elseif ").Append("HandlerTableMode==")
					        .Append(ScrambleUInt(_context.TableWriteTokens[index])).Append(" then ");
					if (tableWriteValueFirst[index])
						fragment.Append("HandlerTableValue=HandlerTableAcquireValue(HandlerTableMode,InstructionFields);HandlerTableKey=HandlerTableAcquireKey(HandlerTableMode,InstructionFields);");
					else
						fragment.Append("HandlerTableKey=HandlerTableAcquireKey(HandlerTableMode,InstructionFields);HandlerTableValue=HandlerTableAcquireValue(HandlerTableMode,InstructionFields);");
					fragment.Append("HandlerTableCommitMode=").Append(ScrambleUInt(tableCommitRoute[index])).Append(";");
				}
				fragment.Append("else error('invalid protected payload',0);end;local HandlerTableResult=HandlerTableCommit(HandlerTableCommitMode,HandlerTableTarget,HandlerTableKey,HandlerTableValue);if HandlerTableFresh then HandlerTableCommit(HandlerTableCommitMode,HandlerTableTarget,HandlerTableDecoyKey,nil);end;return HandlerTableResult;end;");

				fragment.Append("local function HandlerBinary(HandlerFragmentMode,HandlerFragmentLeft,HandlerFragmentRight)");
				var binaryOrder = binaryOperators.OrderBy(_ => r.Next()).ToArray();
				for (int index = 0; index < binaryOrder.Length; index++)
				{
					string op = binaryOrder[index];
					fragment.Append(index == 0 ? "if " : "elseif ").Append("HandlerFragmentMode==")
					        .Append(ScrambleUInt(binaryFragmentTokens[op])).Append(" then return HandlerFragmentLeft")
					        .Append(op).Append("HandlerFragmentRight;");
				}
				fragment.Append("else error('invalid protected payload',0);end;end;");

				fragment.Append("local function HandlerUnary(HandlerFragmentMode,HandlerFragmentValue)");
				var unaryOrder = unaryOperators.OrderBy(_ => r.Next()).ToArray();
				for (int index = 0; index < unaryOrder.Length; index++)
				{
					string op = unaryOrder[index];
					fragment.Append(index == 0 ? "if " : "elseif ").Append("HandlerFragmentMode==")
					        .Append(ScrambleUInt(unaryFragmentTokens[op])).Append(" then return ")
					        .Append(op == "not" ? "not " : op).Append("HandlerFragmentValue;");
				}
				fragment.Append("else error('invalid protected payload',0);end;end;");
				fragment.Append("local function HandlerPc(HandlerFragmentCurrent,HandlerFragmentTarget,HandlerFragmentMode)")
				        .Append("if HandlerFragmentMode==").Append(ScrambleNumber(0)).Append(" then return HandlerFragmentCurrent+").Append(ScrambleNumber(1)).Append(";")
				        .Append("elseif HandlerFragmentMode==").Append(ScrambleNumber(1)).Append(" then return HandlerFragmentTarget;")
				        .Append("else return HandlerFragmentCurrent+HandlerFragmentTarget;end;end;");
				return fragment.ToString();
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

			string BuildPrimitivePrelude()
			{
				string BootstrapLiteral(string value)
				{
					var parts = new List<string>();
					int position = 0;
					while (position < value.Length)
					{
						int remaining = value.Length - position;
						int width = remaining == 1 ? 1 : 1 + r.Next(Math.Min(3, remaining));
						var literal = new StringBuilder("\"");
						for (int i = 0; i < width; i++)
							literal.Append("\\" + ((int)value[position + i]).ToString("D3"));
						literal.Append('"');
						parts.Add(literal.ToString());
						position += width;
					}
					return string.Join("..", parts);
				}

				var keyNames = new Dictionary<string, string>
				{
					["StringTable"] = "string", ["TableTable"] = "table", ["MathTable"] = "math", ["DebugTable"] = "debug",
					["Byte"] = "byte", ["Char"] = "char", ["Sub"] = "sub", ["Concat"] = "concat",
					["Insert"] = "insert", ["LDExp"] = "ldexp", ["GetFEnv"] = "getfenv",
					["Setmetatable"] = "setmetatable", ["Getmetatable"] = "getmetatable",
					["RawGet"] = "rawget", ["RawSet"] = "rawset", ["RawEqual"] = "rawequal",
					["Next"] = "next", ["Select"] = "select", ["PCall"] = "pcall", ["Type"] = "type",
					["ToString"] = "tostring", ["GlobalUnpack"] = "unpack", ["TableUnpack"] = "unpack",
					["ToNumber"] = "tonumber"
				};
				var storageOrder = keyNames.Keys.ToList();
				storageOrder.Shuffle(r);
				var tokens = new Dictionary<string, int>();
				var starts = new Dictionary<string, int>();
				var lengths = new Dictionary<string, int>();
				var salts = new Dictionary<string, int>();
				var usedTokens = new HashSet<int>();
				var encodedBytes = new List<int>();
				int multiplier = new[] { 29, 37, 53, 61, 73 }[r.Next(5)];
				int increment = 17 + r.Next(197);

				foreach (string label in storageOrder)
				{
					int padding = 1 + r.Next(7);
					for (int i = 0; i < padding; i++) encodedBytes.Add(r.Next(256));
					int token;
					do token = 17 + r.Next(220); while (!usedTokens.Add(token));
					int salt = 1 + r.Next(255);
					tokens[label] = token;
					starts[label] = encodedBytes.Count + 1;
					lengths[label] = keyNames[label].Length;
					salts[label] = salt;
					int state = (token * multiplier + salt) & 255;
					for (int i = 0; i < keyNames[label].Length; i++)
					{
						state = (state * multiplier + increment + i) & 255;
						encodedBytes.Add((keyNames[label][i] + state) & 255);
					}
				}
				for (int i = 0; i < 2 + r.Next(8); i++) encodedBytes.Add(r.Next(256));

				var descriptorOrder = keyNames.Keys.ToList();
				descriptorOrder.Shuffle(r);
				var descriptorStatements = descriptorOrder.Select(label =>
					"PrimitiveKeyMeta[" + tokens[label] + "]={" + starts[label] + "," + lengths[label] + "," + salts[label] + "};").ToList();
				string byteLiteral = "{" + string.Join(",", encodedBytes) + "}";
				int vaultTopology = r.Next(3);
				var prelude = new StringBuilder("return(function()");

				int bootstrapTopology = r.Next(3);
				if (bootstrapTopology == 0)
				{
					prelude.Append("local PrimitiveEnvironmentReader=getfenv or function()return _G end;local PrimitiveEnvironment=(PrimitiveEnvironmentReader and PrimitiveEnvironmentReader())or _G;");
					prelude.Append("local PrimitiveRawGet=PrimitiveEnvironment[" + BootstrapLiteral("rawget") + "];");
					prelude.Append("local PrimitiveString=PrimitiveEnvironment[" + BootstrapLiteral("string") + "];");
					prelude.Append("local PrimitiveBootstrapChar=PrimitiveString[" + BootstrapLiteral("char") + "];");
				}
				else if (bootstrapTopology == 1)
				{
					prelude.Append("local PrimitiveEnvironmentReader=getfenv;local PrimitiveEnvironment=(PrimitiveEnvironmentReader and PrimitiveEnvironmentReader())or _G;");
					prelude.Append("PrimitiveEnvironmentReader=PrimitiveEnvironmentReader or function()return PrimitiveEnvironment end;local PrimitiveRawGet,PrimitiveString,PrimitiveBootstrapChar;");
					prelude.Append("PrimitiveRawGet=PrimitiveEnvironment[" + BootstrapLiteral("rawget") + "];PrimitiveString=PrimitiveEnvironment[" + BootstrapLiteral("string") + "];PrimitiveBootstrapChar=PrimitiveString[" + BootstrapLiteral("char") + "];");
				}
				else
				{
					prelude.Append("local PrimitiveEnvironmentReader=getfenv;local PrimitiveEnvironment=(PrimitiveEnvironmentReader and PrimitiveEnvironmentReader())or _G;PrimitiveEnvironmentReader=PrimitiveEnvironmentReader or function()return PrimitiveEnvironment end;");
					prelude.Append("local PrimitiveRawGet=PrimitiveEnvironment[" + BootstrapLiteral("rawget") + "];local PrimitiveString=PrimitiveEnvironment[" + BootstrapLiteral("string") + "];local PrimitiveBootstrapChar=PrimitiveString[" + BootstrapLiteral("char") + "];");
				}
				prelude.Append("local function PrimitiveEnvironmentLookup(PrimitiveToken)local PrimitiveValue=PrimitiveRawGet(PrimitiveEnvironment,PrimitiveToken);if PrimitiveValue~=nil then return PrimitiveValue end;return PrimitiveEnvironment[PrimitiveToken]end;");
				prelude.Append("local function PrimitiveMemberLookup(PrimitiveParent,PrimitiveToken)if PrimitiveParent==nil then return nil end;local PrimitiveValue=PrimitiveRawGet(PrimitiveParent,PrimitiveToken);if PrimitiveValue~=nil then return PrimitiveValue end;return PrimitiveParent[PrimitiveToken]end;");

				if (vaultTopology == 0)
				{
					prelude.Append("local PrimitiveKeyBytes=" + byteLiteral + ";local PrimitiveKeyMeta={};local PrimitiveKeyCache={};");
					foreach (string statement in descriptorStatements) prelude.Append(statement);
				}
				else if (vaultTopology == 1)
				{
					prelude.Append("local PrimitiveKeyMeta={};");
					foreach (string statement in descriptorStatements) prelude.Append(statement);
					prelude.Append("local PrimitiveKeyCache={};local PrimitiveKeyBytes=" + byteLiteral + ";");
				}
				else
				{
					prelude.Append("local PrimitiveKeyBytes,PrimitiveKeyMeta,PrimitiveKeyCache=" + byteLiteral + ",{},{};");
					foreach (string statement in descriptorStatements) prelude.Append(statement);
				}

				prelude.Append("local function PrimitiveDecode(PrimitiveToken)local PrimitiveText=PrimitiveKeyCache[PrimitiveToken];if PrimitiveText then return PrimitiveText end;local PrimitiveRecord=PrimitiveKeyMeta[PrimitiveToken];PrimitiveText='';local PrimitiveIndex=(PrimitiveToken*" + multiplier + "+PrimitiveRecord[3])%256;for PrimitiveParent=0,PrimitiveRecord[2]-1 do PrimitiveIndex=(PrimitiveIndex*" + multiplier + "+" + increment + "+PrimitiveParent)%256;PrimitiveText=PrimitiveText..PrimitiveBootstrapChar((PrimitiveKeyBytes[PrimitiveRecord[1]+PrimitiveParent]-PrimitiveIndex)%256);end;PrimitiveKeyCache[PrimitiveToken]=PrimitiveText;return PrimitiveText end;");

				int resolverTopology = r.Next(3);
				string RootLookup(string label)
				{
					if (resolverTopology == 0) return "PrimitiveLookup(" + tokens[label] + ")";
					if (resolverTopology == 1) return "PrimitiveRoot(" + tokens[label] + ")";
					return "PrimitiveEnvironmentLookup(PrimitiveDecode(" + tokens[label] + "))";
				}
				string MemberLookup(string parent, string label)
				{
					if (resolverTopology == 0) return "PrimitiveLookup(" + tokens[label] + "," + parent + ")";
					if (resolverTopology == 1) return "PrimitiveMember(" + parent + "," + tokens[label] + ")";
					return "PrimitiveMemberLookup(" + parent + ",PrimitiveDecode(" + tokens[label] + "))";
				}
				if (resolverTopology == 0)
					prelude.Append("local function PrimitiveLookup(PrimitiveToken,PrimitiveParent)if PrimitiveParent then return PrimitiveMemberLookup(PrimitiveParent,PrimitiveDecode(PrimitiveToken))end;return PrimitiveEnvironmentLookup(PrimitiveDecode(PrimitiveToken))end;");
				else if (resolverTopology == 1)
					prelude.Append("local function PrimitiveRoot(PrimitiveToken)return PrimitiveEnvironmentLookup(PrimitiveDecode(PrimitiveToken))end;local function PrimitiveMember(PrimitiveParent,PrimitiveToken)return PrimitiveMemberLookup(PrimitiveParent,PrimitiveDecode(PrimitiveToken))end;");

				var libraryAssignments = new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>("StringTable", "PrimitiveString=" + RootLookup("StringTable") + ";"),
					new KeyValuePair<string, string>("TableTable", "PrimitiveTable=" + RootLookup("TableTable") + ";"),
					new KeyValuePair<string, string>("MathTable", "PrimitiveMath=" + RootLookup("MathTable") + ";"),
					new KeyValuePair<string, string>("DebugTable", "PrimitiveDebug=" + RootLookup("DebugTable") + ";")
				};
				libraryAssignments.Shuffle(r);
				prelude.Append("local PrimitiveTable,PrimitiveMath,PrimitiveDebug;");
				foreach (KeyValuePair<string, string> assignment in libraryAssignments) prelude.Append(assignment.Value);
				prelude.Append("local PrimitiveGlobalUnpack=" + RootLookup("GlobalUnpack")
					+ ";local PrimitiveTableUnpack=" + MemberLookup("PrimitiveTable", "TableUnpack") + ";");

				var assignments = new Dictionary<string, string>
				{
					["Byte"] = MemberLookup("PrimitiveString", "Byte"), ["Char"] = MemberLookup("PrimitiveString", "Char"),
					["Sub"] = MemberLookup("PrimitiveString", "Sub"), ["Concat"] = MemberLookup("PrimitiveTable", "Concat"),
					["Insert"] = MemberLookup("PrimitiveTable", "Insert"), ["LDExp"] = MemberLookup("PrimitiveMath", "LDExp"),
					["GetFEnv"] = RootLookup("GetFEnv") + " or PrimitiveEnvironmentReader",
					["Setmetatable"] = RootLookup("Setmetatable"), ["Getmetatable"] = RootLookup("Getmetatable"),
					["RawGet"] = RootLookup("RawGet"), ["RawSet"] = RootLookup("RawSet"), ["RawEqual"] = RootLookup("RawEqual"),
					["Next"] = RootLookup("Next"), ["Select"] = RootLookup("Select"), ["PCall"] = RootLookup("PCall"),
					["Type"] = RootLookup("Type"), ["ToString"] = RootLookup("ToString"),
					["Unpack"] = "PrimitiveGlobalUnpack or PrimitiveTableUnpack",
					["ToNumber"] = RootLookup("ToNumber")
				};
				var declarationOrder = assignments.Keys.ToList();
				declarationOrder.Shuffle(r);
				var resolutionOrder = assignments.Keys.ToList();
				resolutionOrder.Shuffle(r);
				prelude.Append("local " + string.Join(",", declarationOrder) + ";");
				foreach (string semanticName in resolutionOrder)
					prelude.Append(semanticName + "=" + assignments[semanticName] + ";");

				uint resolutionSignature = 2166136261u;
				foreach (KeyValuePair<string, string> assignment in libraryAssignments)
					foreach (char character in assignment.Key)
						resolutionSignature = (resolutionSignature ^ character) * 16777619u;
				foreach (string semanticName in resolutionOrder)
					foreach (char character in semanticName)
						resolutionSignature = (resolutionSignature ^ character) * 16777619u;
				Console.WriteLine("Primitive resolver: bootstrap=" + bootstrapTopology + "; vault=" + vaultTopology
					+ "; topology=" + resolverTopology + "; keys=" + keyNames.Count
					+ "; order=" + resolutionSignature.ToString("x8") + ".");
				return prelude.ToString();
			}

			byte[] bs = new Serializer(_context, settings).SerializeLChunk(_context.HeadChunk);
			string data = Base91Encode(bs);
			PayloadCarrierPlan payloadCarrier = BuildPayloadCarrierPlan(data, payloadCarrierRandom);
			Console.WriteLine("Payload carrier: segments=" + payloadCarrier.SegmentCount
				+ "; carrier=" + payloadCarrier.CarrierTopology
				+ "; assembly=" + payloadCarrier.AssemblyTopology
				+ "; stages=" + string.Join(",", payloadCarrier.StageCounts) + ".");

			vm += T(BuildPrimitivePrelude());

			// Carrier declarations remain in the outer loader scope, while each literal
			// assignment is injected only after identifier rewriting. This avoids
			// mutating identifier-looking byte sequences inside Base91 data.
			vm += payloadCarrier.Prelude;
			if (settings.AntiDump)
			{
				string guard = T(AntiDumpGenerator.GenerateRuntimeGuard(
					37 + r.Next(36),
					(uint) r.Next(1, int.MaxValue),
					_context.Binder.AttestationToken,
					guardRandom));
				for (int stage = 0; stage < payloadCarrier.StageAssignments.Length; stage++)
				{
					string marker = "--__IB2_GUARD_STAGE_" + (stage + 1) + "__";
					if (!guard.Contains(marker, StringComparison.Ordinal))
						throw new InvalidOperationException("Payload carrier guard stage is missing: " + (stage + 1));
					guard = guard.Replace(marker, payloadCarrier.StageAssignments[stage], StringComparison.Ordinal);
				}
				vm += guard;
			}
			else
			{
				vm += string.Concat(payloadCarrier.StageAssignments);
			}

			// Data is always Base91 encoded; Serializer records whether the restored
			// body itself is compressed. Runtime carrier topology is independent from
			// the decoder and from logical segment order.
			vm += T("local function decompress(PayloadParts)local PayloadChunks={}local out={}local PayloadLength=0;local v=-1;local acc=0;local bits=0;local function EmitPayloadByte(Value)out[#out+1]=Char(Value);PayloadLength=PayloadLength+1;if#out>=2048 then PayloadChunks[#PayloadChunks+1]=Concat(out);out={}end end;local function ConsumePayloadPart(b)if Type(b)=='table'then for j=1,#b do ConsumePayloadPart(b[j])end;return end;for i=1,#b do local z=Byte(Sub(b,i,i));local d=z-33;if z>39 then d=d-1 end;if z>92 then d=d-1 end;if d>=0 and d<=90 then if v<0 then v=d else v=v+d*91;acc=acc+v*(2^bits);if(v%8192)>88 then bits=bits+13 else bits=bits+14 end;while bits>=8 do EmitPayloadByte(acc%256);acc=(acc-acc%256)/256;bits=bits-8 end;v=-1 end end end end;ConsumePayloadPart(PayloadParts);PayloadParts=nil;if v>=0 then acc=acc+v*(2^bits);bits=bits+7;while bits>=8 do EmitPayloadByte(acc%256);acc=(acc-acc%256)/256;bits=bits-8 end end;if#out>0 then PayloadChunks[#PayloadChunks+1]=Concat(out)end;out=nil;return PayloadChunks,PayloadLength end;");
			vm += T(payloadCarrier.Assembly);

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
				.Replace("__IB2_PAYLOAD_ATTESTATION__", settings.AntiDump ? "GuardPayloadBinding" : "OuterSeed")
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
	        ConstCount = gBits32();
	        Chunk[15] = ConstCount;
	    elseif (Step == 2) then
        InstrCount = gBits32();
        BlockCount = gBits32();
        Chunk[11] = BlockCount;
        Chunk[12] = gBits32();
        Chunk[16] = gBits32();
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
	            local ChunkSuccessors = {};
	            local SuccessorRecords = {};
	            local PreviousSuccessor = 0;
	            for SuccessorIndex = 1, SuccessorCount do
	                local SuccessorStart = gBits32();
	                local WrappedState = gBits32();
	                local WrappedChunkState = gBits32();
	                if SuccessorStart <= PreviousSuccessor then error('invalid protected payload', 0); end;
	                Successors[SuccessorStart] = WrappedState;
	                ChunkSuccessors[SuccessorStart] = WrappedChunkState;
	                SuccessorRecords[SuccessorIndex] = {SuccessorStart, WrappedState, WrappedChunkState};
	                PreviousSuccessor = SuccessorStart;
	            end;
	            local Length = gBits32();
	            if Length < 25 or Pos + Length - 1 > PrototypeLength then error('invalid protected payload', 0); end;
	            local Block = NewPrototypeRecord(
	                10, K1, K2, K3, BlockStart + Verifier % 65536);
	            Block[1] = BlockStart;
	            Block[2] = Count;
	            Block[3] = SourceReadBytes(Length);
	            Block[4] = References;
	            Block[5] = Successors;
	            Block[6] = Verifier;
	            Block[7] = BlockTag;
	            Block[8] = RouteToken;
	            Block[9] = SuccessorRecords;
	            Block[10] = ChunkSuccessors;
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
	            Functions[Idx - 1] = SourceReadBytes(Length);
	        end;"));

			if (settings.PreserveLineInfo)
				vm += T(@"    elseif (Step == 4) then
        for Idx = 1, gBits32() do Lines[Idx] = gBits32(); end;");

				vm += T(@"    end;
	end;

	if Pos ~= PrototypeLength + 1 or Chunk[3] == nil
	or FinalizePrototypeIntegrity(PrototypeLength, K1, K2, K3) ~= PrototypeTag then error('invalid protected payload', 0); end;
	ActivePrototypeHash, ActivePrototypeRight, PrototypeAbsorb = nil, nil, nil;
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
	        if References[ReferenceIndex] < 1 or References[ReferenceIndex] > 65535 then error('invalid protected payload', 0); end;
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
        local SavedSourceLength, SavedSourceMode = ActiveSourceLength, SourceIsPaged;
        ByteString, Pos, ActiveSourceLength, SourceIsPaged = Encoded, 1, #Encoded, false;
        local Decoded = Deserialize();
        ByteString, Pos, ActiveSourceLength, SourceIsPaged = SavedByteString, SavedPos, SavedSourceLength, SavedSourceMode;
        Proto[Index] = Decoded;
        return Decoded;
    end;
    return Encoded;
end;

local function DecodeConstantCapsule(Capsule, Index, ConstantChainState, EntryState, CurrentChunkState, BlockStart, K1, K2, K3, ConstTags)
    local SavedByteString, SavedPos = ByteString, Pos;
    local SavedSourceLength, SavedSourceMode = ActiveSourceLength, SourceIsPaged;
    ByteString, Pos, ActiveSourceLength, SourceIsPaged = Capsule, 1, #Capsule, false;
    local StoredTag = gBits32();
    local EncodedBody = Sub(Capsule, 5);
    if ComputeConstantIntegrity(EncodedBody, Index, EntryState, CurrentChunkState, BlockStart, K1, K2, K3) ~= StoredTag then error('invalid protected payload', 0); end;
    local State = ConstantMaskState(Index, EntryState, CurrentChunkState, BlockStart, K1, K2, K3);
    local RawParts = {};
    for I = 1, #EncodedBody do
        local Mask = (State - State % 16777216) / 16777216;
        RawParts[I] = Char(BitXOR(Byte(EncodedBody, I, I), Mask));
        State = (State * 1664525 + 1013904223) % 4294967296;
    end;
    local Raw = Concat(RawParts);
    RawParts, EncodedBody = nil, nil;
    ByteString, Pos, ActiveSourceLength, SourceIsPaged = Raw, 1, #Raw, false;
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
        local ShardCount = gBits8();
        if ShardCount < 1 or ShardCount > 7 or (Length > 1 and ShardCount < 2)
        or (Length > 0 and ShardCount > Length) then error('invalid protected payload', 0); end;
        local ShardOrder = DerivePermutation(ShardCount, K1, K2, K3,
            (__IB2_DOMAIN_CONSTANT_MASK__ + 2654435769) % 4294967296);
        local StringParts = {};
        for ShardOffset = 1, ShardCount do
            local ShardIndex = ShardOrder[ShardOffset];
            local ShardLength = gBits32();
            local ExpectedShardLength = 0;
            for ShardPosition = ShardIndex, Length - 1, ShardCount do
                ExpectedShardLength = ExpectedShardLength + 1;
            end;
            if ShardLength ~= ExpectedShardLength or Pos + ShardLength - 1 > #Raw then error('invalid protected payload', 0); end;
            local State = StringShardState(Index, ShardIndex, Length, ConstantChainState,
                EntryState, CurrentChunkState, BlockStart, K1, K2, K3);
            for I = 0, ShardLength - 1 do
                local ShardPosition = ShardIndex + I * ShardCount;
                local Mask = (State - State % 16777216) / 16777216;
                local ShardByte = gBits8();
                StringParts[ShardPosition + 1] = Char(BitXOR(ShardByte, Mask));
                State = (U32Mul(State, 1664525) + 1013904223
                    + ShardByte + (ShardPosition + 1) * 257) % 4294967296;
            end;
        end;
        if Length > 0 and #StringParts ~= Length then error('invalid protected payload', 0); end;
        Cons = Concat(StringParts);
        StringParts, ShardOrder = nil, nil;
    else
        error('invalid protected payload', 0);
    end;
    if Pos ~= #Raw + 1 then error('invalid protected payload', 0); end;
    Raw = nil;
    ByteString, Pos, ActiveSourceLength, SourceIsPaged = SavedByteString, SavedPos, SavedSourceLength, SavedSourceMode;
    return Cons;
end;

local function PrototypeDecoderMode(K1, K2, K3)
    return (K1 * 13 + K2 * 7 + K3 * 11 + __IB2_DOMAIN_DECODE_PIPELINE__) % 4;
end;

local function DecodePrototypeColumn(Data, Mode, Role, TargetIndex, EntryState, K1, K2, K3)
    local Output = {};
    local Low = EntryState % 65536;
    local High = (EntryState - Low) / 65536;
    local Length = #Data;
    for EncodedIndex = 0, Length - 1 do
        local Index = (Mode == 1 or Mode == 3) and (Length - EncodedIndex - 1) or EncodedIndex;
        local Value = Byte(Data, EncodedIndex + 1, EncodedIndex + 1);
        local Mask = (Low + High * 3 + K1 * 5 + K2 * 7 + K3 * 11
            + TargetIndex * 13 + Role * 17 + Index * 29 + __IB2_DOMAIN_DECODE_PIPELINE__) % 256;
        if Mode == 0 then
            Value = BitXOR(Value, Mask);
        elseif Mode == 1 then
            Value = (Value - Mask) % 256;
        elseif Mode == 2 then
            Value = BitXOR(Value, Mask);
            Value = (Value % 16) * 16 + (Value - Value % 16) / 16;
        else
            Value = (Value - Mask) % 256;
            local Shift = ((Role + TargetIndex + Index) % 7) + 1;
            local Divisor = 2 ^ Shift;
            Value = (Value - Value % Divisor) / Divisor + (Value % Divisor) * (2 ^ (8 - Shift));
        end;
        Output[Index + 1] = Char(Value);
    end;
    return Concat(Output);
end;

local function DecodeInstructionBlock(Chunk, Block, EntryState, CurrentChunkState, PreviousOpcodeState, TargetIndex)
    local K1, K2, K3 = Chunk[5], Chunk[6], Chunk[7];
    local References = Block[4];
    local Body = Block[3];
    if ComputeBlockIntegrity(Body, EntryState, Block[1], Block[2], Block[8], References, Block[6], Block[9], K1, K2, K3) ~= Block[7] then
        error('invalid protected payload', 0);
    end;

    -- Scan only the authenticated top-level framing. Logical instruction windows
    -- and block-local constant capsules share one state-permuted physical stream.
    local FragmentCount = Block[2] + #References;
    local FragmentOrder = DeriveCodeDataPermutation(Block[2], #References, U32(BitXOR(EntryState, CurrentChunkState)),
        K1, K2, K3, __IB2_DOMAIN_CODE_DATA_PERMUTATION__);
    local FragmentSpans = {};
    local BodyPosition = 1;
    for PhysicalSlot = 1, FragmentCount do
        if BodyPosition + 3 > #Body then error('invalid protected payload', 0); end;
        local Length = Byte(Body, BodyPosition, BodyPosition) + Byte(Body, BodyPosition + 1, BodyPosition + 1) * 256
            + Byte(Body, BodyPosition + 2, BodyPosition + 2) * 65536 + Byte(Body, BodyPosition + 3, BodyPosition + 3) * 16777216;
        BodyPosition = BodyPosition + 4;
        local LogicalSlot = FragmentOrder[PhysicalSlot] + 1;
        local MinimumLength = LogicalSlot <= Block[2] and 21 or 5;
        if Length < MinimumLength or BodyPosition + Length - 1 > #Body or FragmentSpans[LogicalSlot] then
            error('invalid protected payload', 0);
        end;
        FragmentSpans[LogicalSlot] = {BodyPosition, Length};
        BodyPosition = BodyPosition + Length;
    end;
    if BodyPosition ~= #Body + 1 then error('invalid protected payload', 0); end;

    local function ReadFragment(LogicalSlot)
        local Span = FragmentSpans[LogicalSlot];
        if not Span then error('invalid protected payload', 0); end;
        return Sub(Body, Span[1], Span[1] + Span[2] - 1);
    end;

    local TargetSlot = TargetIndex - Block[1] + 1;
    if TargetSlot < 1 or TargetSlot > Block[2] then error('invalid protected payload', 0); end;
    local Record = ReadFragment(TargetSlot);
    local Digest = InstructionDigest(Record, TargetIndex, K1, K2, K3, CurrentChunkState, EntryState);

    -- Parse just the requested instruction record. Five field roles remain
    -- independently framed and state-permuted, but no block-wide columns or
    -- instruction array are materialized.
    local SavedByteString, SavedPos = ByteString, Pos;
    local SavedSourceLength, SavedSourceMode = ActiveSourceLength, SourceIsPaged;
    ByteString, Pos, ActiveSourceLength, SourceIsPaged = Record, 1, #Record, false;
    local ColumnOrder = DeriveBlockPermutation(5, EntryState, K1, K2, K3, __IB2_DOMAIN_BLOCK_COLUMN__);
    local Columns = {};
    for PhysicalSlot = 1, 5 do
        if Pos + 3 > #Record then error('invalid protected payload', 0); end;
        local Length = gBits32();
        if Pos + Length - 1 > #Record then error('invalid protected payload', 0); end;
        local Role = ColumnOrder[PhysicalSlot] + 1;
        if Columns[Role] ~= nil then error('invalid protected payload', 0); end;
        Columns[Role] = SourceReadBytes(Length);
    end;
    if Pos ~= #Record + 1 then error('invalid protected payload', 0); end;
    ByteString, Pos, ActiveSourceLength, SourceIsPaged = SavedByteString, SavedPos, SavedSourceLength, SavedSourceMode;
    Record = nil;
    local DecoderMode = PrototypeDecoderMode(K1, K2, K3);
    for Role = 1, 5 do
        Columns[Role] = DecodePrototypeColumn(
            Columns[Role], DecoderMode, Role - 1, TargetIndex, EntryState, K1, K2, K3);
    end;

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

    local ReferenceSlots = {};
    for ReferenceIndex = 1, #References do ReferenceSlots[References[ReferenceIndex]] = Block[2] + ReferenceIndex; end;
    local ConstTags = DerivePermutation(4, K1, K2, K3, __IB2_DOMAIN_CONSTANT_TAG_PERMUTATION__);
    local ResolvedConstants, ResolvedConstantFlags = {}, {};
    local function ResolveConstant(Index)
        if ResolvedConstantFlags[Index] then return ResolvedConstants[Index]; end;
        local ConstantChainState = BeginConstantChain(EntryState, CurrentChunkState, Block[1], K1, K2, K3);
        local LogicalSlot;
        for ReferenceIndex = 1, #References do
            local Reference = References[ReferenceIndex];
            local ReferenceSlot = ReferenceSlots[Reference];
            if Reference == Index then LogicalSlot = ReferenceSlot; break; end;
            local PreviousCapsule = ReadFragment(ReferenceSlot);
            ConstantChainState = AdvanceConstantChain(ConstantChainState, PreviousCapsule, Reference);
            PreviousCapsule = nil;
        end;
        if not LogicalSlot then error('invalid protected payload', 0); end;
        local Capsule = ReadFragment(LogicalSlot);
        local Value = DecodeConstantCapsule(Capsule, Index, ConstantChainState,
            EntryState, CurrentChunkState, Block[1], K1, K2, K3, ConstTags);
        Capsule = nil;
        ResolvedConstantFlags[Index], ResolvedConstants[Index] = true, Value;
        return Value;
    end;

    local Descriptor = BitXOR(ColumnRead8(1), BlockFieldKey(EntryState, TargetIndex, 7, K1, K2, K3) % 256);
    local IsFreshTableWrite = Descriptor >= 128;
    if IsFreshTableWrite then Descriptor = Descriptor - 128; end;
    local IsFused = Descriptor >= 64;
    if IsFused then Descriptor = Descriptor - 64; end;
    local Inst;
    local InstructionConstantFields = {};
    if (gBit(Descriptor, 1, 1) == 0) then
        local Type = gBit(Descriptor, 2, 3);
        local Mask = gBit(Descriptor, 4, 6);
        Inst =
        {
            BitXOR(ColumnRead16(2), OpcodeStateKey(PreviousOpcodeState, TargetIndex)),
            BitXOR(BitXOR(ColumnRead16(3), FieldKey(TargetIndex, 1, K1, K2, K3)), BlockFieldKey(EntryState, TargetIndex, 1, K1, K2, K3)),
            nil,
            nil
        };

        if (Type == 0) then
            Inst[OP_B] = BitXOR(BitXOR(ColumnRead16(4), FieldKey(TargetIndex, 2, K1, K2, K3)), BlockFieldKey(EntryState, TargetIndex, 2, K1, K2, K3));
            Inst[OP_C] = BitXOR(BitXOR(ColumnRead16(5), FieldKey(TargetIndex, 3, K1, K2, K3)), BlockFieldKey(EntryState, TargetIndex, 3, K1, K2, K3));
        elseif (Type == 1) then
            Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(TargetIndex, 2, K1, K2, K3)), BlockFieldKey32(EntryState, TargetIndex, 2, K1, K2, K3)));
        elseif (Type == 2) then
            Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(TargetIndex, 2, K1, K2, K3)), BlockFieldKey32(EntryState, TargetIndex, 2, K1, K2, K3))) - (2 ^ 16);
        elseif (Type == 3) then
            Inst[OP_B] = U32(BitXOR(BitXOR(ColumnRead32(4), FieldKey32(TargetIndex, 2, K1, K2, K3)), BlockFieldKey32(EntryState, TargetIndex, 2, K1, K2, K3))) - (2 ^ 16);
            Inst[OP_C] = BitXOR(BitXOR(ColumnRead16(5), FieldKey(TargetIndex, 3, K1, K2, K3)), BlockFieldKey(EntryState, TargetIndex, 3, K1, K2, K3));
        end;

        if gBit(Mask, 1, 1) == 1 then InstructionConstantFields[OP_A] = Inst[OP_A]; end;
        if gBit(Mask, 2, 2) == 1 then InstructionConstantFields[OP_B] = Inst[OP_B]; end;
        if gBit(Mask, 3, 3) == 1 then InstructionConstantFields[OP_C] = Inst[OP_C]; end;

        if IsFused then
            local FusedCount = ColumnRead8(1);
            if FusedCount < 1 or FusedCount > 5 then error('invalid protected payload', 0); end;
            local FusedInstructionFields, FusedConstantFields = {}, {};
            for FusedIndex = 1, FusedCount do
                local FusedDescriptor = ColumnRead8(1);
                if FusedDescriptor >= 64 or gBit(FusedDescriptor, 1, 1) ~= 0 then error('invalid protected payload', 0); end;
                local FusedType = gBit(FusedDescriptor, 2, 3);
                local FusedMask = gBit(FusedDescriptor, 4, 6);
                local FusedInstruction = {nil, ColumnRead16(3), nil, nil};
                if FusedType == 0 then
                    FusedInstruction[OP_B], FusedInstruction[OP_C] = ColumnRead16(4), ColumnRead16(5);
                elseif FusedType == 1 then
                    FusedInstruction[OP_B] = ColumnRead32(4);
                elseif FusedType == 2 then
                    FusedInstruction[OP_B] = ColumnRead32(4) - (2 ^ 16);
                elseif FusedType == 3 then
                    FusedInstruction[OP_B], FusedInstruction[OP_C] = ColumnRead32(4) - (2 ^ 16), ColumnRead16(5);
                end;
                local FusedInstructionConstants = {};
                if gBit(FusedMask, 1, 1) == 1 then FusedInstructionConstants[OP_A] = FusedInstruction[OP_A]; end;
                if gBit(FusedMask, 2, 2) == 1 then FusedInstructionConstants[OP_B] = FusedInstruction[OP_B]; end;
                if gBit(FusedMask, 3, 3) == 1 then FusedInstructionConstants[OP_C] = FusedInstruction[OP_C]; end;
                FusedInstructionFields[FusedIndex], FusedConstantFields[FusedIndex] = FusedInstruction, FusedInstructionConstants;
            end;
            Inst[5], InstructionConstantFields[5] = FusedInstructionFields, FusedConstantFields;
        end;
    elseif Descriptor == 1 then
        Inst = {nil, nil, nil, nil};
    else
        error('invalid protected payload', 0);
    end;
    if IsFreshTableWrite then
        if not Inst or gBit(Descriptor, 1, 1) ~= 0 then error('invalid protected payload', 0); end;
        Inst[6] = true;
    end;
    for Role = 1, 5 do
        if type(Columns[Role]) ~= 'string' or ColumnPositions[Role] ~= #Columns[Role] + 1 then error('invalid protected payload', 0); end;
    end;
    Columns = nil;
    if next(InstructionConstantFields) == nil then
        InstructionConstantFields, ResolveConstant = nil, nil;
        FragmentSpans, Body, ReferenceSlots = nil, nil, nil;
    end;
    return Inst, Digest, InstructionConstantFields, ResolveConstant;
end;

-- Constant capsules stay inside the authenticated block body through all four
-- synthetic field-replay passes. The operand proxy opens a capsule only when
-- the selected handler first indexes that exact operand. Separate decoded flags
-- preserve nil constants, and clearing the resolver releases retained block
-- material as soon as every constant operand used by this invocation is read.
local function BindInstructionOperands(InstructionFields, InstructionConstantFields, InstructionConstantResolver)
    if not InstructionConstantFields then return InstructionFields; end;
    local FusedInstructionFields = InstructionFields[5];
    local FusedConstantFields = InstructionConstantFields[5];
    if FusedInstructionFields then
        if type(FusedConstantFields) ~= 'table' or #FusedInstructionFields ~= #FusedConstantFields then error('invalid protected payload', 0); end;
        InstructionConstantFields[5] = nil;
        for FusedIndex = 1, #FusedInstructionFields do
            FusedInstructionFields[FusedIndex] = BindInstructionOperands(
                FusedInstructionFields[FusedIndex], FusedConstantFields[FusedIndex], InstructionConstantResolver);
        end;
    end;
    if next(InstructionConstantFields) == nil then return InstructionFields; end;
    local InstructionDecodedFields, InstructionDecodedValues = {}, {};
    local InstructionRemainingConstants = 0;
    for InstructionFieldKey in pairs(InstructionConstantFields) do
        InstructionRemainingConstants = InstructionRemainingConstants + 1;
    end;
    if InstructionRemainingConstants == 0 or type(InstructionConstantResolver) ~= 'function' then
        error('invalid protected payload', 0);
    end;
    return Setmetatable({}, {__index = function(_, InstructionFieldKey)
        if InstructionDecodedFields[InstructionFieldKey] then
            return InstructionDecodedValues[InstructionFieldKey];
        end;
        local InstructionConstantIndex = InstructionConstantFields and InstructionConstantFields[InstructionFieldKey];
        if InstructionConstantIndex ~= nil then
            local Value = InstructionConstantResolver(InstructionConstantIndex);
            InstructionDecodedFields[InstructionFieldKey] = true;
            InstructionDecodedValues[InstructionFieldKey] = Value;
            InstructionRemainingConstants = InstructionRemainingConstants - 1;
            if InstructionRemainingConstants == 0 then
                InstructionConstantFields, InstructionConstantResolver = nil, nil;
            end;
            return Value;
        end;
        return InstructionFields[InstructionFieldKey];
    end});
end;

local function SelectMaterializerEnum(Chunk, Stage)
    local MaterializeMode = (Chunk[5] * 13 + Chunk[6] * 7 + Chunk[7]
        + __IB2_DOMAIN_CODE_DATA_PERMUTATION__ + Stage) % 4;
    if MaterializeMode == 0 then return __IB2_MATERIALIZER_OPCODE_0__;
    elseif MaterializeMode == 1 then return __IB2_MATERIALIZER_OPCODE_1__;
    elseif MaterializeMode == 2 then return __IB2_MATERIALIZER_OPCODE_2__;
    else return __IB2_MATERIALIZER_OPCODE_3__; end;
end;

local function GetInstruction(Chunk, Index, Flow, AllowMaterializer)
    local BlockMap = Chunk[10];
    local Block = BlockMap and BlockMap[Index];
    if not Block then error('invalid protected payload', 0); end;

    -- The real instruction is decoded once into an invocation-local overlay.
    -- A synthetic materializer leaf rewinds both PC and Flow by one; the next
    -- top-level fetch consumes this private entry and replays the same PC.
    local MaterializeIndexSlot = 32 + ((Chunk[5] * 257 + Chunk[6] * 17 + Chunk[7]
        + __IB2_DOMAIN_CODE_DATA_PERMUTATION__) % 104729);
    local MaterializeOpcodeSlot = MaterializeIndexSlot + 104729;
    local MaterializeASlot = MaterializeIndexSlot + 209458;
    local MaterializeBSlot = MaterializeIndexSlot + 314187;
    local MaterializeCSlot = MaterializeIndexSlot + 418916;
    local MaterializeStageSlot = MaterializeIndexSlot + 523645;
    local MaterializeConstantFieldsSlot = MaterializeIndexSlot + 628374;
    local MaterializeConstantResolverSlot = MaterializeIndexSlot + 733103;
    local MaterializeFusedSlot = MaterializeIndexSlot + 837832;
    local MaterializeFreshTableSlot = MaterializeIndexSlot + 942561;
    local FlowCache = Flow[4];
    if AllowMaterializer and FlowCache and FlowCache[MaterializeIndexSlot] == Index then
        local MaterializeStage = FlowCache[MaterializeStageSlot];
        if type(MaterializeStage) ~= 'number' or MaterializeStage < 1 or MaterializeStage > 4
        or Flow[1] ~= Index - 1 or Flow[2] ~= Block
        or FlowCache[1] ~= Block or FlowCache[2] ~= Flow[3] then
            error('invalid protected payload', 0);
        end;
        Flow[1] = Index;
        if MaterializeStage < 4 then
            FlowCache[MaterializeStageSlot] = MaterializeStage + 1;
            return {}, SelectMaterializerEnum(Chunk, MaterializeStage);
        end;
        local MaterializedFields = {
            FlowCache[MaterializeOpcodeSlot], FlowCache[MaterializeASlot],
            FlowCache[MaterializeBSlot], FlowCache[MaterializeCSlot],
            FlowCache[MaterializeFusedSlot], FlowCache[MaterializeFreshTableSlot]
        };
        local MaterializedConstantFields = FlowCache[MaterializeConstantFieldsSlot];
        local MaterializedConstantResolver = FlowCache[MaterializeConstantResolverSlot];
        local MaterializedInstruction = BindInstructionOperands(
            MaterializedFields, MaterializedConstantFields, MaterializedConstantResolver);
        FlowCache[MaterializeIndexSlot], FlowCache[MaterializeOpcodeSlot], FlowCache[MaterializeASlot],
            FlowCache[MaterializeBSlot], FlowCache[MaterializeCSlot], FlowCache[MaterializeStageSlot],
            FlowCache[MaterializeConstantFieldsSlot], FlowCache[MaterializeConstantResolverSlot],
            FlowCache[MaterializeFusedSlot], FlowCache[MaterializeFreshTableSlot] =
            nil, nil, nil, nil, nil, nil, nil, nil, nil, nil;
        return MaterializedInstruction;
    end;

    local LastIndex = Flow[1];
    local CurrentBlock = Flow[2];
    local EntryState;
    local CurrentChunkState;
    local PreviousInstructionState;
    local PreviousOpcodeState;
    if not CurrentBlock then
        if Index ~= 1 then error('invalid protected payload', 0); end;
        __IB2_FIRST_BLOCK_CHECK__
        EntryState = U32(BitXOR(Chunk[12], InitialFlowKey(Chunk[5], Chunk[6], Chunk[7])));
        CurrentChunkState = U32(BitXOR(Chunk[16], InitialChunkKey(Chunk[5], Chunk[6], Chunk[7])));
        PreviousInstructionState = BeginInstructionState(CurrentChunkState, EntryState, Block[1], Block[7], Chunk[5], Chunk[6], Chunk[7]);
        PreviousOpcodeState = BeginOpcodeState(CurrentChunkState, EntryState, Block[1], Chunk[5], Chunk[6], Chunk[7]);
    elseif CurrentBlock ~= Block or Index ~= LastIndex + 1 then
        if Index ~= Block[1] or not FlowCache or FlowCache[1] ~= CurrentBlock
        or FlowCache[2] ~= Flow[3]
        or InstructionStateSeal(FlowCache[4], LastIndex, FlowCache[3], Flow[3], CurrentBlock[7]) ~= FlowCache[5]
        or OpcodeStateSeal(FlowCache[6], LastIndex, FlowCache[3], Flow[3], CurrentBlock[7]) ~= FlowCache[7] then
            error('invalid protected payload', 0);
        end;
        local WrappedState = CurrentBlock[5][Block[1]];
        local WrappedChunkState = CurrentBlock[10][Block[1]];
        if not WrappedState or not WrappedChunkState then error('invalid protected payload', 0); end;
        EntryState = U32(BitXOR(WrappedState, FlowKey(Flow[3], LastIndex, Block[1], Chunk[5], Chunk[6], Chunk[7])));
        CurrentChunkState = U32(BitXOR(WrappedChunkState, ChunkChainKey(
            FlowCache[3], Flow[3], LastIndex, Block[1], Chunk[5], Chunk[6], Chunk[7])));
        PreviousInstructionState = BeginInstructionState(CurrentChunkState, EntryState, Block[1], Block[7], Chunk[5], Chunk[6], Chunk[7]);
        PreviousOpcodeState = BeginOpcodeState(CurrentChunkState, EntryState, Block[1], Chunk[5], Chunk[6], Chunk[7]);
    else
        if not FlowCache or FlowCache[1] ~= CurrentBlock or FlowCache[2] ~= Flow[3]
        or InstructionStateSeal(FlowCache[4], LastIndex, FlowCache[3], Flow[3], CurrentBlock[7]) ~= FlowCache[5]
        or OpcodeStateSeal(FlowCache[6], LastIndex, FlowCache[3], Flow[3], CurrentBlock[7]) ~= FlowCache[7] then
            error('invalid protected payload', 0);
        end;
        EntryState = Flow[3];
        CurrentChunkState = FlowCache[3];
        PreviousInstructionState = FlowCache[4];
        PreviousOpcodeState = FlowCache[6];
    end;

    if FlowVerifier(EntryState, Block[1], Chunk[5], Chunk[6], Chunk[7]) ~= Block[6]
    or ChunkState(EntryState, Block[1], Block[2], Chunk[5], Chunk[6], Chunk[7]) ~= CurrentChunkState then
        error('invalid protected payload', 0);
    end;

    local Inst, Digest, InstructionConstantFields, InstructionConstantResolver = DecodeInstructionBlock(
        Chunk, Block, EntryState, CurrentChunkState, PreviousOpcodeState, Index);
    local CurrentInstructionState = AdvanceInstructionState(
        PreviousInstructionState, Digest, Index, CurrentChunkState, EntryState);
    local CurrentInstructionSeal = InstructionStateSeal(
        CurrentInstructionState, Index, CurrentChunkState, EntryState, Block[7]);
    local CurrentOpcodeState = AdvanceOpcodeState(
        PreviousOpcodeState, Digest, Index, CurrentChunkState, EntryState);
    local CurrentOpcodeSeal = OpcodeStateSeal(
        CurrentOpcodeState, Index, CurrentChunkState, EntryState, Block[7]);
    FlowCache = {};
    FlowCache[1], FlowCache[2], FlowCache[3], FlowCache[4], FlowCache[5], FlowCache[6], FlowCache[7] =
        Block, EntryState, CurrentChunkState, CurrentInstructionState, CurrentInstructionSeal, CurrentOpcodeState, CurrentOpcodeSeal;
    Flow[1], Flow[2], Flow[3], Flow[4] = Index, Block, EntryState, FlowCache;
    local MaterializeEnum;
    if AllowMaterializer then
        FlowCache[MaterializeIndexSlot] = Index;
        FlowCache[MaterializeOpcodeSlot] = Inst[1];
        FlowCache[MaterializeASlot] = Inst[2];
        FlowCache[MaterializeBSlot] = Inst[3];
        FlowCache[MaterializeCSlot] = Inst[4];
        FlowCache[MaterializeStageSlot] = 1;
        FlowCache[MaterializeConstantFieldsSlot] = InstructionConstantFields;
        FlowCache[MaterializeConstantResolverSlot] = InstructionConstantResolver;
        FlowCache[MaterializeFusedSlot] = Inst[5];
        FlowCache[MaterializeFreshTableSlot] = Inst[6];
        Inst = {};
        MaterializeEnum = SelectMaterializerEnum(Chunk, 0);
    else
        Inst = BindInstructionOperands(Inst, InstructionConstantFields, InstructionConstantResolver);
    end;
    __IB2_GUARD_BIND__
    return Inst, MaterializeEnum;
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
				// Fetch authenticates the opaque block, parses one instruction window,
				// opens only its referenced constants, then binds the resulting state into
				// the live GuardState/GuardSeal chain before opcode execution.
				blockRuntime = blockRuntime
					.Replace("__IB2_FIRST_BLOCK_CHECK__", "if GuardProbe(true) then Chunk[2], Chunk[15], Flow[4] = {}, 0, nil; return GuardDecoy(); end;")
					.Replace("__IB2_GUARD_BIND__", "if GuardBindPayload(CurrentInstructionState, CurrentChunkState, EntryState, Index, CurrentOpcodeState, CurrentOpcodeSeal) then return GuardDecoy(); end;");
			}
			else
			{
				blockRuntime = blockRuntime
					.Replace("__IB2_FIRST_BLOCK_CHECK__", "")
					.Replace("__IB2_GUARD_BIND__", "");
			}
			for (int mode = 0; mode < materializerOpcodes.Length; mode++)
				blockRuntime = blockRuntime.Replace(
					"__IB2_MATERIALIZER_OPCODE_" + mode + "__",
					materializerOpcodes[mode].VIndex.ToString());
			if (Regex.IsMatch(blockRuntime, @"__IB2_MATERIALIZER_OPCODE_\d+__"))
				throw new InvalidOperationException("A materializer opcode placeholder was not replaced.");
			vm += T(ApplyBuildDomains(blockRuntime));

			string loopRuntime = settings.PreserveLineInfo ? (useRepeat ? VMStrings.VMP2_LI_R : VMStrings.VMP2_LI) : (useRepeat ? VMStrings.VMP2_R : VMStrings.VMP2);
			loopRuntime = loopRuntime.Replace("__IB2_GUARD_CHECK__", settings.AntiDump
				? "GuardProbe(false);"
				: "");
			vm += T(loopRuntime);
			vm += T(BuildHandlerFragmentRuntime());

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

			bool NeedsDynamicCallGuard(VOpcode opcode)
			{
				if (opcode is OpAlias alias) return NeedsDynamicCallGuard(alias.Target);
				if (opcode is OpMutated mutated) return NeedsDynamicCallGuard(mutated.Mutated);
				string name = opcode.GetType().Name;
				return name.StartsWith("OpCall", StringComparison.Ordinal)
				       || name.StartsWith("OpTailCall", StringComparison.Ordinal);
			}

			string BuildHandler(int opcodeIndex)
			{
				string code = virtuals[opcodeIndex].GetObfuscated(_context);
				if (settings.AntiDump && NeedsDynamicCallGuard(virtuals[opcodeIndex]))
					code = "Stk[Inst[OP_A]]=GuardValidateCallTarget(Stk[Inst[OP_A]]);" + code;
				code = ApplySemanticPolymorphism(code);
				code = ApplyHandlerFragmentSharing(code);
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
			const string rootInvocation = "return Wrap(Root, {}, GetFEnv());";
			if (!finalRuntime.Contains(rootInvocation, StringComparison.Ordinal))
				throw new InvalidOperationException("VM root invocation anchor is missing.");
			const string disableGlobalRuntime = @"
local DisabledGlobalFunction = function(...) return nil; end;
local DisabledGlobalEnvironment = PrimitiveEnvironment;
local DisabledEnvironmentOK, DisabledEnvironmentCandidate = PCall(GetFEnv);
if DisabledEnvironmentOK and Type(DisabledEnvironmentCandidate) == 'table' then
    DisabledGlobalEnvironment = DisabledEnvironmentCandidate;
end;
local DisabledGlobalTargets = {};
local function DisabledEnvironmentRead(DisabledEnvironmentCandidate, DisabledErrorKey)
    if Type(DisabledEnvironmentCandidate) ~= 'table' then return nil; end;
    local DisabledEnvironmentValue = RawGet(DisabledEnvironmentCandidate, DisabledErrorKey);
    if DisabledEnvironmentValue ~= nil then return DisabledEnvironmentValue; end;
    local DisabledIndexedOK, DisabledIndexedValue = PCall(function()
        return DisabledEnvironmentCandidate[DisabledErrorKey];
    end);
    if DisabledIndexedOK then return DisabledIndexedValue; end;
    return nil;
end;
local DisabledPrintKey = Char(112) .. Char(114) .. Char(105) .. Char(110) .. Char(116);
local DisabledErrorKey = Char(101) .. Char(114) .. Char(114) .. Char(111) .. Char(114);
local DisabledWarnKey = Char(119) .. Char(97) .. Char(114) .. Char(110);
local DisabledGetGenVKey = Char(103) .. Char(101) .. Char(116) .. Char(103) .. Char(101) .. Char(110) .. Char(118);
local DisabledRootKey = Char(95) .. Char(71);
local function DisableGlobalTarget(DisabledGlobalCandidate)
    if Type(DisabledGlobalCandidate) ~= 'table' then return; end;
    for DisabledGlobalIndex = 1, #DisabledGlobalTargets do
        if RawEqual(DisabledGlobalTargets[DisabledGlobalIndex], DisabledGlobalCandidate) then return; end;
    end;
    DisabledGlobalTargets[#DisabledGlobalTargets + 1] = DisabledGlobalCandidate;
    RawSet(DisabledGlobalCandidate, DisabledPrintKey, DisabledGlobalFunction);
    RawSet(DisabledGlobalCandidate, DisabledErrorKey, DisabledGlobalFunction);
    RawSet(DisabledGlobalCandidate, DisabledWarnKey, DisabledGlobalFunction);
end;
local DisabledGetGenV = DisabledEnvironmentRead(DisabledGlobalEnvironment, DisabledGetGenVKey);
if Type(DisabledGetGenV) == 'function' then
    local DisabledGetGenVOK, DisabledGlobalCandidate = PCall(DisabledGetGenV);
    if DisabledGetGenVOK then DisableGlobalTarget(DisabledGlobalCandidate); end;
end;
DisableGlobalTarget(DisabledEnvironmentRead(DisabledGlobalEnvironment, DisabledRootKey));
DisableGlobalTarget(DisabledGlobalEnvironment);
return Wrap(Root, {}, DisabledGlobalEnvironment);";
			finalRuntime = finalRuntime.Replace(rootInvocation, disableGlobalRuntime);
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
			int[] chunkSlots = GenerateRuntimeSlotPermutation(16);
			int[] blockSlots = GenerateRuntimeSlotPermutation(10);
			int[] flowSlots = GenerateRuntimeSlotPermutation(4);
			int[] flowCacheSlots = GenerateRuntimeSlotPermutation(7);
			vm = ApplyRuntimeSlotPermutation(vm, idents["Chunk"], chunkSlots);
			foreach (string blockAlias in new[] {"Block", "CurrentBlock", "NextBlock", "SuccessorBlock"})
				vm = ApplyRuntimeSlotPermutation(vm, idents[blockAlias], blockSlots);
			vm = ApplyRuntimeSlotPermutation(vm, idents["Flow"], flowSlots);
			vm = ApplyRuntimeSlotPermutation(vm, idents["FlowCache"], flowCacheSlots);

			// Apply the selected carrier topology only after the nested Flow ABI was
			// permuted, so accesses such as Frame[x][flowSlot] stay consistent with
			// helper functions that still receive Flow as a direct parameter.
			vm = ApplyVMLayout(vm, vmLayout);
			Console.WriteLine("Semantic lowering: writes=" + string.Join(",", semanticWriteVariants)
				+ "; raw-stack-reads=" + semanticRawStackReads
				+ "; raw-environment-reads=" + semanticRawEnvironmentReads + ".");
			Console.WriteLine("Handler fragments: stack-read=" + handlerFragmentReadCalls
				+ "; environment-read=" + handlerFragmentEnvironmentCalls
				+ "; writeback=" + handlerFragmentWriteCalls
				+ "; binary=" + handlerFragmentBinaryCalls
				+ "; unary=" + handlerFragmentUnaryCalls
				+ "; pc=" + handlerFragmentPcCalls + ".");

			return vm;
		}
	}
}
