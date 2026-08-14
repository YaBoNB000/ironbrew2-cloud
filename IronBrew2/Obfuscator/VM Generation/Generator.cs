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
			Random r = new Random();
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
			Random                r       = new Random();

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
		
		public string GenerateVM(ObfuscationSettings settings)
		{
			Random r = new Random();

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

			string vm = "";

			// ==== P1: 模板标识符随机化(每次混淆生成不同的 VM 结构名)====
			string[] identKeys = {
				"ByteString","InstrPoint","GetFEnv","Setmetatable","ToNumber","ConstCount","Deserialize",
				"Wrap","Upvalues","NewProto","Indexes","Concat","Insert","LDExp","Select","Unpack",
				"BitXOR","gBits32","gBits8","gBits16","gFloat","gSizet","gString","gInt","Byte","Char","Sub",
				"gBit","Instrs","Functions","Lines","Consts","Instr","Proto","Params","Top","Vararg","Args",
				"PCount","Lupvals","Stk","Inst","Enum","Chunk","decompress","Pos","Xs","Xd","_R","Env",
				"Varargsz","PCall","Loop","Const","RA","RB","K1","K2"
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
				.Replace("CONST_BOOL", _context.ConstantMapping[1].ToString())
				.Replace("CONST_FLOAT", _context.ConstantMapping[2].ToString())
				.Replace("CONST_STRING", _context.ConstantMapping[3].ToString())
				// 环境绑定：注入种子派生代码（读盐 → 跑探针 → Hash 派生 Xs）
				.Replace("__IB2_SEED__", settings.EnvironmentLock ? _context.Binder.SeedDeriveLua : EnvBinder.PlainSeedLua));
			
			for (int i = 0; i < (int) ChunkStep.StepCount; i++)
			{
				switch (_context.ChunkSteps[i])
				{
					case ChunkStep.ParameterCount:
						vm += T("Chunk[3] = gBits8();");
						break;
					case ChunkStep.Instructions:
						vm += T(
							$@"for Idx=1,gBits32() do 
									local Descriptor = gBits8();
									if (gBit(Descriptor, 1, 1) == 0) then
										local Type = gBit(Descriptor, 2, 3);
										local Mask = gBit(Descriptor, 4, 6);
										
										local Inst=
										{{
											gBits16(),
											gBits16(),
											nil,
											nil
										}};
	
										if (Type == 0) then 
											Inst[OP_B] = gBits16(); 
											Inst[OP_C] = gBits16();
										elseif(Type==1) then 
											Inst[OP_B] = gBits32();
										elseif(Type==2) then 
											Inst[OP_B] = gBits32() - (2 ^ 16)
										elseif(Type==3) then 
											Inst[OP_B] = gBits32() - (2 ^ 16)
											Inst[OP_C] = gBits16();
										end;
	
										if (gBit(Mask, 1, 1) == 1) then Inst[OP_A] = Consts[Inst[OP_A]] end
										if (gBit(Mask, 2, 2) == 1) then Inst[OP_B] = Consts[Inst[OP_B]] end
										if (gBit(Mask, 3, 3) == 1) then Inst[OP_C] = Consts[Inst[OP_C]] end
										
										Instrs[Idx] = Inst;
									end
								end;");
						break;
					case ChunkStep.Functions:
						vm += T("for Idx=1,gBits32() do Functions[Idx-1]=Deserialize();end;");
						break;
					case ChunkStep.LineInfo:
						if (settings.PreserveLineInfo)
							vm += T("for Idx=1,gBits32() do Lines[Idx]=gBits32();end;");
						break;
				}
			}

			vm += T("return Chunk;end;");

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
			
			string GetStr(List<int> opcodes)
			{
				string str = "";
				
				if (opcodes.Count == 1)
				{
					string code = T(virtuals[opcodes[0]].GetObfuscated(_context));
					code = ScrambleOps(code);
					if (settings.Noise)
						code = FlattenCode(code);
					str += code;
					if (settings.Noise)
						str += AntiDumpGenerator.GenerateHandlerNoise();
				}

				else if (opcodes.Count == 2) 
				{
					string h0 = T(virtuals[opcodes[0]].GetObfuscated(_context));
					string h1 = T(virtuals[opcodes[1]].GetObfuscated(_context));
					h0 = ScrambleOps(h0);
					h1 = ScrambleOps(h1);
					if (settings.Noise)
					{
						h0 = FlattenCode(h0);
						h1 = FlattenCode(h1);
					}
					if (r.Next(2) == 0)
					{
						str += T("if Enum > ") + ScrambleNumber(virtuals[opcodes[0]].VIndex) + " then " + h1;
						if (settings.Noise)
							str += AntiDumpGenerator.GenerateHandlerNoise();
						str += "else " + h0;
						if (settings.Noise)
							str += AntiDumpGenerator.GenerateHandlerNoise();
						str += "end;";
					}
					else
					{
						str += T("if Enum == ") + ScrambleNumber(virtuals[opcodes[0]].VIndex) + " then " + h0;
						if (settings.Noise)
							str += AntiDumpGenerator.GenerateHandlerNoise();
						str += "else " + h1;
						if (settings.Noise)
							str += AntiDumpGenerator.GenerateHandlerNoise();
						str += "end;";
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
