using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;
using IronBrew2.Obfuscator.AntiDump;
using IronBrew2.Obfuscator.Control_Flow;
using IronBrew2.Obfuscator.Encryption;
using IronBrew2.Obfuscator.VM_Generation;

namespace IronBrew2
{
	public static class IB2
	{
		public static Random Random = new Random();
		private static Encoding _fuckingLua = Encoding.GetEncoding(28591);

		public static string FindTool(params string[] candidates)
		{
			string pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
			string[] exts = { "", ".exe", ".bat", ".cmd" };

			foreach (string candidate in candidates)
				foreach (string dir in pathVar.Split(Path.PathSeparator))
				{
					if (dir.Trim().Length == 0)
						continue;

					foreach (string ext in exts)
					{
						string full = Path.Combine(dir.Trim(), candidate + ext);
						if (File.Exists(full))
							return full;
					}
				}

			return null;
		}

		public static bool Obfuscate(string path, string input, ObfuscationSettings settings, out string error)
		{
			try
			{
				error = "";

				string luacPath = FindTool("luac", "luac5.1", "luac.exe")
					?? throw new Exception("luac (Lua 5.1 compiler) not found in PATH.");
				string luaRunner = FindTool("luajit", "lua", "lua5.1", "lua.exe")
					?? throw new Exception("luajit or lua not found in PATH.");

				string luasrcdiet = Path.Combine(AppContext.BaseDirectory, "Lua", "Minifier", "luasrcdiet.lua");
				if (!File.Exists(luasrcdiet))
					luasrcdiet = Path.Combine(Directory.GetCurrentDirectory(), "Lua", "Minifier", "luasrcdiet.lua");
				if (!File.Exists(luasrcdiet))
					throw new Exception("luasrcdiet.lua not found (expected under Lua/Minifier/).");

				string l = Path.Combine(path, "luac.out");

				if (!File.Exists(input))
					throw new Exception("Invalid input file.");

				Console.WriteLine("Checking file...");
				
				Process proc = new Process
				       {
					       StartInfo =
					       {
						       FileName  = luacPath,
						       Arguments = "-o \"" + l + "\" \"" + input + "\"",
						       UseShellExecute = false,
						       RedirectStandardError = true,
						       RedirectStandardOutput = true
					       }
				       };

				string err = "";
				
				proc.OutputDataReceived += (sender, args) => { err += args.Data; };
				proc.ErrorDataReceived += (sender, args) => { err += args.Data; };

				proc.Start();
				proc.BeginOutputReadLine();
				proc.BeginErrorReadLine();
				proc.WaitForExit();

				error = err;
				
				if (!File.Exists(l))
					return false;
				
				File.Delete(l);
				string t0 = Path.Combine(path, "t0.lua");
				
				Console.WriteLine("Stripping comments...");

				proc = new Process
				       {
					       StartInfo =
					       {
						       FileName = luaRunner,
						       Arguments =
							       "\"" + luasrcdiet + "\" --noopt-whitespace --noopt-emptylines --noopt-numbers --noopt-locals --noopt-strings --opt-comments \"" +
							       input                                                       +
							       "\" -o \""                                                  + t0 + "\"",
						       UseShellExecute        = false,
						       RedirectStandardError  = true,
						       RedirectStandardOutput = true
					       }
				       };

				proc.OutputDataReceived += (sender, args) => { err += args.Data; };
				proc.ErrorDataReceived  += (sender, args) => { err += args.Data; };

				proc.Start();
				proc.BeginOutputReadLine();
				proc.BeginErrorReadLine();
				proc.WaitForExit();

				error = err;

				if (!File.Exists(t0))
					return false;

				string t1 = Path.Combine(path, "t1.lua");
				
				Console.WriteLine("Compiling...");

				var _t1src = new ConstantEncryption(settings, File.ReadAllText(t0, _fuckingLua)).EncryptStrings(); Console.WriteLine("DBG t1 len=" + _t1src.Length + " enc=" + _t1src.Contains("((function(b)") + " sEnc=" + settings.EncryptStrings); File.WriteAllText(t1, _t1src, _fuckingLua);
				proc = new Process
				       {
					       StartInfo =
					       {
						       FileName  = luacPath,
						       Arguments = "-o \"" + l + "\" \"" + t1 + "\"",
						       UseShellExecute = false,
						       RedirectStandardError = true,
						       RedirectStandardOutput = true
					       }
				       };

				proc.OutputDataReceived += (sender, args) => { err += args.Data; };
				proc.ErrorDataReceived += (sender, args) => { err += args.Data; };

				proc.Start();
				proc.BeginOutputReadLine();
				proc.BeginErrorReadLine();
				proc.WaitForExit();

				error = err;

				if (!File.Exists(l))
					return false;
				
				Console.WriteLine("Obfuscating...");

				Deserializer des    = new Deserializer(File.ReadAllBytes(l));
				Chunk lChunk = des.DecodeFile();

				if (settings.ControlFlow)
				{
					CFContext cf = new CFContext(lChunk);
					cf.DoChunks();
				}

				if (settings.AntiDump)
				{
					// === 防 dump 主动防御块(先合并,guard 之后、主脚本之前执行)===
					// 仅真实执行器环境运行(guard 放行后才执行到);字符串全 string.char 构造。
					Instruction mainFirst = lChunk.Instructions.Count > 0 ? lChunk.Instructions[0] : null;
					string defSrc = DefenseGenerator.GenerateSourceBlock();
					string defLua = Path.Combine(path, "defense_src.lua");
					string defOut = Path.Combine(path, "defense.luac");
					File.WriteAllText(defLua, defSrc, _fuckingLua);

					proc = new Process
					{
						StartInfo =
						{
							FileName = luacPath,
							Arguments = "-o \"" + defOut + "\" \"" + defLua + "\"",
							UseShellExecute = false,
							RedirectStandardError = true,
							RedirectStandardOutput = true
						}
					};
					proc.Start();
					proc.WaitForExit();

					if (File.Exists(defOut))
					{
						Deserializer dd = new Deserializer(File.ReadAllBytes(defOut));
						Chunk defense = dd.DecodeFile();

						// 去掉防护块末尾 RETURN(顺序执行到主脚本);内部 Jmp(若有)指向主脚本
						if (defense.Instructions.Count > 0 && defense.Instructions[defense.Instructions.Count - 1].OpCode == Opcode.Return)
						{
							Instruction ret = defense.Instructions[defense.Instructions.Count - 1];
							defense.Instructions.RemoveAt(defense.Instructions.Count - 1);
							foreach (Instruction di in defense.Instructions)
								if (di.RefOperands[0] == ret)
									di.RefOperands[0] = mainFirst;
						}

						int off1 = lChunk.StackSize;
						defense.Rebase(off1);

						foreach (Constant dc in defense.Constants)
							lChunk.Constants.Add(dc);
						foreach (Chunk df in defense.Functions)
							lChunk.Functions.Add(df);
						foreach (Instruction di in defense.Instructions)
							di.Chunk = lChunk;

						lChunk.Instructions.InsertRange(0, defense.Instructions);
						lChunk.StackSize = (byte) Math.Max(lChunk.StackSize, defense.StackSize);
						lChunk.UpdateMappings();

						// guard 的"检测通过"跳转应落在防护块首指令(而非主脚本)
						mainFirst = lChunk.Instructions.Count > 0 ? lChunk.Instructions[0] : null;
					}

					// P3: 反 dump 引导块编入 VM——不再以源码明文存在于产物。
					// 检测逻辑为"执行器特征"(getgenv 等纯全局读取),不依赖 Roblox API。
					string guardSrc = AntiDumpGenerator.GenerateSourceBlock();
					string guardLua = Path.Combine(path, "guard_src.lua");
					string guardOut = Path.Combine(path, "guard.luac");
					File.WriteAllText(guardLua, guardSrc, _fuckingLua);

					proc = new Process
					{
						StartInfo =
						{
							FileName = luacPath,
							Arguments = "-o \"" + guardOut + "\" \"" + guardLua + "\"",
							UseShellExecute = false,
							RedirectStandardError = true,
							RedirectStandardOutput = true
						}
					};
					proc.Start();
					proc.WaitForExit();

					if (File.Exists(guardOut))
					{
						Deserializer gd = new Deserializer(File.ReadAllBytes(guardOut));
						Chunk guard = gd.DecodeFile();

						// 去掉 guard chunk 末尾的 RETURN:luac 编译 do...end 块会自动补 return。
						// 同时把引用该 RETURN 的 Jmp(检测通过时的跳转)重定向到防护块/主脚本首指令,
						// 否则 Jmp 目标悬空 → UpdateRegisters 抛 KeyNotFound
						if (guard.Instructions.Count > 0 && guard.Instructions[guard.Instructions.Count - 1].OpCode == Opcode.Return)
						{
							Instruction ret = guard.Instructions[guard.Instructions.Count - 1];
							guard.Instructions.RemoveAt(guard.Instructions.Count - 1);
							foreach (Instruction gi in guard.Instructions)
								if (gi.RefOperands[0] == ret)
									gi.RefOperands[0] = mainFirst;
						}

						// 寄存器平移:guard 用到主脚本栈顶之上,避免寄存器冲突
						int offset = lChunk.StackSize;
						guard.Rebase(offset);

						// 常量/子函数/指令合并进主 chunk(对象引用不变,UpdateMappings 后索引正确)
						foreach (Constant gc in guard.Constants)
							lChunk.Constants.Add(gc);
						foreach (Chunk gf in guard.Functions)
							lChunk.Functions.Add(gf);
						foreach (Instruction gi in guard.Instructions)
							gi.Chunk = lChunk;

						lChunk.Instructions.InsertRange(0, guard.Instructions);
						lChunk.StackSize = (byte) Math.Max(lChunk.StackSize, guard.StackSize);
						lChunk.UpdateMappings();
					}
				}

				Console.WriteLine("Serializing...");
				
				//shuffle stuff
				//lChunk.Constants.Shuffle();
				//lChunk.Functions.Shuffle();

				ObfuscationContext context = new ObfuscationContext(lChunk, settings);

				string t2 = Path.Combine(path, "t2.lua");
				string c = new Generator(context).GenerateVM(settings);

				//string byteLocal = c.Substring(null, "\n");
				//string rest = c.Substring("\n");

				File.WriteAllText(t2, c, _fuckingLua);

				string t3 = Path.Combine(path, "t3.lua");
				
				Console.WriteLine("Minifying...");
				
				proc = new Process
				       {
					       StartInfo =
					       {
						       FileName = luaRunner,
						       Arguments =
							       "\"" + luasrcdiet + "\" --maximum --opt-entropy --opt-emptylines --opt-eols --opt-numbers --opt-whitespace --opt-locals --noopt-strings \"" +
							       t2                                                                                                                                                +
							       "\" -o \"" + 
							        t3 + 
							       "\""
								,
					       }
				       };

				proc.Start();
				proc.WaitForExit();

				if (!File.Exists(t3))
					return false;
				
				File.WriteAllText(Path.Combine(path, "out.lua"), File.ReadAllText(t3, _fuckingLua).Replace("\n", " "), _fuckingLua);
				
				return true;
			}
			catch (Exception e)
			{
				Console.WriteLine("ERROR");
				Console.WriteLine(e);

				error = e.ToString();
				return false;
			}
		}
	}
}