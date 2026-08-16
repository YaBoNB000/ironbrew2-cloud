using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;
using IronBrew2.Obfuscator.Control_Flow;
using IronBrew2.Obfuscator.Encryption;
using IronBrew2.Obfuscator.VM_Generation;

namespace IronBrew2
{
	public static class IB2
	{
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
				using BuildSeed buildSeed = new BuildSeed();

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

				// LuaSrcDiet loads sibling modules with require(). Make module resolution
				// independent of the caller's current working directory.
				proc.StartInfo.Environment["LUA_PATH"] =
					Path.Combine(Path.GetDirectoryName(luasrcdiet) ?? ".", "?.lua") + ";;";
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

				var t1Source = new ConstantEncryption(settings, File.ReadAllText(t0, _fuckingLua),
					buildSeed.GetStream("constant-encryption")).EncryptStrings();
				File.WriteAllText(t1, t1Source, _fuckingLua);
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
					CFContext cf = new CFContext(lChunk, buildSeed.GetStream("control-flow"));
					cf.DoChunks();
				}

				// AntiDump is implemented inside the generated VM so its state is coupled
				// to payload decoding and invocation-local instruction flow. No source chunk
				// is prepended and no executor global is modified.

				Console.WriteLine("Serializing...");
				
				//shuffle stuff
				//lChunk.Constants.Shuffle();
				//lChunk.Functions.Shuffle();

				ObfuscationContext context = new ObfuscationContext(lChunk, settings, buildSeed);

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

				proc.StartInfo.Environment["LUA_PATH"] =
					Path.Combine(Path.GetDirectoryName(luasrcdiet) ?? ".", "?.lua") + ";;";
				proc.Start();
				proc.WaitForExit();

				if (proc.ExitCode != 0 || !File.Exists(t3))
					throw new Exception("LuaSrcDiet final minification failed.");
				
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