using System;
using System.IO;
using System.Text;
using IronBrew2;
using IronBrew2.Obfuscator;

namespace IronBrew2_CLI
{
	class Program
	{
		static void Main(string[] args)
		{
			if (args.Length < 1)
			{
				Console.WriteLine("Usage: IronBrew2 CLI <input.lua> [--no-antidump] [--strength low|mid|high]");
				return;
			}

			if (Directory.Exists("temp"))
				Directory.Delete("temp", true);
			Directory.CreateDirectory("temp");

			ObfuscationSettings settings = new ObfuscationSettings();

			for (int i = 1; i < args.Length; i++)
			{
				if (args[i] == "--no-antidump")
					settings.AntiDump = false;

				else if (args[i] == "--strength" && i + 1 < args.Length)
				{
					switch (args[++i])
					{
						case "low":
							settings.AntiDump = false;
							settings.EnvironmentLock = false;
							settings.Mutate = false;
							settings.SuperOperators = false;
							settings.EncryptStrings = false;
							settings.EncryptImportantStrings = false;
							settings.ControlFlow = true;
							settings.Noise = false;
							break;

						case "high":
							settings.Mutate = true;
							settings.SuperOperators = true;
							settings.EncryptStrings = true;
							settings.EncryptImportantStrings = true;
							settings.ControlFlow = true;
							settings.BytecodeCompress = true;
							settings.MaxMutations = 400;
							settings.MaxMegaSuperOperators = 240;
							settings.MaxMiniSuperOperators = 240;
							break;

						default: // "mid": keep defaults (balanced)
							settings.EncryptStrings = true;
							settings.EncryptImportantStrings = true;
							break;
					}
				}
			}

			if (!IB2.Obfuscate("temp", args[0], settings, out string err))
			{
				Console.WriteLine("ERR: " + err);
				return;
			}

			File.Delete("out.lua");
			File.Move("temp/out.lua", "out.lua");
			Console.WriteLine("Done!");
		}
	}
}