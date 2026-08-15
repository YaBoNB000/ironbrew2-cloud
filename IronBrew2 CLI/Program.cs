using System;
using System.IO;
using IronBrew2;
using IronBrew2.Obfuscator;

namespace IronBrew2_CLI
{
	class Program
	{
		private static void PrintUsage()
		{
			Console.WriteLine("Usage: IronBrew2 CLI <input.lua> [--line-info]");
		}

		private static ObfuscationSettings CreateSettings(bool preserveLineInfo)
		{
			// Single supported profile. VM-integrated anti-debug/anti-dump defense is
			// enabled; destructive executor hooks and the strict Roblox fingerprint gate
			// remain disabled.
			return new ObfuscationSettings
			{
				Mutate = false,
				SuperOperators = false,
				EncryptStrings = false,
				EncryptImportantStrings = false,
				AggressiveDefense = false,
				Noise = false,
				AntiDump = true,
				EnvironmentLock = false,
				ControlFlow = true,
				BytecodeCompress = true,
				PreserveLineInfo = preserveLineInfo
			};
		}

		static int Main(string[] args)
		{
			if (args.Length < 1)
			{
				PrintUsage();
				return 2;
			}

			bool preserveLineInfo = false;
			for (int i = 1; i < args.Length; i++)
			{
				if (args[i] == "--line-info")
					preserveLineInfo = true;
				else
				{
					Console.WriteLine("ERR: unknown option: " + args[i]);
					PrintUsage();
					return 2;
				}
			}

			ObfuscationSettings settings = CreateSettings(preserveLineInfo);

			if (Directory.Exists("temp"))
				Directory.Delete("temp", true);
			Directory.CreateDirectory("temp");

			if (!IB2.Obfuscate("temp", args[0], settings, out string err))
			{
				Console.WriteLine("ERR: " + err);
				return 1;
			}

			File.Delete("out.lua");
			File.Move("temp/out.lua", "out.lua");
			Console.WriteLine("Done!");
			return 0;
		}
	}
}
