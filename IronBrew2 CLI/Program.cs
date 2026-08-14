using System;
using System.IO;
using System.Text;
using IronBrew2;
using IronBrew2.Obfuscator;

namespace IronBrew2_CLI
{
	class Program
	{
		static int Main(string[] args)
		{
			if (args.Length < 1)
			{
				Console.WriteLine("Usage: IronBrew2 CLI <input.lua> [--no-antidump] [--strength low|mid|high]");
				return 2;
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
							// 兼容性优先：保留环境绑定、AntiDump guard、Opcode 随机化以及
							// 字节码正文的 DEFLATE + 流式 XOR；关闭不稳定的源码解密闭包和实验性变换。
							settings.Mutate = false;
							settings.SuperOperators = false;
							settings.Noise = false;
							settings.EncryptStrings = false;
							settings.EncryptImportantStrings = false;
							settings.ControlFlow = true;
							settings.BytecodeCompress = true;
							break;

						default: // "mid": balanced and executor-compatible
							settings.Mutate = false;
							settings.SuperOperators = false;
							settings.Noise = false;
							settings.EncryptStrings = false;
							settings.EncryptImportantStrings = false;
							break;
					}
				}
			}

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