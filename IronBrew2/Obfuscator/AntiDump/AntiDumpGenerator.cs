using System;
using System.Collections.Generic;
using System.Text;

namespace IronBrew2.Obfuscator.AntiDump
{
	public static class AntiDumpGenerator
	{
		private static readonly Random R = new Random();
		private static string RN(int min, int max)
		{
			const string cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
			int len = R.Next(min, max + 1);
			char[] n = new char[len];
			n[0] = cs[R.Next(cs.Length)];
			for (int i = 1; i < len; i++)
				n[i] = (R.Next(2) == 0) ? (char)('0' + R.Next(10)) : cs[R.Next(cs.Length)];
			return new string(n);
		}


		public static string GenerateSourceBlock()
		{
			// 兼容模式 guard：不再生成递归/死循环/内存膨胀闭包。
			// 这些闭包会增加 VM upvalue，并在不同执行器中导致寄存器错位、nil 比较或卡死。
			// 检测失败时返回明确错误；EnvironmentLock 仍负责阻止离线解密。
			var sb = new StringBuilder();
			sb.Append("do\n");
			sb.Append("local _ok=false;\n");

			string[] exeApis = { "getgenv", "identifyexecutor", "getexecutorname", "isexecutorclosure", "getscriptbytecode", "syn" };
			foreach (string api in exeApis)
				sb.Append("if not _ok and " + api + " and type(" + api + ")==" + (api == "syn" ? "\"table\"" : "\"function\"") + " then _ok=true end\n");

			sb.Append("if not _ok then error(\"unsupported executor environment\",0) end\n");
			sb.Append("local _a,_b=pcall(string.byte,\"A\");if not(_a and _b==65)then error(\"environment integrity check failed\",0)end\n");
			sb.Append("local _c,_d=pcall(string.char,65);if not(_c and _d==\"A\")then error(\"environment integrity check failed\",0)end\n");
			sb.Append("local _e,_f=pcall(string.sub,\"abc\",1,2);if not(_e and _f==\"ab\")then error(\"environment integrity check failed\",0)end\n");
			sb.Append("local _g,_h=pcall(table.concat,{\"a\",\"b\"});if not(_g and _h==\"ab\")then error(\"environment integrity check failed\",0)end\n");
			sb.Append("end\n");
			return sb.ToString();
		}

		public static string GenerateHandlerNoise()
		{
			// 注意:不能有 getfenv/_G 环境写入——执行器 hook getfenv/观察 _G 写入会记录这些噪音键,
			// dump 出一堆 fenv["key"]=true。只用纯计算噪音(无外部副作用)。
			var parts = new List<string>();
			var exprs = new[] { "string.byte(\"A\")==65", "#{\"x\"}==1", "(-1<0)==true", "tostring(1)==\"1\"" };
			parts.Add("local " + RN(4, 8) + "=(" + exprs[R.Next(4)] + ")");
			var fn = RN(5, 8);
			parts.Add("local function " + fn + "(...)local _={...};return #_ end;" + fn + "(1,2,3);" + fn + "=nil");
			return "\t" + string.Join(";", parts) + ";\n";
		}

		public static string GenerateLoopNoise()
		{
			// 纯计算噪音(无 getfenv/_G 环境写入,防执行器记录噪音键)
			var mod = new[] { 7, 11, 13, 17, 19 }[R.Next(5)];
			var sb = new StringBuilder();
			sb.Append("\tif (InstrPoint%"); sb.Append(mod); sb.Append("==0) then\n");
			sb.Append("\t\tlocal _lt={};for _li=1,20 do _lt[_li]={_li}end;\n");
			sb.Append("\tend;\n");
			return sb.ToString();
		}
	}
}
