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

		private static readonly string FN = RN(5, 10);

		// 把字符串转成 Lua 的 _s(字节...) 调用形式(产物中无明文)
		private static string S(string s)
		{
			var sb = new StringBuilder("_s(");
			for (int i = 0; i < s.Length; i++)
			{
				if (i > 0) sb.Append(",");
				sb.Append((int) s[i]);
			}
			sb.Append(")");
			return sb.ToString();
		}

		public static string GenerateSourceBlock()
		{
			var sb = new StringBuilder();
			sb.Append("do\n");

			// Freeze function —— 随机多模式,避免被 dump 工具模式匹配统一替换
			// (死循环被识别成 infinitelooperror 替换;换用多种形态:循环变体/递归/error/内存膨胀)
			int fm = R.Next(0, 4);
			switch (fm)
			{
				case 0: // 循环变体(随机一种死循环形态)
				{
					int lv = R.Next(0, 3);
					if (lv == 0)
					{
						sb.Append("local function "); sb.Append(FN); sb.Append("()local _m={};for _mi=1,500 do _m[_mi]={}end;repeat until false end\n");
					}
					else if (lv == 1)
					{
						sb.Append("local function "); sb.Append(FN); sb.Append("()while true do end end\n");
					}
					else
					{
						sb.Append("local function "); sb.Append(FN); sb.Append("()for _m=1,math.huge do end end\n");
					}
					break;
				}
				case 1: // 无限递归(栈溢出终止)
				{
					string rn = RN(3, 6);
					sb.Append("local " + rn + ";local function "); sb.Append(FN); sb.Append("()" + rn + "() end;" + rn + "=" + FN + ";" + rn + "() end\n");
					break;
				}
				case 2: // error 抛错终止
					sb.Append("local function "); sb.Append(FN); sb.Append("()error(\"" + RN(5, 9) + "\") end\n");
					break;
				default: // 内存膨胀(耗尽内存终止)
					sb.Append("local function "); sb.Append(FN); sb.Append("()local _t={};for _i=1,9999999 do _t[_i]={}end end\n");
					break;
			}

			// ===== 执行器特征检测 =====
			// 仅在检测到第三方执行器 API(getgenv/loadstring/identifyexecutor 等)时放行;
			// 纯 Roblox 原生环境没有这些,模拟器/沙箱也不会有 → 冻结。
			// 直接全局引用(兼容 Lua 5.1 / Luau 执行器环境)。
			// 执行器专有 API(getgenv/identifyexecutor 等)——Lua 5.1 标准库和纯 Roblox 都没有;
			// 注意不能用 loadstring(Lua 5.1 标准库自带,会误判)
			// 用直接 if 判断(不用 pcall 闭包:VM 内递归执行匿名函数有兼容问题,且此处读取全局+type 不会抛错)
			string[] exeApis = { "getgenv", "identifyexecutor", "getexecutorname", "isexecutorclosure", "getscriptbytecode", "syn" };
			sb.Append("local _ok=false;\n");
			foreach (string api in exeApis)
			{
				sb.Append("if not _ok and " + api + " and type(" + api + ")==" + (api == "syn" ? "\"table\"" : "\"function\"") + " then _ok=true end\n");
			}
			sb.Append("if not _ok then "); sb.Append(FN); sb.Append("() end\n");

			// ===== 反调试检测(库函数被包装/篡改 → 冻结)=====
			// 执行器 hook 环境函数偷数据时通常保持行为(难防),但替换/破坏库函数时行为会变;
			// 只做"行为验证 + 元表痕迹"两级检测,发现异常直接冻结。
			// 注意:只 pcall C 函数(不用 pcall(匿名函数),VM 内递归匿名闭包有兼容问题)
			sb.Append("local _okb,_r1=pcall(string.byte,\"A\");if not(_okb and _r1==65)then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _okc,_r2=pcall(string.char,65);if not(_okc and _r2==\"A\")then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _oks,_r3=pcall(string.sub,\"abc\",1,2);if not(_oks and _r3==\"ab\")then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _okt,_r4=pcall(table.concat,{\"a\",\"b\"});if not(_okt and _r4==\"ab\")then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _okl,_r5=pcall(math.ldexp,1,0);if not(_okl and _r5==1)then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _okn,_r6=pcall(tonumber,\"5\");if not(_okn and _r6==5)then "); sb.Append(FN); sb.Append("() end\n");
			sb.Append("local _oks2,_r7=pcall(select,\"#\",1,2);if not(_oks2 and _r7==2)then "); sb.Append(FN); sb.Append("() end\n");

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
