using System;
using System.Text;

namespace IronBrew2.Obfuscator.AntiDump
{
	/// <summary>
	/// 防 dump 主动防御块(学习 Sentinel 风格反调试):
	/// 在 guard 放行后、主脚本前执行,仅真实执行器环境运行。
	/// 核心能力:① 禁用 dump 工具 API;② debug 完整性自检;③ loadstring 内容检测;
	/// ④ 文件路径拦截(保留正常文件读写);⑤ registry/调用栈定时扫描;⑥ 自毁响应。
	/// 重要:所有闭包(hook/定时器)必须零 upvalue —— 数据经 getgenv() 表传递(键为内联字面量),
	/// 规避合并进主 chunk 后 OpClosure 捕获 upvalue 的寄存器错位问题(零 upvalue 走 OpClosureNU 无捕获)。
	/// 敏感字符串以明文写入源码,编译成字节码后由 Serializer 流式 XOR 加密进产物 blob(产物无明文)。
	/// </summary>
	public static class DefenseGenerator
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

		// 字符串 → 明文 Lua 字面量。
		// 反 dump 块会被编译成字节码、合并进主 chunk，再经 Serializer 的流式 XOR 整体加密，
		// 产物 blob 中不含明文；因此源码侧无需 string.char 逐字符编码(那会显著放大字节码)。
		private static string C(string s) => "\"" + s + "\"";

		public static string GenerateSourceBlock()
		{
			var sb = new StringBuilder();
			sb.Append("do\n");

			// 随机名(变量/键)
			string ge = RN(3, 5);
			string kA = "\"" + RN(8, 14) + "\"";   // 黑名单表键
			string kB = "\"" + RN(8, 14) + "\"";   // 自毁函数键
			string kC = "\"" + RN(8, 14) + "\"";   // 原始 loadstring 键
			string kD = "\"" + RN(8, 14) + "\"";   // 扫描词表键
			string kE = "\"" + RN(8, 14) + "\"";   // 路径表键
			string kF = "\"" + RN(8, 14) + "\"";   // 扫描函数键
			string kG = "\"" + RN(8, 14) + "\"";   // writefile 原始键
			string kH = "\"" + RN(8, 14) + "\"";   // readfile 原始键
			string kI = "\"" + RN(8, 14) + "\"";   // listfiles 原始键
			string kJ = "\"" + RN(8, 14) + "\"";   // appendfile 原始键

			// ===== 环境 =====
			sb.Append("local " + ge + "=(getgenv and getgenv()) or _G;\n");

			// ===== 自毁函数(零 upvalue,存 ge)=====
			sb.Append(ge + "[" + kB + "]=function()local _mb={};for _i=1,80000 do _mb[_i]={data=string.rep(" + C("X") + ",200)}end;while true do end end;\n");

			// ===== dump 工具 API 黑名单 → 禁用 =====
			string[] apis = {
				"getscriptbytecode","getscripthash","decompile","dumpstring",
				"getreg","getgc","getconnections","getsenv","getscripts",
				"getcallingscript","getscriptclosure","getscriptfunction",
				"hookfunction","hookmetamethod","replaceclosure","newcclosure",
				"firesignal","getrawmetatable","setrawmetatable",
				"getloadedmodules","getrunningscripts","deobfuscate","seccbreak",
				"getscriptclosure","getgc"
			};
			sb.Append(ge + "[" + kA + "]={");
			for (int i = 0; i < apis.Length; i++)
			{
				if (i > 0) sb.Append(",");
				sb.Append(C(apis[i]));
			}
			sb.Append("};\n");
			sb.Append("for _i=1,#" + ge + "[" + kA + "] do " + ge + "[" + ge + "[" + kA + "][_i]]=nil end;\n");

			// ===== 原始 loadstring 保存(供 hook 内部使用,避免递归)=====
			sb.Append(ge + "[" + kC + "]=" + ge + ".loadstring or loadstring;\n");

			// ===== loadstring 内容检测 hook(零 upvalue:经 ge 取表)=====
			sb.Append(ge + ".loadstring=function(_src,...)local _g=(getgenv and getgenv()) or _G;local _w=_g[" + kA + "];if type(_src)==" + C("string") + "then local _sl=string.lower(_src);local _n=0;for _i=1,#_w do if string.find(_sl,_w[_i],1,true)then _n=_n+1;if _n>=2 then return nil," + C("blocked") + " end end end end;return _g[" + kC + "](_src,...)end;\n");

			// ===== 路径检测表 + 文件 hook(零 upvalue)=====
			string[] paths = { "dump","output","decompile","bytecode","morpa","extract","seccbreak","rawscript","getscript" };
			sb.Append(ge + "[" + kE + "]={");
			for (int i = 0; i < paths.Length; i++)
			{
				if (i > 0) sb.Append(",");
				sb.Append(C(paths[i]));
			}
			sb.Append("};\n");
			sb.Append("local function _pf(_p)local _g=(getgenv and getgenv()) or _G;local _pl=_g[" + kE + "];local _l=string.lower(tostring(_p));for _i=1,#_pl do if string.find(_l,_pl[_i],1,true)then return true end end;if string.find(_l," + C(".lua") + ")or string.find(_l," + C(".txt") + ")then return true end;return false end;\n");
			// _pf 是防护块主 chunk 的 local 函数(非闭包,无 upvalue 捕获——引用全局 + ge)——但 writefile hook 引用 _pf(upvalue!)→ _pf 存 ge
			sb.Append(ge + "[" + kF + "]=_pf;_pf=nil;\n");
			// 保存原始文件函数
			sb.Append(ge + "[" + kG + "]=" + ge + ".writefile;" + ge + "[" + kH + "]=" + ge + ".readfile;" + ge + "[" + kI + "]=" + ge + ".listfiles;" + ge + "[" + kJ + "]=" + ge + ".appendfile;\n");
			// hook:writefile(内容含 ≥2 黑名单词 → 拦截)
			sb.Append("if " + ge + "[" + kG + "]then " + ge + ".writefile=function(_p,_c)local _g=(getgenv and getgenv()) or _G;local _w=_g[" + kA + "];if _g[" + kF + "](_p)then return nil end;if type(_c)==" + C("string") + "then local _sl=string.lower(_c);local _n=0;for _i=1,#_w do if string.find(_sl,_w[_i],1,true)then _n=_n+1;if _n>=2 then return nil end end end end;return _g[" + kG + "](_p,_c)end end;\n");
			sb.Append("if " + ge + "[" + kH + "]then " + ge + ".readfile=function(_p)local _g=(getgenv and getgenv()) or _G;if _g[" + kF + "](_p)then return nil end;return _g[" + kH + "](_p)end end;\n");
			sb.Append("if " + ge + "[" + kI + "]then " + ge + ".listfiles=function(_p)local _g=(getgenv and getgenv()) or _G;if _g[" + kF + "](_p)then return {} end;return _g[" + kI + "](_p)end end;\n");
			sb.Append("if " + ge + "[" + kJ + "]then " + ge + ".appendfile=function(_p,_c)local _g=(getgenv and getgenv()) or _G;local _w=_g[" + kA + "];if _g[" + kF + "](_p)then return nil end;if type(_c)==" + C("string") + "then local _sl=string.lower(_c);local _n=0;for _i=1,#_w do if string.find(_sl,_w[_i],1,true)then _n=_n+1;if _n>=2 then return nil end end end end;return _g[" + kJ + "](_p,_c)end end;\n");

			// ===== debug 完整性自检(同步,引用 ge[kB] 自毁)=====
			sb.Append("local _o1,_i1=pcall(debug.getinfo,print," + C("nS") + ");if not(_o1 and _i1 and _i1.what==" + C("C") + ")then " + ge + "[" + kB + "]()end;\n");
			sb.Append("local _o2,_n2=pcall(debug.getupvalue,print,1);if _o2 and _n2 then " + ge + "[" + kB + "]()end;\n");

			// ===== 扫描词表 + 函数扫描(零 upvalue,存 ge)=====
			string[] scanWords = {
				"deobfuscate","dumpstring","getscriptbytecode","seccbreak",
				"decompile","extract","morpa","dump_file","dump_string",
				"link_spy","getscripthash","dumper","hookfunction"
			};
			sb.Append(ge + "[" + kD + "]={");
			for (int i = 0; i < scanWords.Length; i++)
			{
				if (i > 0) sb.Append(",");
				sb.Append(C(scanWords[i]));
			}
			sb.Append("};\n");
			sb.Append(ge + "[" + kF + "]=function(_f)if type(_f)~=" + C("function") + "then return false end;local _g=(getgenv and getgenv()) or _G;local _sw=_g[" + kD + "];local _ok,_cs=pcall(debug.getconstants,_f);if _ok and type(_cs)==" + C("table") + "then for _i=1,#_cs do local _v=_cs[_i];if type(_v)==" + C("string") + "then local _l=string.lower(_v);for _j=1,#_sw do if string.find(_l,_sw[_j],1,true)then return true end end end end end;local _i=1;while _i<=30 do local _ok2,_n,_v=pcall(debug.getupvalue,_f,_i);if not _ok2 or not _n then break end;if type(_v)==" + C("string") + "then local _l=string.lower(_v);for _j=1,#_sw do if string.find(_l,_sw[_j],1,true)then return true end end end;_i=_i+1 end;local _ok3,_ps=pcall(debug.getprotos,_f);if _ok3 and type(_ps)==" + C("table") + "then for _i=1,#_ps do if _g[" + kF + "](_ps[_i])then return true end end end;return false end;\n");

			// ===== 定时扫描(仅 Luau 有 task;registry + 调用栈)→ 自毁 =====
			int w1 = R.Next(3, 8), w2 = R.Next(2, 6), w4 = R.Next(2, 5);
			sb.Append("if task and task.spawn then task.spawn(function()local _g=(getgenv and getgenv()) or _G;while true do task.wait(" + w1 + "+math.random());local _ok,_reg=pcall(debug.getregistry);if _ok and type(_reg)==" + C("table") + "then local _n=math.min(#_reg,300);for _i=1,_n do if _g[" + kF + "](_reg[_i])then _g[" + kB + "]()return end end end;for _lv=1,12 do local _ok2,_inf=pcall(debug.getinfo,_lv," + C("nS") + ");if not _ok2 or not _inf then break end;local _l=string.lower(tostring(_inf.source or " + C("") + "));for _j=1,#_g[" + kD + "] do if string.find(_l,_g[" + kD + "][_j],1,true)then _g[" + kB + "]()return end end end;end end);end;\n");
			// 额外守护:环境完整性轮询
			sb.Append("if task and task.spawn then task.spawn(function()local _g=(getgenv and getgenv()) or _G;while true do task.wait(" + w4 + ");local _o1,_i1=pcall(debug.getinfo,print," + C("nS") + ");if not(_o1 and _i1 and _i1.what==" + C("C") + ")then _g[" + kB + "]()return end;local _o2,_n2=pcall(debug.getupvalue,print,1);if _o2 and _n2 then _g[" + kB + "]()return end;end end);end;\n");

			sb.Append("end\n");
			return sb.ToString();
		}
	}
}
