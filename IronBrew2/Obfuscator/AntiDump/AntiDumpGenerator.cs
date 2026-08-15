using System;
using System.Collections.Generic;
using System.Text;

namespace IronBrew2.Obfuscator.AntiDump
{
	/// <summary>
	/// Generates capability-gated runtime integrity probes and side-effect-free VM noise.
	/// The guard never mutates executor globals and never allocates an unbounded amount of
	/// memory. A high-confidence signal is consumed by the generated VM as a silent decoy
	/// route instead of exposing a distinct "blocked" error.
	/// </summary>
	public static class AntiDumpGenerator
	{
		private static readonly Random R = new Random(System.Security.Cryptography.RandomNumberGenerator.GetInt32(int.MaxValue));

		private static string RN(int min, int max)
		{
			const string cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
			int len = R.Next(min, max + 1);
			char[] n = new char[len];
			n[0] = cs[R.Next(cs.Length)];
			for (int i = 1; i < len; i++)
				n[i] = R.Next(2) == 0 ? (char)('0' + R.Next(10)) : cs[R.Next(cs.Length)];
			return new string(n);
		}

		/// <summary>
		/// Builds the guard that is embedded directly into the generated VM. Roblox/Luau
		/// capabilities are optional: ordinary Lua remains a valid execution environment,
		/// while iscclosure/islclosure and debug.gethook are used when the host exposes them.
		/// </summary>
		public static string GenerateRuntimeGuard(int probeInterval, uint decoySeed)
		{
			if (probeInterval < 16)
				throw new ArgumentOutOfRangeException(nameof(probeInterval));

			return @"
local Type = type;
local PCall = pcall;
local GuardString = string;
local GuardTable = table;
local GuardMath = math;
local GuardDebug = debug;
local GuardGetHook = GuardDebug and GuardDebug.gethook;
local GuardEnvOK, GuardEnvironment = PCall(GetFEnv);
if not GuardEnvOK or Type(GuardEnvironment) ~= 'table' then GuardEnvironment = nil; end;
local GuardIsC = GuardEnvironment and GuardEnvironment.iscclosure;
local GuardIsL = GuardEnvironment and GuardEnvironment.islclosure;
if Type(GuardIsC) ~= 'function' then GuardIsC = nil; end;
if Type(GuardIsL) ~= 'function' then GuardIsL = nil; end;
local GuardCounter = 0;
local GuardTripped = false;

local function GuardProbe(Force)
    GuardCounter = GuardCounter + 1;
    if GuardTripped then return true; end;
    if not Force and GuardCounter % __IB2_GUARD_INTERVAL__ ~= 0 then return false; end;

    if string ~= GuardString or table ~= GuardTable or math ~= GuardMath
        or pcall ~= PCall or type ~= Type
        or GuardString.byte ~= Byte or GuardString.char ~= Char or GuardString.sub ~= Sub
        or GuardTable.concat ~= Concat or GuardTable.insert ~= Insert then
        GuardTripped = true;
    end;

    if not GuardTripped and GuardDebug then
        if debug ~= GuardDebug or GuardDebug.gethook ~= GuardGetHook then
            GuardTripped = true;
        elseif GuardGetHook then
            local GuardHookOK, GuardHook = PCall(GuardGetHook);
            if GuardHookOK and GuardHook ~= nil then GuardTripped = true; end;
        end;
    end;

    if not GuardTripped and GuardEnvironment then
        if GuardIsC and GuardEnvironment.iscclosure ~= GuardIsC then GuardTripped = true; end;
        if GuardIsL and GuardEnvironment.islclosure ~= GuardIsL then GuardTripped = true; end;
    end;

    if not GuardTripped and GuardIsC then
        local GuardOK1, GuardC1 = PCall(GuardIsC, Byte);
        local GuardOK2, GuardC2 = PCall(GuardIsC, Sub);
        local GuardOK3, GuardC3 = PCall(GuardIsC, Concat);
        local GuardOK4, GuardC4 = PCall(GuardIsC, PCall);
        if not GuardOK1 or GuardC1 ~= true or not GuardOK2 or GuardC2 ~= true
            or not GuardOK3 or GuardC3 ~= true or not GuardOK4 or GuardC4 ~= true then
            GuardTripped = true;
        end;
    end;

    if not GuardTripped and GuardIsL then
        local GuardOK1, GuardL1 = PCall(GuardIsL, Byte);
        local GuardOK2, GuardL2 = PCall(GuardIsL, Sub);
        local GuardOK3, GuardL3 = PCall(GuardIsL, Concat);
        if not GuardOK1 or GuardL1 ~= false or not GuardOK2 or GuardL2 ~= false
            or not GuardOK3 or GuardL3 ~= false then
            GuardTripped = true;
        end;
    end;
    return GuardTripped;
end;

local function GuardDecoy(...)
    local GuardValue = (__IB2_DECOY_SEED__ + Select('#', ...)) % 2147483647;
    for GuardIndex = 1, 11 do
        GuardValue = (GuardValue * 48271 + GuardIndex * 257) % 2147483647;
    end;
    if GuardValue == -1 then return GuardValue; end;
    return nil;
end;

if GuardProbe(true) then return GuardDecoy; end;
"
				.Replace("__IB2_GUARD_INTERVAL__", probeInterval.ToString())
				.Replace("__IB2_DECOY_SEED__", decoySeed.ToString());
		}

		public static string GenerateHandlerNoise()
		{
			// Pure computation only: no getfenv/_G writes and no executor API hooks.
			var parts = new List<string>();
			var exprs = new[] { "string.byte(\"A\")==65", "#{\"x\"}==1", "(-1<0)==true", "tostring(1)==\"1\"" };
			parts.Add("local " + RN(4, 8) + "=(" + exprs[R.Next(4)] + ")");
			var fn = RN(5, 8);
			parts.Add("local function " + fn + "(...)local _={...};return #_ end;" + fn + "(1,2,3);" + fn + "=nil");
			return "\t" + string.Join(";", parts) + ";\n";
		}

		public static string GenerateLoopNoise()
		{
			var mod = new[] { 7, 11, 13, 17, 19 }[R.Next(5)];
			var sb = new StringBuilder();
			sb.Append("\tif (InstrPoint%"); sb.Append(mod); sb.Append("==0) then\n");
			sb.Append("\t\tlocal _lt={};for _li=1,20 do _lt[_li]={_li}end;\n");
			sb.Append("\tend;\n");
			return sb.ToString();
		}
	}
}
