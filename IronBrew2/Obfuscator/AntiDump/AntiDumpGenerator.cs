using System;
using System.Collections.Generic;
using System.Text;

namespace IronBrew2.Obfuscator.AntiDump
{
	/// <summary>
	/// Generates capability-gated runtime integrity probes and side-effect-free VM noise.
	/// The guard never mutates executor globals, performs network or file operations, or
	/// allocates an unbounded amount of memory. High-confidence signals are combined and
	/// consumed by the generated VM as a silent decoy route.
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
		/// Builds the guard embedded directly into the generated VM. It adapts the useful
		/// ideas from the reviewed v5.4 sample (staged checks, primitive snapshots,
		/// provenance cross-checks and multi-signal scoring) without importing its global
		/// API hooks, network probes, timing thresholds, background scans or crash payloads.
		/// Ordinary Lua remains supported; Luau/executor capabilities are used only when
		/// the host actually exposes them.
		/// </summary>
		public static string GenerateRuntimeGuard(int probeInterval, uint decoySeed)
		{
			if (probeInterval < 16)
				throw new ArgumentOutOfRangeException(nameof(probeInterval));

			int probeJitter = Math.Max(5, probeInterval / 3);
			int heavyPeriod = 3 + (int) (decoySeed % 3);
			int decoyRounds = 9 + (int) (decoySeed % 7);
			uint sealSalt = (decoySeed ^ 0x9E3779B9u) % 2147483647u;
			uint decoyMultiplier = 40009u + decoySeed % 19991u;
			uint decoyIncrement = 257u + decoySeed % 4093u;

			return @"
local GuardString = string;
local GuardTable = table;
local GuardMath = math;
local GuardDebug = debug;
local GuardGetHook = GuardDebug and RawGet(GuardDebug, 'gethook');
local GuardGetInfo = GuardDebug and RawGet(GuardDebug, 'getinfo');
local GuardInfo = GuardDebug and RawGet(GuardDebug, 'info');
local GuardInspector = Type(GuardInfo) == 'function' and GuardInfo or GuardGetInfo;
local GuardUnpack = unpack;
local GuardTableUnpack = GuardTable.unpack;
local GuardGetFEnvGlobal = getfenv;

local GuardEnvOK, GuardEnvironment = PCall(GetFEnv);
if not GuardEnvOK or Type(GuardEnvironment) ~= 'table' then GuardEnvironment = nil; end;
local GuardGetGenV = GuardEnvironment and RawGet(GuardEnvironment, 'getgenv');
local GuardCapabilityEnvironment = GuardEnvironment;
if Type(GuardGetGenV) == 'function' then
    local GuardCapOK, GuardCapEnv = PCall(GuardGetGenV);
    if GuardCapOK and Type(GuardCapEnv) == 'table' then GuardCapabilityEnvironment = GuardCapEnv; end;
else
    GuardGetGenV = nil;
end;
local GuardIsC = GuardCapabilityEnvironment and RawGet(GuardCapabilityEnvironment, 'iscclosure');
local GuardIsL = GuardCapabilityEnvironment and RawGet(GuardCapabilityEnvironment, 'islclosure');
if Type(GuardIsC) ~= 'function' then GuardIsC = nil; end;
if Type(GuardIsL) ~= 'function' then GuardIsL = nil; end;

local GuardCounter = 0;
local GuardNextProbe = 1;
local GuardEpoch = 0;
local GuardState = __IB2_DECOY_SEED__ % 2147483647;
local GuardSeal = (GuardState * 65599 + __IB2_SEAL_SALT__) % 2147483647;
local GuardTripped = false;
local function GuardLuaProbe(GuardProbeValue) return GuardProbeValue; end;

local function GuardNativeSource(GuardFunction)
    if Type(GuardFunction) ~= 'function' or Type(GuardInspector) ~= 'function' then return false, false; end;
    if GuardInfo then
        local GuardSourceOK, GuardSource = PCall(GuardInfo, GuardFunction, 's');
        if GuardSourceOK and Type(GuardSource) == 'string' then return true, GuardSource == '[C]'; end;
    elseif GuardGetInfo then
        local GuardSourceOK, GuardSource = PCall(GuardGetInfo, GuardFunction, 'S');
        if GuardSourceOK and Type(GuardSource) == 'table' and Type(GuardSource.what) == 'string' then
            return true, GuardSource.what == 'C';
        end;
    end;
    return false, false;
end;

local function GuardProbe(Force)
    GuardCounter = GuardCounter + 1;
    if GuardTripped then return true; end;
    if not Force and GuardCounter < GuardNextProbe then return false; end;

    if GuardSeal ~= (GuardState * 65599 + __IB2_SEAL_SALT__) % 2147483647 then
        GuardTripped = true;
        return true;
    end;

    GuardEpoch = GuardEpoch + 1;
    GuardState = (GuardState * 48271 + GuardCounter + GuardEpoch * 17) % 2147483647;
    GuardSeal = (GuardState * 65599 + __IB2_SEAL_SALT__) % 2147483647;
    GuardNextProbe = GuardCounter + __IB2_GUARD_INTERVAL__ + (GuardState % __IB2_GUARD_JITTER__);

    local GuardScore = 0;
    local GuardHeavy = Force or GuardEpoch % __IB2_HEAVY_PERIOD__ == 0;

    if string ~= GuardString or table ~= GuardTable or math ~= GuardMath
        or pcall ~= PCall or type ~= Type or rawget ~= RawGet or rawset ~= RawSet
        or next ~= Next or getmetatable ~= Getmetatable or setmetatable ~= Setmetatable
        or rawequal ~= RawEqual or tostring ~= ToString or select ~= Select
        or tonumber ~= ToNumber or getfenv ~= GuardGetFEnvGlobal
        or GuardString.byte ~= Byte or GuardString.char ~= Char or GuardString.sub ~= Sub
        or GuardTable.concat ~= Concat or GuardTable.insert ~= Insert
        or GuardMath.ldexp ~= LDExp or unpack ~= GuardUnpack
        or GuardTable.unpack ~= GuardTableUnpack or (unpack or GuardTable.unpack) ~= Unpack then
        GuardScore = GuardScore + 8;
    end;

    if debug ~= GuardDebug then
        GuardScore = GuardScore + 8;
    elseif GuardDebug then
        if RawGet(GuardDebug, 'gethook') ~= GuardGetHook
            or RawGet(GuardDebug, 'getinfo') ~= GuardGetInfo
            or RawGet(GuardDebug, 'info') ~= GuardInfo then
            GuardScore = GuardScore + 8;
        end;
        if Type(GuardGetHook) == 'function' then
            local GuardHookOK, GuardHook = PCall(GuardGetHook);
            if GuardHookOK and GuardHook ~= nil then
                GuardScore = GuardScore + 8;
            elseif not GuardHookOK then
                GuardScore = GuardScore + 3;
            end;
        end;
    end;

    if GuardEnvironment and GuardGetGenV and RawGet(GuardEnvironment, 'getgenv') ~= GuardGetGenV then
        GuardScore = GuardScore + 6;
    end;
    if GuardCapabilityEnvironment then
        local GuardCurrentIsC = RawGet(GuardCapabilityEnvironment, 'iscclosure');
        local GuardCurrentIsL = RawGet(GuardCapabilityEnvironment, 'islclosure');
        if (GuardIsC and GuardCurrentIsC ~= GuardIsC) or (not GuardIsC and Type(GuardCurrentIsC) == 'function') then
            GuardScore = GuardScore + 6;
        end;
        if (GuardIsL and GuardCurrentIsL ~= GuardIsL) or (not GuardIsL and Type(GuardCurrentIsL) == 'function') then
            GuardScore = GuardScore + 6;
        end;
    end;

    if GuardHeavy and Type(GuardIsC) == 'function' then
        local GuardNativeMisses = 0;
        local GuardOK1, GuardC1 = PCall(GuardIsC, Byte);
        local GuardOK2, GuardC2 = PCall(GuardIsC, PCall);
        local GuardOK3, GuardC3 = PCall(GuardIsC, RawGet);
        local GuardOK4, GuardC4 = PCall(GuardIsC, RawSet);
        if not GuardOK1 or GuardC1 ~= true then GuardNativeMisses = GuardNativeMisses + 1; end;
        if not GuardOK2 or GuardC2 ~= true then GuardNativeMisses = GuardNativeMisses + 1; end;
        if not GuardOK3 or GuardC3 ~= true then GuardNativeMisses = GuardNativeMisses + 1; end;
        if not GuardOK4 or GuardC4 ~= true then GuardNativeMisses = GuardNativeMisses + 1; end;
        if GuardNativeMisses >= 2 then GuardScore = GuardScore + 8;
        elseif GuardNativeMisses == 1 then GuardScore = GuardScore + 2; end;
        local GuardLuaOK, GuardLuaIsC = PCall(GuardIsC, GuardLuaProbe);
        if not GuardLuaOK or GuardLuaIsC ~= false then GuardScore = GuardScore + 6; end;
    end;

    if GuardHeavy and Type(GuardIsL) == 'function' then
        local GuardNativeMisses = 0;
        local GuardOK1, GuardL1 = PCall(GuardIsL, Byte);
        local GuardOK2, GuardL2 = PCall(GuardIsL, PCall);
        local GuardOK3, GuardL3 = PCall(GuardIsL, RawSet);
        if not GuardOK1 or GuardL1 ~= false then GuardNativeMisses = GuardNativeMisses + 1; end;
        if not GuardOK2 or GuardL2 ~= false then GuardNativeMisses = GuardNativeMisses + 1; end;
        if not GuardOK3 or GuardL3 ~= false then GuardNativeMisses = GuardNativeMisses + 1; end;
        if GuardNativeMisses >= 2 then GuardScore = GuardScore + 8;
        elseif GuardNativeMisses == 1 then GuardScore = GuardScore + 2; end;
        local GuardLuaOK, GuardLuaIsL = PCall(GuardIsL, GuardLuaProbe);
        if not GuardLuaOK or GuardLuaIsL ~= true then GuardScore = GuardScore + 6; end;
    end;

    if GuardHeavy and Type(GuardInspector) == 'function' then
        local GuardKnown, GuardNative = GuardNativeSource(Byte);
        if GuardKnown and not GuardNative then GuardScore = GuardScore + 6; end;
        GuardKnown, GuardNative = GuardNativeSource(PCall);
        if GuardKnown and not GuardNative then GuardScore = GuardScore + 6; end;
        GuardKnown, GuardNative = GuardNativeSource(RawGet);
        if GuardKnown and not GuardNative then GuardScore = GuardScore + 6; end;
        GuardKnown, GuardNative = GuardNativeSource(RawSet);
        if GuardKnown and not GuardNative then GuardScore = GuardScore + 6; end;
        GuardKnown, GuardNative = GuardNativeSource(GuardInspector);
        if GuardKnown and not GuardNative then GuardScore = GuardScore + 6; end;
        GuardKnown, GuardNative = GuardNativeSource(GuardLuaProbe);
        if GuardKnown and GuardNative then GuardScore = GuardScore + 6; end;
    end;

    if GuardHeavy then
        local GuardBehaviorOK, GuardBehaviorResult = PCall(function()
            local GuardBehaviorTable = {};
            local GuardBehaviorMeta = {};
            local GuardBehaviorKey = 3 + (__IB2_DECOY_SEED__ % 11);
            RawSet(GuardBehaviorTable, GuardBehaviorKey, GuardLuaProbe);
            Setmetatable(GuardBehaviorTable, GuardBehaviorMeta);
            local GuardFirstKey = Next(GuardBehaviorTable);
            return RawGet(GuardBehaviorTable, GuardBehaviorKey) == GuardLuaProbe
                and GuardFirstKey == GuardBehaviorKey
                and Getmetatable(GuardBehaviorTable) == GuardBehaviorMeta
                and RawEqual(RawGet(GuardBehaviorTable, GuardBehaviorKey), GuardLuaProbe)
                and Select('#', 1, nil, 3) == 3
                and Byte(Char(65)) == 65
                and Sub(Char(97, 98, 99), 2, 2) == Char(98)
                and Concat({Char(97), Char(98)}) == Char(97, 98)
                and ToNumber('17') == 17 and ToString(17) == '17';
        end);
        if not GuardBehaviorOK or GuardBehaviorResult ~= true then GuardScore = GuardScore + 6; end;
    end;

    if GuardScore >= 6 then GuardTripped = true; end;
    return GuardTripped;
end;

local function GuardDecoy(...)
    local GuardValue = (__IB2_DECOY_SEED__ + GuardState + Select('#', ...)) % 2147483647;
    for GuardIndex = 1, __IB2_DECOY_ROUNDS__ do
        GuardValue = (GuardValue * __IB2_DECOY_MULTIPLIER__ + GuardIndex * __IB2_DECOY_INCREMENT__) % 2147483647;
    end;
    if GuardValue == -1 then return GuardValue; end;
    return nil;
end;

if GuardProbe(true) then return GuardDecoy; end;
"
				.Replace("__IB2_GUARD_INTERVAL__", probeInterval.ToString())
				.Replace("__IB2_GUARD_JITTER__", probeJitter.ToString())
				.Replace("__IB2_HEAVY_PERIOD__", heavyPeriod.ToString())
				.Replace("__IB2_DECOY_SEED__", decoySeed.ToString())
				.Replace("__IB2_SEAL_SALT__", sealSalt.ToString())
				.Replace("__IB2_DECOY_ROUNDS__", decoyRounds.ToString())
				.Replace("__IB2_DECOY_MULTIPLIER__", decoyMultiplier.ToString())
				.Replace("__IB2_DECOY_INCREMENT__", decoyIncrement.ToString());
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
