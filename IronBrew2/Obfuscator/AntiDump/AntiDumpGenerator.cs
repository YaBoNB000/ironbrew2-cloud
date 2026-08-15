using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IronBrew2.Obfuscator.AntiDump
{
    /// <summary>
    /// Generates the VM-integrated executor attestation and fixed-memory decoy sink.
    /// The guard is intentionally fail-closed: ordinary Lua, plain Luau, Roblox Studio
    /// and partial executor shims never receive the attestation token required by the
    /// serialized payload seed.
    /// </summary>
    public static class AntiDumpGenerator
    {
        private static readonly Random R = new Random(RandomNumberGenerator.GetInt32(int.MaxValue));

        private static string RN(int min, int max)
        {
            const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int length = R.Next(min, max + 1);
            char[] name = new char[length];
            name[0] = characters[R.Next(characters.Length)];
            for (int index = 1; index < length; index++)
                name[index] = R.Next(2) == 0
                    ? (char)('0' + R.Next(10))
                    : characters[R.Next(characters.Length)];
            return new string(name);
        }

        private static uint MixWord(uint hash, uint value) => unchecked(hash * 31u + value);

        private static string LuaChars(string value) =>
            "Char(" + string.Join(",", Encoding.ASCII.GetBytes(value).Select(item => item.ToString())) + ")";

        private static string BuildDecoyGraph(uint seed)
        {
            int stateCount = 6 + (int)(seed % 5);
            var routes = new HashSet<int>();
            while (routes.Count < stateCount)
                routes.Add(RandomNumberGenerator.GetInt32(100000, int.MaxValue));
            int[] route = routes.ToArray();

            var graph = new StringBuilder();
            graph.Append(@"
local function GuardBXor(GuardLeft, GuardRight)
    GuardLeft = GuardLeft % 2147483648;
    GuardRight = GuardRight % 2147483648;
    local GuardXorValue = 0;
    local GuardXorBit = 1;
    for GuardXorIndex = 0, 30 do
        local GuardLeftBit = GuardLeft % 2;
        local GuardRightBit = GuardRight % 2;
        if GuardLeftBit ~= GuardRightBit then GuardXorValue = GuardXorValue + GuardXorBit; end;
        GuardLeft = (GuardLeft - GuardLeftBit) / 2;
        GuardRight = (GuardRight - GuardRightBit) / 2;
        GuardXorBit = GuardXorBit * 2;
    end;
    return GuardXorValue;
end;

local function GuardDecoy(...)
    local GuardValue = (__IB2_DECOY_SEED__ + GuardState + Select('#', ...)) % 2147483648;
    local GuardLaneA = (GuardValue * __IB2_DECOY_MUL_A__ + __IB2_DECOY_ADD_A__) % 2147483648;
    local GuardLaneB = (GuardValue * __IB2_DECOY_MUL_B__ + __IB2_DECOY_ADD_B__) % 2147483648;
    local GuardLaneC = GuardBXor(GuardLaneA, GuardLaneB);
    local GuardRoute = __IB2_ROUTE_0__;
    while true do
");
            for (int index = 0; index < route.Length; index++)
            {
                string branch = index == 0 ? "        if" : "        elseif";
                int next = route[(index + 1) % route.Length];
                int multiplier = 30011 + R.Next(20000);
                int increment = 257 + R.Next(8000);
                int rotate = 3 + R.Next(21);
                graph.Append(branch).Append(" GuardRoute == ").Append(route[index]).Append(" then\n");
                switch (index % 3)
                {
                    case 0:
                        graph.Append("            GuardLaneA = GuardBXor((GuardLaneA * ").Append(multiplier)
                            .Append(" + ").Append(increment).Append(") % 2147483648, GuardLaneC);\n")
                            .Append("            GuardValue = (GuardValue + GuardLaneA + ").Append(rotate).Append(") % 2147483648;\n");
                        break;
                    case 1:
                        graph.Append("            GuardLaneB = GuardBXor((GuardLaneB + GuardValue * ").Append(rotate)
                            .Append(") % 2147483648, GuardLaneA);\n")
                            .Append("            GuardLaneC = (GuardLaneC * ").Append(multiplier).Append(" + GuardLaneB + ")
                            .Append(increment).Append(") % 2147483648;\n");
                        break;
                    default:
                        graph.Append("            GuardLaneC = GuardBXor((GuardLaneC * ").Append(multiplier)
                            .Append(" + GuardLaneA + ").Append(increment).Append(") % 2147483648, GuardLaneB);\n")
                            .Append("            GuardValue = GuardBXor(GuardValue, (GuardLaneC + ").Append(rotate)
                            .Append(") % 2147483648);\n");
                        break;
                }
                graph.Append("            GuardRoute = ").Append(next).Append(";\n");
            }
            graph.Append("        else GuardRoute = ").Append(route[0]).Append("; end;\n    end;\nend;\n");

            return graph.ToString()
                .Replace("__IB2_DECOY_SEED__", seed.ToString())
                .Replace("__IB2_DECOY_MUL_A__", (41011u + seed % 19001u).ToString())
                .Replace("__IB2_DECOY_ADD_A__", (521u + seed % 7001u).ToString())
                .Replace("__IB2_DECOY_MUL_B__", (33013u + seed % 17011u).ToString())
                .Replace("__IB2_DECOY_ADD_B__", (911u + seed % 5003u).ToString())
                .Replace("__IB2_ROUTE_0__", route[0].ToString());
        }

        /// <summary>
        /// Builds strict, brand-neutral executor attestation. identifyexecutor is a
        /// required stability signal, not a product allow-list. Admission additionally
        /// requires Roblox host semantics, executor closure APIs, debug introspection,
        /// private setupvalue/proto challenges, loadstring behavior and provenance
        /// consistency. Any failure becomes sticky and enters a non-yielding O(1)-memory
        /// state graph without printing or throwing a dedicated block message.
        /// </summary>
        public static string GenerateRuntimeGuard(int probeInterval, uint decoySeed, uint attestationToken)
        {
            if (probeInterval < 16)
                throw new ArgumentOutOfRangeException(nameof(probeInterval));
            if (attestationToken == 0)
                throw new ArgumentOutOfRangeException(nameof(attestationToken));

            int probeJitter = Math.Max(5, probeInterval / 3);
            int heavyPeriod = 3 + (int)(decoySeed % 3);
            uint sealSalt = (decoySeed ^ 0x6E624EB7u) % 2147483647u;
            uint constantExpected = (uint)RandomNumberGenerator.GetInt32(1000000, 1000000000);
            uint upvalueExpected = (uint)RandomNumberGenerator.GetInt32(1000000, 1000000000);
            uint upvalueChanged = (uint)RandomNumberGenerator.GetInt32(1000000, 1000000000);
            uint protoConstant = (uint)RandomNumberGenerator.GetInt32(1000000, 1000000000);
            uint protoInput = (uint)RandomNumberGenerator.GetInt32(1000, 100000);
            uint protoExpected = (protoConstant + protoInput) % 2147483647u;
            uint loadExpected = (uint)RandomNumberGenerator.GetInt32(1000000, 1000000000);
            uint cInput = (uint)RandomNumberGenerator.GetInt32(1000, 100000);
            uint transcriptSeed = (uint)RandomNumberGenerator.GetInt32(1, int.MaxValue);
            uint transcriptExpected = transcriptSeed;
            foreach (uint value in new[]
                     {
                         constantExpected, upvalueExpected, upvalueChanged,
                         protoExpected, loadExpected, cInput
                     })
                transcriptExpected = MixWord(transcriptExpected, value);
            uint attestationOffset = unchecked(attestationToken - transcriptExpected);

            string guard = @"
local GuardString = string;
local GuardTable = table;
local GuardMath = math;
local GuardDebug = debug;
local GuardUnpack = unpack;
local GuardTableUnpack = GuardTable and GuardTable.unpack;
local GuardGetFEnvGlobal = getfenv;

local GuardEnvOK, GuardEnvironment = PCall(GetFEnv);
if not GuardEnvOK or Type(GuardEnvironment) ~= 'table' then GuardEnvironment = nil; end;
local GuardGetGenV = GuardEnvironment and RawGet(GuardEnvironment, __KEY_GETGENV__);
local GuardCapOK, GuardCapabilityEnvironment = false, nil;
if Type(GuardGetGenV) == 'function' then
    GuardCapOK, GuardCapabilityEnvironment = PCall(GuardGetGenV);
end;
if not GuardCapOK or Type(GuardCapabilityEnvironment) ~= 'table' then GuardCapabilityEnvironment = nil; end;

local function GuardLookup(GuardLookupKey)
    local GuardLookupValue = GuardCapabilityEnvironment and RawGet(GuardCapabilityEnvironment, GuardLookupKey);
    if GuardLookupValue == nil and GuardEnvironment then GuardLookupValue = RawGet(GuardEnvironment, GuardLookupKey); end;
    return GuardLookupValue;
end;

local GuardIdentify = GuardLookup(__KEY_IDENTIFY__);
local GuardIdentifyAlias = GuardLookup(__KEY_IDENTIFY_ALIAS__);
local GuardExecutorNameAlias = GuardLookup(__KEY_EXECUTOR_NAME_ALIAS__);
local GuardCheckCaller = GuardLookup(__KEY_CHECKCALLER__);
local GuardIsC = GuardLookup(__KEY_ISC__);
local GuardIsL = GuardLookup(__KEY_ISL__);
local GuardNewC = GuardLookup(__KEY_NEWC__);
local GuardLoadString = GuardLookup(__KEY_LOADSTRING__);
local GuardTypeOf = GuardLookup(__KEY_TYPEOF__);
local GuardGame = GuardLookup(__KEY_GAME__);
local GuardInstance = GuardLookup(__KEY_INSTANCE__);
local GuardVector3 = GuardLookup(__KEY_VECTOR3__);
local GuardTask = GuardLookup(__KEY_TASK__);

local GuardGetHook = GuardDebug and RawGet(GuardDebug, __KEY_GETHOOK__);
local GuardGetInfo = GuardDebug and RawGet(GuardDebug, __KEY_GETINFO__);
local GuardInfo = GuardDebug and RawGet(GuardDebug, __KEY_INFO__);
local GuardInspector = Type(GuardInfo) == 'function' and GuardInfo or GuardGetInfo;
local GuardGetConstants = GuardDebug and RawGet(GuardDebug, __KEY_GETCONSTANTS__);
local GuardGetUpvalues = GuardDebug and RawGet(GuardDebug, __KEY_GETUPVALUES__);
local GuardGetProto = GuardDebug and RawGet(GuardDebug, __KEY_GETPROTO__);
local GuardGetProtos = GuardDebug and RawGet(GuardDebug, __KEY_GETPROTOS__);
local GuardSetupValue = GuardDebug and RawGet(GuardDebug, __KEY_SETUPVALUE__);

local GuardCounter = 0;
local GuardNextProbe = 1;
local GuardEpoch = 0;
local GuardState = __IB2_DECOY_SEED__ % 2147483647;
local GuardAttestation = 0;
local GuardSeal = (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardAttestation) % 2147483647;
local GuardTripped = false;
local GuardAttested = false;
local GuardUpvalue = __IB2_UPVALUE_EXPECTED__;

local function GuardLuaProbe(GuardProbeValue) return GuardProbeValue; end;
local function GuardConstantProbe() return __IB2_CONSTANT_EXPECTED__; end;
local function GuardUpvalueProbe(GuardProbeValue) return (GuardUpvalue + GuardProbeValue) % 2147483647; end;
local function GuardProtoProbe()
    local function GuardProtoChild(GuardProtoValue)
        return (GuardProtoValue + __IB2_PROTO_CONSTANT__) % 2147483647;
    end;
    return GuardProtoChild;
end;
local function GuardCBody(GuardCValue) return GuardMath.abs(GuardCValue); end;

local function GuardTableContains(GuardValues, GuardExpected)
    if Type(GuardValues) ~= 'table' then return false; end;
    for GuardValueKey, GuardValueItem in Next, GuardValues do
        if GuardValueItem == GuardExpected then return true; end;
    end;
    return false;
end;

local function GuardNativeSource(GuardFunction)
    if Type(GuardFunction) ~= 'function' or Type(GuardInspector) ~= 'function' then return false, false; end;
    if Type(GuardInfo) == 'function' then
        local GuardSourceOK, GuardSource = PCall(GuardInfo, GuardFunction, 's');
        if GuardSourceOK and Type(GuardSource) == 'string' then return true, GuardSource == '[C]'; end;
    elseif Type(GuardGetInfo) == 'function' then
        local GuardSourceOK, GuardSource = PCall(GuardGetInfo, GuardFunction, 'S');
        if GuardSourceOK and Type(GuardSource) == 'table' and Type(GuardSource.what) == 'string' then
            return true, GuardSource.what == 'C';
        end;
    end;
    return false, false;
end;

local function GuardCurrentIdentity()
    if string ~= GuardString or table ~= GuardTable or math ~= GuardMath or debug ~= GuardDebug
        or pcall ~= PCall or type ~= Type or rawget ~= RawGet or rawset ~= RawSet
        or next ~= Next or getmetatable ~= Getmetatable or setmetatable ~= Setmetatable
        or rawequal ~= RawEqual or tostring ~= ToString or select ~= Select
        or tonumber ~= ToNumber or getfenv ~= GuardGetFEnvGlobal
        or GuardString.byte ~= Byte or GuardString.char ~= Char or GuardString.sub ~= Sub
        or GuardTable.concat ~= Concat or GuardTable.insert ~= Insert
        or GuardMath.ldexp ~= LDExp or unpack ~= GuardUnpack
        or GuardTable.unpack ~= GuardTableUnpack or (unpack or GuardTable.unpack) ~= Unpack then
        return false;
    end;
    if not GuardEnvironment or Type(GuardGetGenV) ~= 'function'
        or RawGet(GuardEnvironment, __KEY_GETGENV__) ~= GuardGetGenV then return false; end;
    local GuardCurrentEnvOK, GuardCurrentEnvironment = PCall(GuardGetGenV);
    if not GuardCurrentEnvOK or GuardCurrentEnvironment ~= GuardCapabilityEnvironment then return false; end;
    if GuardLookup(__KEY_IDENTIFY__) ~= GuardIdentify
        or GuardLookup(__KEY_IDENTIFY_ALIAS__) ~= GuardIdentifyAlias
        or GuardLookup(__KEY_EXECUTOR_NAME_ALIAS__) ~= GuardExecutorNameAlias
        or GuardLookup(__KEY_CHECKCALLER__) ~= GuardCheckCaller
        or GuardLookup(__KEY_ISC__) ~= GuardIsC
        or GuardLookup(__KEY_ISL__) ~= GuardIsL
        or GuardLookup(__KEY_NEWC__) ~= GuardNewC
        or GuardLookup(__KEY_LOADSTRING__) ~= GuardLoadString
        or GuardLookup(__KEY_TYPEOF__) ~= GuardTypeOf
        or GuardLookup(__KEY_GAME__) ~= GuardGame
        or GuardLookup(__KEY_INSTANCE__) ~= GuardInstance
        or GuardLookup(__KEY_VECTOR3__) ~= GuardVector3
        or GuardLookup(__KEY_TASK__) ~= GuardTask then return false; end;
    if not GuardDebug
        or RawGet(GuardDebug, __KEY_GETHOOK__) ~= GuardGetHook
        or RawGet(GuardDebug, __KEY_GETINFO__) ~= GuardGetInfo
        or RawGet(GuardDebug, __KEY_INFO__) ~= GuardInfo
        or RawGet(GuardDebug, __KEY_GETCONSTANTS__) ~= GuardGetConstants
        or RawGet(GuardDebug, __KEY_GETUPVALUES__) ~= GuardGetUpvalues
        or RawGet(GuardDebug, __KEY_GETPROTO__) ~= GuardGetProto
        or RawGet(GuardDebug, __KEY_GETPROTOS__) ~= GuardGetProtos
        or RawGet(GuardDebug, __KEY_SETUPVALUE__) ~= GuardSetupValue then return false; end;
    if Type(GuardGetHook) == 'function' then
        local GuardHookOK, GuardHook = PCall(GuardGetHook);
        if not GuardHookOK or GuardHook ~= nil then return false; end;
    end;
    return true;
end;

local function GuardStrictChallenge()
    if Type(GuardIdentify) ~= 'function' or Type(GuardCheckCaller) ~= 'function'
        or Type(GuardIsC) ~= 'function' or Type(GuardIsL) ~= 'function'
        or Type(GuardNewC) ~= 'function' or Type(GuardLoadString) ~= 'function'
        or Type(GuardTypeOf) ~= 'function' or Type(GuardInspector) ~= 'function'
        or Type(GuardGetConstants) ~= 'function' or Type(GuardGetUpvalues) ~= 'function'
        or (Type(GuardGetProto) ~= 'function' and Type(GuardGetProtos) ~= 'function')
        or Type(GuardSetupValue) ~= 'function' then return false, 0; end;

    local GuardIdOK1, GuardName1, GuardVersion1 = PCall(GuardIdentify);
    local GuardIdOK2, GuardName2, GuardVersion2 = PCall(GuardIdentify);
    local GuardVersionType1, GuardVersionType2 = Type(GuardVersion1), Type(GuardVersion2);
    if not GuardIdOK1 or not GuardIdOK2 or Type(GuardName1) ~= 'string'
        or #GuardName1 < 1 or #GuardName1 > 128 or GuardName1 ~= GuardName2
        or (GuardVersionType1 ~= 'nil' and GuardVersionType1 ~= 'string' and GuardVersionType1 ~= 'number')
        or GuardVersionType1 ~= GuardVersionType2 or ToString(GuardVersion1) ~= ToString(GuardVersion2) then return false, 0; end;
    for GuardAliasIndex = 1, 2 do
        local GuardAlias = GuardIdentifyAlias;
        if GuardAliasIndex == 2 then GuardAlias = GuardExecutorNameAlias; end;
        if GuardAlias ~= nil then
            if Type(GuardAlias) ~= 'function' then return false, 0; end;
            local GuardAliasOK, GuardAliasName = PCall(GuardAlias);
            if not GuardAliasOK or GuardAliasName ~= GuardName1 then return false, 0; end;
        end;
    end;
    local GuardCallerOK, GuardCaller = PCall(GuardCheckCaller);
    if not GuardCallerOK or GuardCaller ~= true then return false, 0; end;

    if (Type(GuardGame) ~= 'table' and Type(GuardGame) ~= 'userdata')
        or Type(GuardInstance) ~= 'table' or Type(GuardVector3) ~= 'table'
        or Type(GuardTask) ~= 'table' then return false, 0; end;
    local GuardHostOK, GuardHostResult = PCall(function()
        local GuardPlayers = GuardGame:GetService(__VALUE_PLAYERS__);
        local GuardVector = GuardVector3.new();
        return GuardPlayers and GuardPlayers.ClassName == __VALUE_PLAYERS__
            and GuardTypeOf(GuardVector) == __VALUE_VECTOR3__
            and GuardTypeOf(Setmetatable({}, {})) == 'table'
            and Type(GuardInstance.new) == 'function'
            and Type(GuardTask.wait) == 'function'
            and Type(GuardTask.spawn) == 'function'
            and Type(GuardTask.defer) == 'function';
    end);
    if not GuardHostOK or GuardHostResult ~= true then return false, 0; end;

    local GuardClassOK1, GuardNativeByte = PCall(GuardIsC, Byte);
    local GuardClassOK2, GuardLuaByte = PCall(GuardIsL, Byte);
    local GuardClassOK3, GuardNativeProbe = PCall(GuardIsC, GuardLuaProbe);
    local GuardClassOK4, GuardLuaProbeResult = PCall(GuardIsL, GuardLuaProbe);
    if not GuardClassOK1 or not GuardClassOK2 or not GuardClassOK3 or not GuardClassOK4
        or GuardNativeByte ~= true or GuardLuaByte ~= false
        or GuardNativeProbe ~= false or GuardLuaProbeResult ~= true then return false, 0; end;

    local GuardPrimitives = {
        Byte, Char, Sub, Concat, Insert, LDExp, Select, PCall, Type, ToString,
        ToNumber, RawGet, RawSet, RawEqual, Next, Setmetatable, Getmetatable, Unpack
    };
    local GuardKnown, GuardNative;
    for GuardPrimitiveIndex = 1, #GuardPrimitives do
        GuardKnown, GuardNative = GuardNativeSource(GuardPrimitives[GuardPrimitiveIndex]);
        if not GuardKnown or not GuardNative then return false, 0; end;
    end;
    GuardKnown, GuardNative = GuardNativeSource(GuardLuaProbe);
    if not GuardKnown or GuardNative then return false, 0; end;
    GuardKnown, GuardNative = GuardNativeSource(GuardInspector);
    if not GuardKnown or not GuardNative then return false, 0; end;

    local GuardTranscript = __IB2_TRANSCRIPT_SEED__;
    local function GuardTranscriptWord(GuardTranscriptValue)
        GuardTranscript = (GuardTranscript * 31 + GuardTranscriptValue) % 4294967296;
    end;

    local GuardConstantsOK, GuardConstants = PCall(GuardGetConstants, GuardConstantProbe);
    if not GuardConstantsOK or not GuardTableContains(GuardConstants, __IB2_CONSTANT_EXPECTED__) then return false, 0; end;
    GuardTranscriptWord(__IB2_CONSTANT_EXPECTED__);

    local GuardUpvaluesOK, GuardUpvalues = PCall(GuardGetUpvalues, GuardUpvalueProbe);
    if not GuardUpvaluesOK or not GuardTableContains(GuardUpvalues, __IB2_UPVALUE_EXPECTED__) then return false, 0; end;
    GuardTranscriptWord(__IB2_UPVALUE_EXPECTED__);

    local GuardSetOK = PCall(GuardSetupValue, GuardUpvalueProbe, 1, __IB2_UPVALUE_CHANGED__);
    local GuardChangedOK = GuardSetOK and GuardUpvalueProbe(0) == __IB2_UPVALUE_CHANGED__;
    local GuardRestoreOK = PCall(GuardSetupValue, GuardUpvalueProbe, 1, __IB2_UPVALUE_EXPECTED__);
    if not GuardChangedOK or not GuardRestoreOK or GuardUpvalueProbe(0) ~= __IB2_UPVALUE_EXPECTED__ then return false, 0; end;
    GuardTranscriptWord(__IB2_UPVALUE_CHANGED__);

    local GuardProtoCandidate = nil;
    if Type(GuardGetProto) == 'function' then
        local GuardProtoOK, GuardProtoResult = PCall(GuardGetProto, GuardProtoProbe, 1, true);
        if GuardProtoOK then
            if Type(GuardProtoResult) == 'function' then GuardProtoCandidate = GuardProtoResult;
            elseif Type(GuardProtoResult) == 'table' then
                for GuardProtoKey, GuardProtoItem in Next, GuardProtoResult do
                    if Type(GuardProtoItem) == 'function' then GuardProtoCandidate = GuardProtoItem; break; end;
                end;
            end;
        end;
    end;
    if not GuardProtoCandidate and Type(GuardGetProtos) == 'function' then
        local GuardProtosOK, GuardProtos = PCall(GuardGetProtos, GuardProtoProbe);
        if GuardProtosOK and Type(GuardProtos) == 'table' then
            for GuardProtoKey, GuardProtoItem in Next, GuardProtos do
                if Type(GuardProtoItem) == 'function' then GuardProtoCandidate = GuardProtoItem; break; end;
            end;
        end;
    end;
    if Type(GuardProtoCandidate) ~= 'function' then return false, 0; end;
    local GuardProtoCallOK, GuardProtoCallResult = PCall(GuardProtoCandidate, __IB2_PROTO_INPUT__);
    local GuardProtoClassOK, GuardProtoIsL = PCall(GuardIsL, GuardProtoCandidate);
    if not GuardProtoCallOK or GuardProtoCallResult ~= __IB2_PROTO_EXPECTED__
        or not GuardProtoClassOK or GuardProtoIsL ~= true then return false, 0; end;
    GuardTranscriptWord(__IB2_PROTO_EXPECTED__);

    local GuardLoadSource = Char(114,101,116,117,114,110,32) .. ToString(__IB2_LOAD_EXPECTED__);
    local GuardCompileOK, GuardLoaded = PCall(GuardLoadString, GuardLoadSource);
    if not GuardCompileOK or Type(GuardLoaded) ~= 'function' then return false, 0; end;
    local GuardLoadedOK, GuardLoadedValue = PCall(GuardLoaded);
    local GuardLoadedCOK, GuardLoadedC = PCall(GuardIsC, GuardLoaded);
    local GuardLoadedLOK, GuardLoadedL = PCall(GuardIsL, GuardLoaded);
    if not GuardLoadedOK or GuardLoadedValue ~= __IB2_LOAD_EXPECTED__
        or not GuardLoadedCOK or not GuardLoadedLOK or GuardLoadedC ~= false or GuardLoadedL ~= true then return false, 0; end;
    local GuardLoadedConstantsOK, GuardLoadedConstants = PCall(GuardGetConstants, GuardLoaded);
    if not GuardLoadedConstantsOK or not GuardTableContains(GuardLoadedConstants, __IB2_LOAD_EXPECTED__) then return false, 0; end;
    GuardKnown, GuardNative = GuardNativeSource(GuardLoaded);
    if not GuardKnown or GuardNative then return false, 0; end;
    GuardTranscriptWord(__IB2_LOAD_EXPECTED__);

    local GuardWrapOK, GuardWrapped = PCall(GuardNewC, GuardCBody);
    if not GuardWrapOK or Type(GuardWrapped) ~= 'function' then return false, 0; end;
    local GuardWrappedOK, GuardWrappedValue = PCall(GuardWrapped, -__IB2_C_INPUT__);
    local GuardWrappedCOK, GuardWrappedC = PCall(GuardIsC, GuardWrapped);
    local GuardWrappedLOK, GuardWrappedL = PCall(GuardIsL, GuardWrapped);
    if not GuardWrappedOK or GuardWrappedValue ~= __IB2_C_INPUT__
        or not GuardWrappedCOK or not GuardWrappedLOK or GuardWrappedC ~= true or GuardWrappedL ~= false then return false, 0; end;
    GuardKnown, GuardNative = GuardNativeSource(GuardWrapped);
    if not GuardKnown or not GuardNative then return false, 0; end;
    GuardTranscriptWord(__IB2_C_INPUT__);

    return true, GuardTranscript;
end;

__IB2_DECOY_GRAPH__

local function GuardProbe(Force)
    GuardCounter = GuardCounter + 1;
    if GuardTripped then return true; end;
    if not Force and GuardCounter < GuardNextProbe then return false; end;
    if GuardSeal ~= (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardAttestation) % 2147483647 then
        GuardTripped = true;
        GuardAttestation = 0;
        return true;
    end;

    GuardEpoch = GuardEpoch + 1;
    local GuardHeavy = Force or not GuardAttested or GuardEpoch % __IB2_HEAVY_PERIOD__ == 0;
    local GuardValid = GuardCurrentIdentity();
    local GuardTranscript = __IB2_TRANSCRIPT_EXPECTED__;
    if GuardValid and GuardHeavy then
        GuardValid, GuardTranscript = GuardStrictChallenge();
    end;
    if GuardValid and GuardTranscript ~= __IB2_TRANSCRIPT_EXPECTED__ then GuardValid = false; end;
    if not GuardValid then
        GuardTripped = true;
        GuardAttestation = 0;
        return true;
    end;

    if not GuardAttested then
        GuardAttestation = (GuardTranscript + __IB2_ATTESTATION_OFFSET__) % 4294967296;
        GuardAttested = true;
    end;
    if GuardAttestation ~= __IB2_ATTESTATION_TOKEN__ then
        GuardTripped = true;
        GuardAttestation = 0;
        return true;
    end;

    GuardState = (GuardState * 48271 + GuardCounter + GuardEpoch * 17 + GuardAttestation % 65521) % 2147483647;
    GuardSeal = (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardAttestation) % 2147483647;
    GuardNextProbe = GuardCounter + __IB2_GUARD_INTERVAL__ + (GuardState % __IB2_GUARD_JITTER__);
    return false;
end;

if GuardProbe(true) then return GuardDecoy(); end;
";

            var replacements = new Dictionary<string, string>
            {
                ["__IB2_GUARD_INTERVAL__"] = probeInterval.ToString(),
                ["__IB2_GUARD_JITTER__"] = probeJitter.ToString(),
                ["__IB2_HEAVY_PERIOD__"] = heavyPeriod.ToString(),
                ["__IB2_DECOY_SEED__"] = decoySeed.ToString(),
                ["__IB2_SEAL_SALT__"] = sealSalt.ToString(),
                ["__IB2_CONSTANT_EXPECTED__"] = constantExpected.ToString(),
                ["__IB2_UPVALUE_EXPECTED__"] = upvalueExpected.ToString(),
                ["__IB2_UPVALUE_CHANGED__"] = upvalueChanged.ToString(),
                ["__IB2_PROTO_CONSTANT__"] = protoConstant.ToString(),
                ["__IB2_PROTO_INPUT__"] = protoInput.ToString(),
                ["__IB2_PROTO_EXPECTED__"] = protoExpected.ToString(),
                ["__IB2_LOAD_EXPECTED__"] = loadExpected.ToString(),
                ["__IB2_C_INPUT__"] = cInput.ToString(),
                ["__IB2_TRANSCRIPT_SEED__"] = transcriptSeed.ToString(),
                ["__IB2_TRANSCRIPT_EXPECTED__"] = transcriptExpected.ToString(),
                ["__IB2_ATTESTATION_OFFSET__"] = attestationOffset.ToString(),
                ["__IB2_ATTESTATION_TOKEN__"] = attestationToken.ToString(),
                ["__IB2_DECOY_GRAPH__"] = BuildDecoyGraph(decoySeed),
                ["__KEY_GETGENV__"] = LuaChars("getgenv"),
                ["__KEY_IDENTIFY__"] = LuaChars("identifyexecutor"),
                ["__KEY_IDENTIFY_ALIAS__"] = LuaChars("getexecutorname"),
                ["__KEY_EXECUTOR_NAME_ALIAS__"] = LuaChars("executorname"),
                ["__KEY_CHECKCALLER__"] = LuaChars("checkcaller"),
                ["__KEY_ISC__"] = LuaChars("iscclosure"),
                ["__KEY_ISL__"] = LuaChars("islclosure"),
                ["__KEY_NEWC__"] = LuaChars("newcclosure"),
                ["__KEY_LOADSTRING__"] = LuaChars("loadstring"),
                ["__KEY_TYPEOF__"] = LuaChars("typeof"),
                ["__KEY_GAME__"] = LuaChars("game"),
                ["__KEY_INSTANCE__"] = LuaChars("Instance"),
                ["__KEY_VECTOR3__"] = LuaChars("Vector3"),
                ["__KEY_TASK__"] = LuaChars("task"),
                ["__KEY_GETHOOK__"] = LuaChars("gethook"),
                ["__KEY_GETINFO__"] = LuaChars("getinfo"),
                ["__KEY_INFO__"] = LuaChars("info"),
                ["__KEY_GETCONSTANTS__"] = LuaChars("getconstants"),
                ["__KEY_GETUPVALUES__"] = LuaChars("getupvalues"),
                ["__KEY_GETPROTO__"] = LuaChars("getproto"),
                ["__KEY_GETPROTOS__"] = LuaChars("getprotos"),
                ["__KEY_SETUPVALUE__"] = LuaChars("setupvalue"),
                ["__VALUE_PLAYERS__"] = LuaChars("Players"),
                ["__VALUE_VECTOR3__"] = LuaChars("Vector3")
            };
            foreach (KeyValuePair<string, string> replacement in replacements)
                guard = guard.Replace(replacement.Key, replacement.Value);
            return guard;
        }

        public static string GenerateHandlerNoise()
        {
            var parts = new List<string>();
            var expressions = new[]
            {
                "string.byte(\"A\")==65", "#{\"x\"}==1", "(-1<0)==true", "tostring(1)==\"1\""
            };
            parts.Add("local " + RN(4, 8) + "=(" + expressions[R.Next(4)] + ")");
            string function = RN(5, 8);
            parts.Add("local function " + function + "(...)local _={...};return #_ end;" + function + "(1,2,3);" + function + "=nil");
            return "\t" + string.Join(";", parts) + ";\n";
        }

        public static string GenerateLoopNoise()
        {
            int modulus = new[] {7, 11, 13, 17, 19}[R.Next(5)];
            var output = new StringBuilder();
            output.Append("\tif (InstrPoint%"); output.Append(modulus); output.Append("==0) then\n");
            output.Append("\t\tlocal _lt={};for _li=1,20 do _lt[_li]={_li}end;\n");
            output.Append("\tend;\n");
            return output.ToString();
        }
    }
}
