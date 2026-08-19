using System;
using System.Collections.Generic;
using System.Linq;
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
        // Emergency diagnostic switch only. Production keeps strict sink
        // enforcement enabled; a true value must never ship.
        private const bool TemporaryGlobalSinkBypass = false;

        private static string RN(Random random, int min, int max)
        {
            const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int length = random.Next(min, max + 1);
            char[] name = new char[length];
            name[0] = characters[random.Next(characters.Length)];
            for (int index = 1; index < length; index++)
                name[index] = random.Next(2) == 0
                    ? (char)('0' + random.Next(10))
                    : characters[random.Next(characters.Length)];
            return new string(name);
        }

        private static uint MixWord(uint hash, uint value) => unchecked(hash * 31u + value);

        private sealed class KeyVault
        {
            public string Prelude { get; init; }
            public Dictionary<string, string> References { get; init; }
        }

        /// <summary>
        /// Packs executor and host lookup keys into one build-local additive stream.
        /// Tokens, byte positions, per-key states, padding and descriptor order all
        /// vary per build, so the runtime has no stable plaintext API sequence.
        /// </summary>
        private static KeyVault BuildKeyVault(Dictionary<string, string> values, Random random)
        {
            var entries = values.ToList();
            for (int index = entries.Count - 1; index > 0; index--)
            {
                int swap = random.Next(index + 1);
                (entries[index], entries[swap]) = (entries[swap], entries[index]);
            }

            var bytes = new List<int>();
            var descriptors = new List<string>();
            var references = new Dictionary<string, string>();
            var tokens = new HashSet<int>();
            foreach (KeyValuePair<string, string> entry in entries)
            {
                for (int pad = 0; pad < random.Next(1, 6); pad++) bytes.Add(random.Next(256));
                int token;
                do token = random.Next(10000, int.MaxValue); while (!tokens.Add(token));
                int start = bytes.Count + 1;
                int seed = random.Next(1, 256);
                int step = random.Next(1, 256);
                byte[] plain = Encoding.ASCII.GetBytes(entry.Value);
                for (int index = 0; index < plain.Length; index++)
                    bytes.Add((plain[index] + seed + (index + 1) * step) % 256);
                descriptors.Add("[" + token + "]={" + start + "," + plain.Length + "," + seed + "," + step + "}");
                references[entry.Key] = "GuardKey(" + token + ")";
            }
            for (int pad = 0; pad < random.Next(3, 9); pad++) bytes.Add(random.Next(256));
            for (int index = descriptors.Count - 1; index > 0; index--)
            {
                int swap = random.Next(index + 1);
                (descriptors[index], descriptors[swap]) = (descriptors[swap], descriptors[index]);
            }

            string prelude = "local GuardKeyBytes={" + string.Join(",", bytes) + "};" +
                "local GuardKeyMeta={" + string.Join(",", descriptors) + "};" +
                "local GuardKeyCache={};" +
                "local function GuardKey(GuardLookupKey)" +
                "local GuardLookupValue=GuardKeyCache[GuardLookupKey];if GuardLookupValue then return GuardLookupValue end;" +
                "local GuardKeyRecord=GuardKeyMeta[GuardLookupKey];if not GuardKeyRecord then return nil end;" +
                "local GuardKeyParts={};for GuardKeyIndex=1,GuardKeyRecord[2] do " +
                "GuardKeyParts[GuardKeyIndex]=Char((GuardKeyBytes[GuardKeyRecord[1]+GuardKeyIndex-1]-GuardKeyRecord[3]-GuardKeyIndex*GuardKeyRecord[4])%256);end;" +
                "GuardLookupValue=Concat(GuardKeyParts);GuardKeyCache[GuardLookupKey]=GuardLookupValue;return GuardLookupValue;end;";
            return new KeyVault { Prelude = prelude, References = references };
        }

        private static string BuildDecoyGraph(uint seed, Random random)
        {
            int stateCount = 6 + (int)(seed % 5);
            var routes = new HashSet<int>();
            while (routes.Count < stateCount)
                routes.Add(random.Next(100000, int.MaxValue));
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

GuardDecoy = function(...)
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
                int multiplier = 30011 + random.Next(20000);
                int increment = 257 + random.Next(8000);
                int rotate = 3 + random.Next(21);
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
        /// typed stability signal, never a product allow-list. Admission is based on
        /// sUNC-style observable behavior: isolated executor globals, Roblox host
        /// semantics, closure classification/wrapping, Luau compilation, debug API
        /// call/shape and C-isolation rules, plus active local-prototype behavior.
        /// Exact debug source strings and non-standard identity aliases are excluded.
        /// Any failure becomes sticky and normally enters a non-yielding O(1)-memory
        /// state graph without printing or throwing a dedicated block message. The
        /// temporary global diagnostic switch changes only that rejection response.
        /// </summary>
        public static string GenerateRuntimeGuard(int probeInterval, uint decoySeed, uint attestationToken, Random random)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            if (probeInterval < 16)
                throw new ArgumentOutOfRangeException(nameof(probeInterval));
            if (attestationToken == 0)
                throw new ArgumentOutOfRangeException(nameof(attestationToken));

            int probeJitter = Math.Max(5, probeInterval / 3);
            int heavyPeriod = 3 + (int)(decoySeed % 3);
            uint sealSalt = (decoySeed ^ 0x6E624EB7u) % 2147483647u;
            uint payloadSealSalt = unchecked(decoySeed ^ (uint)random.NextInt64(1, 1L << 32));
            uint payloadStateSalt = unchecked(attestationToken ^ (uint)random.NextInt64(1, 1L << 32));
            uint constantExpected = (uint)random.Next(1000000, 1000000000);
            uint upvalueExpected = (uint)random.Next(1000000, 1000000000);
            uint upvalueChanged = (uint)random.Next(1000000, 1000000000);
            uint protoConstant = (uint)random.Next(1000000, 1000000000);
            uint protoInput = (uint)random.Next(1000, 100000);
            uint protoExpected = (protoConstant + protoInput) % 2147483647u;
            uint loadExpected = (uint)random.Next(1000000, 1000000000);
            uint cInput = (uint)random.Next(1000, 100000);
            uint transcriptSeed = (uint)random.Next(1, int.MaxValue);
            uint transcriptExpected = transcriptSeed;
            foreach (uint value in new[]
                     {
                         constantExpected, upvalueExpected, upvalueChanged,
                         protoExpected, loadExpected, cInput
                     })
                transcriptExpected = MixWord(transcriptExpected, value);
            uint attestationOffset = unchecked(attestationToken - transcriptExpected);
            uint faultWord = unchecked((uint)random.NextInt64(0, 1L << 32));
            if (faultWord == 0) faultWord = 0xC2B2AE35u;
            uint sealSaltB = unchecked((uint)random.NextInt64(1, int.MaxValue));
            uint sealSaltC = unchecked((uint)random.NextInt64(1, int.MaxValue));

            var keyValues = new Dictionary<string, string>
            {
                ["__KEY_STRING_TABLE__"] = "string",
                ["__KEY_TABLE_TABLE__"] = "table",
                ["__KEY_MATH_TABLE__"] = "math",
                ["__KEY_DEBUG_TABLE__"] = "debug",
                ["__KEY_BYTE__"] = "byte",
                ["__KEY_CHAR__"] = "char",
                ["__KEY_SUB__"] = "sub",
                ["__KEY_CONCAT__"] = "concat",
                ["__KEY_INSERT__"] = "insert",
                ["__KEY_LDEXP__"] = "ldexp",
                ["__KEY_PCALL__"] = "pcall",
                ["__KEY_TYPE__"] = "type",
                ["__KEY_RAWGET__"] = "rawget",
                ["__KEY_RAWSET__"] = "rawset",
                ["__KEY_NEXT__"] = "next",
                ["__KEY_GETMETATABLE__"] = "getmetatable",
                ["__KEY_SETMETATABLE__"] = "setmetatable",
                ["__KEY_RAWEQUAL__"] = "rawequal",
                ["__KEY_TOSTRING__"] = "tostring",
                ["__KEY_SELECT__"] = "select",
                ["__KEY_TONUMBER__"] = "tonumber",
                ["__KEY_GETFENV__"] = "getfenv",
                ["__KEY_UNPACK__"] = "unpack",
                ["__KEY_GETGENV__"] = "getgenv",
                ["__KEY_ENV_CANARY__"] = RN(random, 14, 20),
                ["__KEY_IDENTIFY__"] = "identifyexecutor",
                ["__KEY_CHECKCALLER__"] = "checkcaller",
                ["__KEY_ISC__"] = "iscclosure",
                ["__KEY_ISL__"] = "islclosure",
                ["__KEY_NEWC__"] = "newcclosure",
                ["__KEY_LOADSTRING__"] = "loadstring",
                ["__KEY_TYPEOF__"] = "typeof",
                ["__KEY_GAME__"] = "game",
                ["__KEY_INSTANCE__"] = "Instance",
                ["__KEY_VECTOR3__"] = "Vector3",
                ["__KEY_TASK__"] = "task",
                ["__KEY_GETINFO__"] = "getinfo",
                ["__KEY_INFO__"] = "info",
                ["__KEY_GETCONSTANTS__"] = "getconstants",
                ["__KEY_GETUPVALUES__"] = "getupvalues",
                ["__KEY_GETPROTO__"] = "getproto",
                ["__KEY_GETPROTOS__"] = "getprotos",
                ["__KEY_SETUPVALUE__"] = "setupvalue",
                ["__VALUE_PLAYERS__"] = "Players",
                ["__VALUE_VECTOR3__"] = "Vector3",
                ["__VALUE_INVALID_CHUNK__"] = RN(random, 10, 16),
                ["__VALUE_INVALID_SOURCE__"] = "return )",
                ["__VALUE_LOAD_PREFIX__"] = "return "
            };
            KeyVault keyVault = BuildKeyVault(keyValues, random);

            var captureStatements = new List<string>
            {
                "local GuardIdentify=GuardLookup(__KEY_IDENTIFY__);",
                "local GuardCheckCaller=GuardLookup(__KEY_CHECKCALLER__);",
                "local GuardIsC=GuardLookup(__KEY_ISC__);",
                "local GuardIsL=GuardLookup(__KEY_ISL__);",
                "local GuardNewC=GuardLookup(__KEY_NEWC__);",
                "local GuardLoadString=GuardLookup(__KEY_LOADSTRING__);",
                "local GuardTypeOf=GuardLookup(__KEY_TYPEOF__);",
                "local GuardGame=GuardLookup(__KEY_GAME__);",
                "local GuardInstance=GuardLookup(__KEY_INSTANCE__);",
                "local GuardVector3=GuardLookup(__KEY_VECTOR3__);",
                "local GuardTask=GuardLookup(__KEY_TASK__);",
                "local GuardGetInfo=GuardDebug and RawGet(GuardDebug,__KEY_GETINFO__);",
                "local GuardInfo=GuardDebug and RawGet(GuardDebug,__KEY_INFO__);",
                "local GuardGetConstants=GuardDebug and RawGet(GuardDebug,__KEY_GETCONSTANTS__);",
                "local GuardGetUpvalues=GuardDebug and RawGet(GuardDebug,__KEY_GETUPVALUES__);",
                "local GuardGetProto=GuardDebug and RawGet(GuardDebug,__KEY_GETPROTO__);",
                "local GuardGetProtos=GuardDebug and RawGet(GuardDebug,__KEY_GETPROTOS__);",
                "local GuardSetupValue=GuardDebug and RawGet(GuardDebug,__KEY_SETUPVALUE__);"
            };
            for (int index = captureStatements.Count - 1; index > 0; index--)
            {
                int swap = random.Next(index + 1);
                (captureStatements[index], captureStatements[swap]) = (captureStatements[swap], captureStatements[index]);
            }
            string captureBlock = string.Join("", captureStatements) +
                "local GuardInspector=Type(GuardInfo)=='function' and GuardInfo or GuardGetInfo;";

            string guard = @"
local GuardEvidenceFold, GuardEvidenceA, GuardEvidenceB, GuardEvidenceC, GuardEvidenceD;
local GuardProbe, GuardBindPayload, GuardFaultWord, GuardDecoy;
do
local GuardString = PrimitiveString;
local GuardTable = PrimitiveTable;
local GuardMath = PrimitiveMath;
local GuardDebug = PrimitiveDebug;
local GuardUnpack = PrimitiveGlobalUnpack;
local GuardTableUnpack = PrimitiveTableUnpack;
local GuardGetFEnvGlobal;
__IB2_KEY_VAULT__
GuardGetFEnvGlobal = RawGet(PrimitiveEnvironment, __KEY_GETFENV__);

local GuardEnvOK, GuardEnvironment = PCall(GetFEnv);
if not GuardEnvOK or Type(GuardEnvironment) ~= 'table' then GuardEnvironment = nil; end;
local function GuardEnvironmentRead(GuardReadEnvironment, GuardReadKey)
    if Type(GuardReadEnvironment) ~= 'table' then return nil; end;
    local GuardReadValue = RawGet(GuardReadEnvironment, GuardReadKey);
    if GuardReadValue ~= nil then return GuardReadValue; end;
    local GuardReadOK, GuardIndexedValue = PCall(function()
        return GuardReadEnvironment[GuardReadKey];
    end);
    if GuardReadOK then return GuardIndexedValue; end;
    return nil;
end;
local GuardGetGenV = GuardEnvironmentRead(GuardEnvironment, __KEY_GETGENV__);
local GuardCapOK, GuardCapabilityEnvironment = false, nil;
if Type(GuardGetGenV) == 'function' then
    GuardCapOK, GuardCapabilityEnvironment = PCall(GuardGetGenV);
end;
if not GuardCapOK or Type(GuardCapabilityEnvironment) ~= 'table' then GuardCapabilityEnvironment = nil; end;

local function GuardLookup(GuardLookupKey)
    local GuardLookupValue = GuardEnvironmentRead(GuardCapabilityEnvironment, GuardLookupKey);
    if GuardLookupValue == nil then GuardLookupValue = GuardEnvironmentRead(GuardEnvironment, GuardLookupKey); end;
    return GuardLookupValue;
end;

__IB2_API_CAPTURE_BLOCK__

local GuardCounter = 0;
local GuardNextProbe = 1;
local GuardEpoch = 0;
local GuardState = __IB2_DECOY_SEED__ % 2147483647;
GuardEvidenceFold = 0;
local GuardSealA = (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardEvidenceFold) % 2147483647;
local GuardSealB = (GuardState * 4099 + __IB2_SEAL_SALT_B__ + GuardEvidenceFold % 104729) % 2147483647;
local GuardSealC = (GuardState * 8191 + __IB2_SEAL_SALT_C__ + (GuardEvidenceFold % 65521) * 131) % 2147483647;
local GuardTripped = false;
local GuardAttested = false;
local GuardReportOnly = __IB2_REPORT_ONLY__;
GuardFaultWord = 0;
local GuardPayloadState = 0;
local GuardPayloadSeal = 0;
local GuardPayloadActive = false;
local GuardUpvalue = __IB2_UPVALUE_EXPECTED__;

local function GuardRejectA()
    GuardTripped = true;
    GuardEvidenceA, GuardEvidenceB, GuardEvidenceC, GuardEvidenceD = 0, 0, 0, 0;
    if GuardReportOnly then GuardEvidenceFold = (__IB2_FAULT_WORD__ + 1) % 4294967296; return false; end;
    GuardFaultWord = __IB2_FAULT_WORD__; GuardEvidenceFold = 0;
    while GuardFaultWord == GuardFaultWord do
        GuardFaultWord = (GuardFaultWord * __IB2_SINK_MUL_A__ + GuardState + __IB2_SINK_ADD_A__) % 2147483647;
        GuardState = (GuardState + GuardFaultWord) % 2147483647;
    end;
end;
local function GuardRejectB()
    GuardTripped = true;
    GuardEvidenceA, GuardEvidenceB, GuardEvidenceC, GuardEvidenceD = 0, 0, 0, 0;
    if GuardReportOnly then GuardEvidenceFold = (__IB2_FAULT_WORD__ + 1) % 4294967296; return false; end;
    GuardEvidenceFold = 0; GuardPayloadSeal = __IB2_FAULT_WORD__;
    repeat
        GuardPayloadSeal = (GuardPayloadSeal * __IB2_SINK_MUL_B__ + GuardPayloadState + __IB2_SINK_ADD_B__) % 2147483647;
        GuardPayloadState = (GuardPayloadState + GuardPayloadSeal) % 2147483647;
    until GuardPayloadState ~= GuardPayloadState;
end;
local function GuardRejectC()
    GuardTripped = true;
    GuardEvidenceA, GuardEvidenceB, GuardEvidenceC, GuardEvidenceD = 0, 0, 0, 0;
    if GuardReportOnly then GuardEvidenceFold = (__IB2_FAULT_WORD__ + 1) % 4294967296; return false; end;
    GuardEvidenceFold = 0; GuardFaultWord = __IB2_FAULT_WORD__;
    while not (GuardPayloadState ~= GuardPayloadState) do
        GuardPayloadState = (GuardPayloadState * __IB2_SINK_MUL_C__ + GuardFaultWord) % 2147483647;
        GuardFaultWord = (GuardFaultWord + GuardPayloadState + __IB2_SINK_ADD_C__) % 2147483647;
    end;
end;
local function GuardRejectD()
    GuardTripped = true;
    GuardEvidenceA, GuardEvidenceB, GuardEvidenceC, GuardEvidenceD = 0, 0, 0, 0;
    if GuardReportOnly then GuardEvidenceFold = (__IB2_FAULT_WORD__ + 1) % 4294967296; return false; end;
    GuardEvidenceFold = 0; GuardFaultWord = __IB2_FAULT_WORD__;
    while GuardTripped do
        GuardState = (GuardState * __IB2_SINK_MUL_D__ + GuardFaultWord + __IB2_SINK_ADD_D__) % 2147483647;
        GuardFaultWord = (GuardFaultWord * 257 + GuardState) % 2147483647;
    end;
end;
--__IB2_GUARD_STAGE_1__

local function GuardLuaProbe(GuardProbeValue) return GuardProbeValue; end;
local function GuardConstantProbe() return __IB2_CONSTANT_EXPECTED__; end;
local function GuardUpvalueProbe(GuardProbeValue)
    GuardUpvalue = (GuardUpvalue + GuardProbeValue) % 2147483647;
    return GuardUpvalue;
end;
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

local function GuardTableEmpty(GuardValues)
    return Type(GuardValues) == 'table' and Next(GuardValues) == nil;
end;

local function GuardClassifies(GuardFunction, GuardExpectedC)
    if Type(GuardFunction) ~= 'function' then return false; end;
    local GuardCOK, GuardCResult = PCall(GuardIsC, GuardFunction);
    local GuardLOK, GuardLResult = PCall(GuardIsL, GuardFunction);
    return GuardCOK and GuardLOK and GuardCResult == GuardExpectedC
        and GuardLResult == (not GuardExpectedC);
end;

local function GuardCurrentIdentity()
    if RawGet(PrimitiveEnvironment, __KEY_STRING_TABLE__) ~= GuardString
        or RawGet(PrimitiveEnvironment, __KEY_TABLE_TABLE__) ~= GuardTable
        or RawGet(PrimitiveEnvironment, __KEY_MATH_TABLE__) ~= GuardMath
        or RawGet(PrimitiveEnvironment, __KEY_DEBUG_TABLE__) ~= GuardDebug
        or RawGet(PrimitiveEnvironment, __KEY_PCALL__) ~= PCall
        or RawGet(PrimitiveEnvironment, __KEY_TYPE__) ~= Type
        or RawGet(PrimitiveEnvironment, __KEY_RAWGET__) ~= RawGet
        or RawGet(PrimitiveEnvironment, __KEY_RAWSET__) ~= RawSet
        or RawGet(PrimitiveEnvironment, __KEY_NEXT__) ~= Next
        or RawGet(PrimitiveEnvironment, __KEY_GETMETATABLE__) ~= Getmetatable
        or RawGet(PrimitiveEnvironment, __KEY_SETMETATABLE__) ~= Setmetatable
        or RawGet(PrimitiveEnvironment, __KEY_RAWEQUAL__) ~= RawEqual
        or RawGet(PrimitiveEnvironment, __KEY_TOSTRING__) ~= ToString
        or RawGet(PrimitiveEnvironment, __KEY_SELECT__) ~= Select
        or RawGet(PrimitiveEnvironment, __KEY_TONUMBER__) ~= ToNumber
        or RawGet(PrimitiveEnvironment, __KEY_GETFENV__) ~= GuardGetFEnvGlobal
        or RawGet(GuardString, __KEY_BYTE__) ~= Byte
        or RawGet(GuardString, __KEY_CHAR__) ~= Char
        or RawGet(GuardString, __KEY_SUB__) ~= Sub
        or RawGet(GuardTable, __KEY_CONCAT__) ~= Concat
        or RawGet(GuardTable, __KEY_INSERT__) ~= Insert
        or RawGet(GuardMath, __KEY_LDEXP__) ~= LDExp
        or RawGet(PrimitiveEnvironment, __KEY_UNPACK__) ~= GuardUnpack
        or RawGet(GuardTable, __KEY_UNPACK__) ~= GuardTableUnpack
        or (GuardUnpack or GuardTableUnpack) ~= Unpack then
        return false;
    end;
    if not GuardEnvironment or Type(GuardGetGenV) ~= 'function'
        or GuardEnvironmentRead(GuardEnvironment, __KEY_GETGENV__) ~= GuardGetGenV then return false; end;
    local GuardCurrentEnvOK, GuardCurrentEnvironment = PCall(GuardGetGenV);
    if not GuardCurrentEnvOK or GuardCurrentEnvironment ~= GuardCapabilityEnvironment then return false; end;
    if GuardLookup(__KEY_IDENTIFY__) ~= GuardIdentify
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
        or RawGet(GuardDebug, __KEY_GETINFO__) ~= GuardGetInfo
        or RawGet(GuardDebug, __KEY_INFO__) ~= GuardInfo
        or RawGet(GuardDebug, __KEY_GETCONSTANTS__) ~= GuardGetConstants
        or RawGet(GuardDebug, __KEY_GETUPVALUES__) ~= GuardGetUpvalues
        or RawGet(GuardDebug, __KEY_GETPROTO__) ~= GuardGetProto
        or RawGet(GuardDebug, __KEY_GETPROTOS__) ~= GuardGetProtos
        or RawGet(GuardDebug, __KEY_SETUPVALUE__) ~= GuardSetupValue then return false; end;
    return true;
end;
--__IB2_GUARD_STAGE_2__

local function GuardStrictChallenge()
    if Type(GuardIdentify) ~= 'function' or Type(GuardCheckCaller) ~= 'function'
        or Type(GuardIsC) ~= 'function' or Type(GuardIsL) ~= 'function'
        or Type(GuardNewC) ~= 'function' or Type(GuardLoadString) ~= 'function'
        or Type(GuardTypeOf) ~= 'function' or Type(GuardInspector) ~= 'function'
        or Type(GuardGetConstants) ~= 'function' or Type(GuardGetUpvalues) ~= 'function'
        or (Type(GuardGetProto) ~= 'function' and Type(GuardGetProtos) ~= 'function')
        or Type(GuardSetupValue) ~= 'function' then return false, 0; end;

    if GuardCapabilityEnvironment == GuardEnvironment then return false, 0; end;
    local GuardThreadOld = RawGet(GuardEnvironment, __KEY_ENV_CANARY__);
    local GuardCapabilityOld = RawGet(GuardCapabilityEnvironment, __KEY_ENV_CANARY__);
    local GuardThreadMarker, GuardCapabilityMarker = {}, {};
    local GuardSeparated, GuardPersistent = false, false;
    local GuardCanaryOK = PCall(function()
        RawSet(GuardEnvironment, __KEY_ENV_CANARY__, GuardThreadMarker);
        GuardSeparated = RawGet(GuardCapabilityEnvironment, __KEY_ENV_CANARY__) ~= GuardThreadMarker;
        RawSet(GuardCapabilityEnvironment, __KEY_ENV_CANARY__, GuardCapabilityMarker);
        local GuardRepeatOK, GuardRepeatEnvironment = PCall(GuardGetGenV);
        GuardPersistent = GuardRepeatOK and GuardRepeatEnvironment == GuardCapabilityEnvironment
            and RawGet(GuardRepeatEnvironment, __KEY_ENV_CANARY__) == GuardCapabilityMarker;
    end);
    local GuardThreadRestoreOK = PCall(RawSet, GuardEnvironment, __KEY_ENV_CANARY__, GuardThreadOld);
    local GuardCapabilityRestoreOK = PCall(RawSet, GuardCapabilityEnvironment, __KEY_ENV_CANARY__, GuardCapabilityOld);
    if not GuardCanaryOK or not GuardThreadRestoreOK or not GuardCapabilityRestoreOK
        or not GuardSeparated or not GuardPersistent then return false, 0; end;

    local GuardIdOK1, GuardName1, GuardVersion1 = PCall(GuardIdentify);
    local GuardIdOK2, GuardName2, GuardVersion2 = PCall(GuardIdentify);
    if not GuardIdOK1 or not GuardIdOK2 or Type(GuardName1) ~= 'string'
        or Type(GuardVersion1) ~= 'string' or Type(GuardVersion2) ~= 'string'
        or #GuardName1 < 1 or #GuardName1 > 128 or #GuardVersion1 > 128
        or GuardName1 ~= GuardName2 or GuardVersion1 ~= GuardVersion2 then return false, 0; end;
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

    local GuardPrimitives = {
        Byte, Char, Sub, Concat, Insert, LDExp, Select, PCall, Type, ToString,
        ToNumber, RawGet, RawSet, RawEqual, Next, Setmetatable, Getmetatable, Unpack,
        GuardInspector
    };
    for GuardPrimitiveIndex = 1, #GuardPrimitives do
        if not GuardClassifies(GuardPrimitives[GuardPrimitiveIndex], true) then return false, 0; end;
    end;
    if not GuardClassifies(GuardLuaProbe, false) then return false, 0; end;

    local GuardCConstantsOK = PCall(GuardGetConstants, Byte);
    local GuardCUpvaluesOK, GuardCUpvalues = PCall(GuardGetUpvalues, Byte);
    local GuardCSetupOK = PCall(GuardSetupValue, Byte, 1, 0);
    if GuardCConstantsOK or GuardCSetupOK
        or (GuardCUpvaluesOK and not GuardTableEmpty(GuardCUpvalues)) then return false, 0; end;
    if Type(GuardGetProto) == 'function' then
        local GuardCProtoOK = PCall(GuardGetProto, Byte, 1);
        if GuardCProtoOK then return false, 0; end;
    end;
    if Type(GuardGetProtos) == 'function' then
        local GuardCProtosOK = PCall(GuardGetProtos, Byte);
        if GuardCProtosOK then return false, 0; end;
    end;

    local GuardTranscript = __IB2_TRANSCRIPT_SEED__;
    local function GuardTranscriptWord(GuardTranscriptValue)
        GuardTranscript = (GuardTranscript * 31 + GuardTranscriptValue) % 4294967296;
    end;

    local GuardConstantsOK, GuardConstants = PCall(GuardGetConstants, GuardConstantProbe);
    if not GuardConstantsOK or Type(GuardConstants) ~= 'table' then return false, 0; end;
    GuardTranscriptWord(__IB2_CONSTANT_EXPECTED__);

    local GuardUpvaluesOK, GuardUpvalues = PCall(GuardGetUpvalues, GuardUpvalueProbe);
    if not GuardUpvaluesOK or Type(GuardUpvalues) ~= 'table' then return false, 0; end;
    GuardTranscriptWord(__IB2_UPVALUE_EXPECTED__);

    local GuardSetOK = PCall(GuardSetupValue, GuardUpvalueProbe, 1, __IB2_UPVALUE_CHANGED__);
    local GuardRestoreOK = PCall(GuardSetupValue, GuardUpvalueProbe, 1, __IB2_UPVALUE_EXPECTED__);
    if not GuardSetOK or not GuardRestoreOK or GuardUpvalueProbe(0) ~= __IB2_UPVALUE_EXPECTED__ then return false, 0; end;
    GuardTranscriptWord(__IB2_UPVALUE_CHANGED__);

    local GuardActiveProto = GuardProtoProbe();
    local GuardActiveCallOK, GuardActiveCallResult = PCall(GuardActiveProto, __IB2_PROTO_INPUT__);
    if not GuardActiveCallOK or GuardActiveCallResult ~= __IB2_PROTO_EXPECTED__
        or not GuardClassifies(GuardActiveProto, false) then return false, 0; end;

    local GuardSawInactiveProto = false;
    if Type(GuardGetProto) == 'function' then
        local GuardProtoOK = PCall(GuardGetProto, GuardProtoProbe, 1);
        if not GuardProtoOK then return false, 0; end;
        GuardSawInactiveProto = true;

        local GuardActivatedOK, GuardActivated = PCall(GuardGetProto, GuardProtoProbe, 1, true);
        if not GuardActivatedOK or Type(GuardActivated) ~= 'table' then return false, 0; end;
    end;
    if Type(GuardGetProtos) == 'function' then
        local GuardProtosOK, GuardProtos = PCall(GuardGetProtos, GuardProtoProbe);
        if not GuardProtosOK or Type(GuardProtos) ~= 'table' then return false, 0; end;
        GuardSawInactiveProto = true;
    end;
    if not GuardSawInactiveProto then return false, 0; end;
    GuardTranscriptWord(__IB2_PROTO_EXPECTED__);

    local GuardInvalidSource = __VALUE_INVALID_SOURCE__;
    local GuardInvalidOK, GuardInvalidFunction, GuardInvalidError = PCall(
        GuardLoadString, GuardInvalidSource, __VALUE_INVALID_CHUNK__);
    if not GuardInvalidOK or GuardInvalidFunction ~= nil or Type(GuardInvalidError) ~= 'string'
        or #GuardInvalidError < 1 then return false, 0; end;

    local GuardLoadSource = __VALUE_LOAD_PREFIX__ .. ToString(__IB2_LOAD_EXPECTED__);
    local GuardCompileOK, GuardLoaded = PCall(GuardLoadString, GuardLoadSource);
    if not GuardCompileOK or Type(GuardLoaded) ~= 'function' then return false, 0; end;
    local GuardLoadedOK, GuardLoadedValue = PCall(GuardLoaded);
    if not GuardLoadedOK or GuardLoadedValue ~= __IB2_LOAD_EXPECTED__
        or not GuardClassifies(GuardLoaded, false) then return false, 0; end;
    local GuardLoadedConstantsOK, GuardLoadedConstants = PCall(GuardGetConstants, GuardLoaded);
    if not GuardLoadedConstantsOK or not GuardTableContains(GuardLoadedConstants, __IB2_LOAD_EXPECTED__) then return false, 0; end;
    GuardTranscriptWord(__IB2_LOAD_EXPECTED__);

    local GuardWrapOK, GuardWrapped = PCall(GuardNewC, GuardCBody);
    if not GuardWrapOK or Type(GuardWrapped) ~= 'function' then return false, 0; end;
    local GuardWrappedOK, GuardWrappedValue = PCall(GuardWrapped, -__IB2_C_INPUT__);
    if not GuardWrappedOK or GuardWrappedValue ~= __IB2_C_INPUT__
        or not GuardClassifies(GuardWrapped, true) then return false, 0; end;
    local GuardWrappedUpvaluesOK, GuardWrappedUpvalues = PCall(GuardGetUpvalues, GuardWrapped);
    if GuardWrappedUpvaluesOK and not GuardTableEmpty(GuardWrappedUpvalues) then return false, 0; end;
    GuardTranscriptWord(__IB2_C_INPUT__);

    return true, GuardTranscript;
end;
--__IB2_GUARD_STAGE_3__

__IB2_DECOY_GRAPH__

local function GuardPayloadExpectedSeal()
    local GuardPayloadLow = GuardPayloadState % 65536;
    local GuardPayloadHigh = (GuardPayloadState - GuardPayloadLow) / 65536;
    return (GuardPayloadLow * 65599 + GuardPayloadHigh * 257
        + GuardState * 4099 + GuardSealA + GuardSealB + GuardSealC + GuardEvidenceFold + __IB2_PAYLOAD_SEAL_SALT__) % 2147483647;
end;

GuardBindPayload = function(GuardVMState, GuardChunkState, GuardEntryState, GuardInstructionPoint, GuardOpcodeState, GuardOpcodeSeal)
    if GuardTripped then return GuardReject(); end;
    if GuardSealA ~= (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardEvidenceFold) % 2147483647
        or GuardSealC ~= (GuardState * 8191 + __IB2_SEAL_SALT_C__ + (GuardEvidenceFold % 65521) * 131) % 2147483647 then
        return GuardReject();
    end;
    if GuardPayloadActive and GuardPayloadSeal ~= GuardPayloadExpectedSeal() then return GuardReject(); end;
    local GuardVMLow = GuardVMState % 65536;
    local GuardVMHigh = (GuardVMState - GuardVMLow) / 65536;
    local GuardChunkLow = GuardChunkState % 65536;
    local GuardChunkHigh = (GuardChunkState - GuardChunkLow) / 65536;
    local GuardEntryLow = GuardEntryState % 65536;
    local GuardEntryHigh = (GuardEntryState - GuardEntryLow) / 65536;
    local GuardOpcodeLow = GuardOpcodeState % 65536;
    local GuardOpcodeHigh = (GuardOpcodeState - GuardOpcodeLow) / 65536;
    GuardPayloadState = (GuardPayloadState * 4093 + GuardVMLow * 257 + GuardVMHigh * 17
        + GuardChunkLow * 251 + GuardChunkHigh * 29 + GuardEntryLow * 13 + GuardEntryHigh * 7
        + GuardOpcodeLow * 19 + GuardOpcodeHigh * 11 + (GuardOpcodeSeal % 65521) * 37
        + GuardInstructionPoint * 31 + GuardState + GuardEvidenceFold + __IB2_PAYLOAD_STATE_SALT__) % 2147483647;
    GuardPayloadState = GuardBXor(GuardPayloadState,
        (GuardVMState % 2147483648 + GuardChunkState % 2147483648
            + GuardOpcodeState % 2147483648 + GuardOpcodeSeal % 2147483648) % 2147483648) % 2147483647;
    GuardPayloadActive = true;
    -- Payload execution changes GuardState, and the new GuardState immediately
    -- reseals payload state. Periodic probes perform the inverse update below.
    GuardState = (GuardState + GuardPayloadState % 65521 + GuardInstructionPoint * 17
        + GuardOpcodeState % 32749 + GuardOpcodeSeal % 16381 + GuardEpoch) % 2147483647;
    GuardSealA = (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardEvidenceFold) % 2147483647;
    GuardSealB = (GuardState * 4099 + __IB2_SEAL_SALT_B__ + GuardEvidenceFold % 104729) % 2147483647;
    GuardSealC = (GuardState * 8191 + __IB2_SEAL_SALT_C__ + (GuardEvidenceFold % 65521) * 131) % 2147483647;
    GuardPayloadSeal = GuardPayloadExpectedSeal();
    return false;
end;
--__IB2_GUARD_STAGE_4__

GuardProbe = function(Force)
    GuardCounter = GuardCounter + 1;
    if GuardTripped then return GuardReject(); end;
    if GuardPayloadActive and GuardPayloadSeal ~= GuardPayloadExpectedSeal() then return GuardReject(); end;
    if not Force and GuardCounter < GuardNextProbe then return false; end;
    if GuardSealB ~= (GuardState * 4099 + __IB2_SEAL_SALT_B__ + GuardEvidenceFold % 104729) % 2147483647 then
        return GuardReject();
    end;

    GuardEpoch = GuardEpoch + 1;
    local GuardHeavy = Force or not GuardAttested or GuardEpoch % __IB2_HEAVY_PERIOD__ == 0;
    local GuardValid = GuardCurrentIdentity();
    local GuardTranscript = __IB2_TRANSCRIPT_EXPECTED__;
    if GuardValid and GuardHeavy then
        GuardValid, GuardTranscript = GuardStrictChallenge();
    end;
    if GuardValid and GuardTranscript ~= __IB2_TRANSCRIPT_EXPECTED__ then GuardValid = false; end;
    if not GuardValid then return GuardReject(); end;
    if GuardSealC ~= (GuardState * 8191 + __IB2_SEAL_SALT_C__ + (GuardEvidenceFold % 65521) * 131) % 2147483647 then
        return GuardReject();
    end;

    if not GuardAttested then
        local GuardCompatibility = (GuardTranscript + __IB2_ATTESTATION_OFFSET__) % 4294967296;
        GuardEvidenceA = (GuardCompatibility * 65599 + 2654435769) % 4294967296;
        GuardEvidenceB = (GuardCompatibility * 48271 + 1831565813) % 4294967296;
        GuardEvidenceC = ((GuardCompatibility + 2781082087) * 131071 + 2135587861) % 4294967296;
        GuardEvidenceD = ((GuardCompatibility + 3302136427) * 524287 + 3266489909) % 4294967296;
        GuardCompatibility = 0;
        GuardEvidenceFold = (GuardEvidenceA + GuardEvidenceB * 3 + GuardEvidenceC * 5 + GuardEvidenceD * 7) % 2147483647;
        GuardAttested = true;
    end;

    GuardState = (GuardState * 48271 + GuardCounter + GuardEpoch * 17 + GuardEvidenceFold % 65521) % 2147483647;
    GuardSealA = (GuardState * 65599 + __IB2_SEAL_SALT__ + GuardEvidenceFold) % 2147483647;
    GuardSealB = (GuardState * 4099 + __IB2_SEAL_SALT_B__ + GuardEvidenceFold % 104729) % 2147483647;
    GuardSealC = (GuardState * 8191 + __IB2_SEAL_SALT_C__ + (GuardEvidenceFold % 65521) * 131) % 2147483647;
    if GuardPayloadActive then GuardPayloadSeal = GuardPayloadExpectedSeal(); end;
    GuardNextProbe = GuardCounter + __IB2_GUARD_INTERVAL__ + (GuardState % __IB2_GUARD_JITTER__);
    return false;
end;
--__IB2_GUARD_STAGE_5__

if GuardProbe(true) then return GuardDecoy(); end;
end;
";

            var replacements = new Dictionary<string, string>
            {
                ["__IB2_GUARD_INTERVAL__"] = probeInterval.ToString(),
                ["__IB2_GUARD_JITTER__"] = probeJitter.ToString(),
                ["__IB2_HEAVY_PERIOD__"] = heavyPeriod.ToString(),
                ["__IB2_DECOY_SEED__"] = decoySeed.ToString(),
                ["__IB2_SEAL_SALT__"] = sealSalt.ToString(),
                ["__IB2_SEAL_SALT_B__"] = sealSaltB.ToString(),
                ["__IB2_SEAL_SALT_C__"] = sealSaltC.ToString(),
                ["__IB2_SINK_MUL_A__"] = (30011 + random.Next(20000)).ToString(),
                ["__IB2_SINK_ADD_A__"] = (257 + random.Next(100000)).ToString(),
                ["__IB2_SINK_MUL_B__"] = (33013 + random.Next(20000)).ToString(),
                ["__IB2_SINK_ADD_B__"] = (521 + random.Next(100000)).ToString(),
                ["__IB2_SINK_MUL_C__"] = (36007 + random.Next(20000)).ToString(),
                ["__IB2_SINK_ADD_C__"] = (911 + random.Next(100000)).ToString(),
                ["__IB2_SINK_MUL_D__"] = (39019 + random.Next(20000)).ToString(),
                ["__IB2_SINK_ADD_D__"] = (1237 + random.Next(100000)).ToString(),
                ["__IB2_PAYLOAD_SEAL_SALT__"] = payloadSealSalt.ToString(),
                ["__IB2_PAYLOAD_STATE_SALT__"] = payloadStateSalt.ToString(),
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
                ["__IB2_FAULT_WORD__"] = faultWord.ToString(),
                ["__IB2_REPORT_ONLY__"] = TemporaryGlobalSinkBypass ? "true" : "false",
                ["__IB2_DECOY_GRAPH__"] = BuildDecoyGraph(decoySeed, random),
                ["__IB2_KEY_VAULT__"] = keyVault.Prelude,
                ["__IB2_API_CAPTURE_BLOCK__"] = captureBlock
            };
            foreach (KeyValuePair<string, string> replacement in replacements)
                guard = guard.Replace(replacement.Key, replacement.Value);
            foreach (KeyValuePair<string, string> reference in keyVault.References)
                guard = guard.Replace(reference.Key, reference.Value);

            int rejectionOffset = random.Next(4);
            int rejectionCount = 0;
            guard = System.Text.RegularExpressions.Regex.Replace(guard, @"\bGuardReject\(\)", _ =>
                "GuardReject" + (char)('A' + ((rejectionOffset + rejectionCount++) % 4)) + "()");
            return guard;
        }

        public static string GenerateHandlerNoise(Random random)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            var parts = new List<string>();
            var expressions = new[]
            {
                "string.byte(\"A\")==65", "#{\"x\"}==1", "(-1<0)==true", "tostring(1)==\"1\""
            };
            parts.Add("local " + RN(random, 4, 8) + "=(" + expressions[random.Next(4)] + ")");
            string function = RN(random, 5, 8);
            parts.Add("local function " + function + "(...)local _={...};return #_ end;" + function + "(1,2,3);" + function + "=nil");
            return "\t" + string.Join(";", parts) + ";\n";
        }

        public static string GenerateLoopNoise(Random random)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            int modulus = new[] {7, 11, 13, 17, 19}[random.Next(5)];
            var output = new StringBuilder();
            output.Append("\tif (InstrPoint%"); output.Append(modulus); output.Append("==0) then\n");
            output.Append("\t\tlocal _lt={};for _li=1,20 do _lt[_li]={_li}end;\n");
            output.Append("\tend;\n");
            return output.ToString();
        }
    }
}
