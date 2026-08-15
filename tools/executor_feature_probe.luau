-- IronBrew2 strict executor feature probe
-- Run this file by itself in the executor, not through the obfuscator.
-- It reads capabilities, mutates/restores private probe upvalues, saves the report
-- as IronBrew2_executor_probe.txt, verifies it with readfile when available, and copies
-- the same report to the clipboard when setclipboard/toclipboard is available.
-- It does not use the network, hooks, getgc, background tasks, or infinite loops.

local Output = {}
local Failures = {}
local Print = print
local Type = type
local ToString = tostring
local PCall = pcall
local RawGet = rawget
local RawSet = rawset
local RawEqual = rawequal
local Next = next
local Setmetatable = setmetatable
local Getmetatable = getmetatable
local StringLibrary = string
local TableLibrary = table
local MathLibrary = math
local DebugLibrary = debug
local GetFEnvSnapshot = getfenv
local UnpackGlobal = unpack
local TableUnpack = TableLibrary and TableLibrary.unpack
local Unpack = UnpackGlobal or TableUnpack

local function escape(value)
    local ok, text = PCall(ToString, value)
    if not ok then
        text = "<tostring-error>"
    end
    text = text:gsub("\\", "\\\\")
        :gsub("\r", "\\r")
        :gsub("\n", "\\n")
        :gsub("|", "\\x7C")
    if #text > 600 then
        text = text:sub(1, 600) .. "..."
    end
    return text
end

local function scalar(value)
    local kind = Type(value)
    if kind == "nil" or kind == "boolean" or kind == "number" or kind == "string" then
        return kind .. ":" .. escape(value)
    end
    return kind .. ":" .. escape(value)
end

local function tableSummary(value)
    if Type(value) ~= "table" then
        return scalar(value)
    end
    local items = {}
    local count = 0
    local ok, err = PCall(function()
        for key, item in Next, value do
            count = count + 1
            if #items < 16 then
                items[#items + 1] = scalar(key) .. "=" .. scalar(item)
            end
        end
    end)
    if not ok then
        return "table:<iteration-error:" .. escape(err) .. ">"
    end
    return "table(count=" .. count .. "){" .. table.concat(items, ",") .. "}"
end

local function emit(section, key, ok, value)
    Output[#Output + 1] = "IB2PROBE|" .. escape(section) .. "|" .. escape(key)
        .. "|" .. (ok and "OK" or "FAIL") .. "|" .. tableSummary(value)
end

local function contract(name, ok, detail)
    emit("contract", name, ok == true, detail)
    if ok ~= true then
        Failures[#Failures + 1] = name
    end
    return ok == true
end

local function call(fn, ...)
    if Type(fn) ~= "function" then
        return false, nil, nil, "not-a-function"
    end
    local result = {PCall(fn, ...)}
    return result[1], result[2], result[3], result[4]
end

local function safeRawGet(container, key)
    if Type(container) ~= "table" then
        return nil
    end
    local ok, value = PCall(RawGet, container, key)
    if ok then
        return value
    end
    return nil
end

local BaseEnvironment = nil
local GetFEnv = GetFEnvSnapshot
if Type(GetFEnv) == "function" then
    local ok, value = call(GetFEnv)
    if ok and Type(value) == "table" then
        BaseEnvironment = value
    end
end
if not BaseEnvironment and Type(_G) == "table" then
    BaseEnvironment = _G
end
emit("environment", "base_environment", Type(BaseEnvironment) == "table",
    "type=" .. Type(BaseEnvironment) .. " (contents intentionally not dumped)")

-- The production guard intentionally obtains getgenv from the current environment.
local GetGenV = safeRawGet(BaseEnvironment, "getgenv")
local CapabilityEnvironment = nil
local GetGenVOK, GetGenVResult = call(GetGenV)
if GetGenVOK and Type(GetGenVResult) == "table" then
    CapabilityEnvironment = GetGenVResult
end
emit("environment", "getgenv_type", Type(GetGenV) == "function", Type(GetGenV))
emit("environment", "getgenv_result", GetGenVOK and Type(CapabilityEnvironment) == "table",
    "type=" .. Type(CapabilityEnvironment) .. " (contents intentionally not dumped)")

local function lookup(name)
    local value = safeRawGet(CapabilityEnvironment, name)
    if value == nil then
        value = safeRawGet(BaseEnvironment, name)
    end
    return value
end

local GetGenVSecondOK, GetGenVSecond = call(GetGenV)
contract("stable_getgenv",
    Type(GetGenV) == "function" and GetGenVOK and GetGenVSecondOK
        and Type(CapabilityEnvironment) == "table" and GetGenVSecond == CapabilityEnvironment,
    "first=" .. scalar(GetGenVResult) .. ",second=" .. scalar(GetGenVSecond))

local Identify = lookup("identifyexecutor")
local IdentifyAlias = lookup("getexecutorname")
local ExecutorNameAlias = lookup("executorname")
local IdOK1, Name1, Version1 = call(Identify)
local IdOK2, Name2, Version2 = call(Identify)
local IdentityStable = IdOK1 and IdOK2 and Type(Name1) == "string"
    and #Name1 >= 1 and #Name1 <= 128 and Name1 == Name2
    and (Type(Version1) == "nil" or Type(Version1) == "string" or Type(Version1) == "number")
    and Type(Version1) == Type(Version2) and ToString(Version1) == ToString(Version2)
emit("identity", "identifyexecutor_first", IdOK1, "name=" .. scalar(Name1) .. ",version=" .. scalar(Version1))
emit("identity", "identifyexecutor_second", IdOK2, "name=" .. scalar(Name2) .. ",version=" .. scalar(Version2))
contract("stable_nonempty_identity", IdentityStable,
    "name1=" .. scalar(Name1) .. ",name2=" .. scalar(Name2)
        .. ",version1=" .. scalar(Version1) .. ",version2=" .. scalar(Version2))

local function checkIdentityAlias(label, fn)
    if fn == nil then
        emit("identity", label, true, "absent")
        return true
    end
    local ok, aliasName, aliasVersion = call(fn)
    emit("identity", label, ok and aliasName == Name1,
        "type=" .. Type(fn) .. ",name=" .. scalar(aliasName) .. ",version=" .. scalar(aliasVersion))
    return Type(fn) == "function" and ok and aliasName == Name1
end
local IdentifyAliasOK = checkIdentityAlias("getexecutorname", IdentifyAlias)
local ExecutorNameAliasOK = checkIdentityAlias("executorname", ExecutorNameAlias)
contract("identity_aliases_consistent", IdentifyAliasOK and ExecutorNameAliasOK,
    "optional aliases must return the identifyexecutor name")

local CheckCaller = lookup("checkcaller")
local CallerOK, Caller = call(CheckCaller)
emit("executor", "checkcaller", CallerOK and Caller == true, Caller)
contract("checkcaller_true", Type(CheckCaller) == "function" and CallerOK and Caller == true,
    "type=" .. Type(CheckCaller) .. ",result=" .. scalar(Caller))

local IsC = lookup("iscclosure")
local IsL = lookup("islclosure")
local NewC = lookup("newcclosure")
local LoadString = lookup("loadstring")
local TypeOf = lookup("typeof")
local Game = lookup("game")
local Instance = lookup("Instance")
local Vector3 = lookup("Vector3")
local Task = lookup("task")
local Debug = DebugLibrary

local DebugFunctions = {
    gethook = Debug and safeRawGet(Debug, "gethook"),
    getinfo = Debug and safeRawGet(Debug, "getinfo"),
    info = Debug and safeRawGet(Debug, "info"),
    getconstants = Debug and safeRawGet(Debug, "getconstants"),
    getupvalues = Debug and safeRawGet(Debug, "getupvalues"),
    getproto = Debug and safeRawGet(Debug, "getproto"),
    getprotos = Debug and safeRawGet(Debug, "getprotos"),
    setupvalue = Debug and safeRawGet(Debug, "setupvalue"),
}

for _, name in ipairs({
    "iscclosure", "islclosure", "newcclosure", "loadstring", "typeof",
    "game", "Instance", "Vector3", "task"
}) do
    local value = lookup(name)
    emit("surface", name, value ~= nil, Type(value))
end
for _, name in ipairs({
    "gethook", "getinfo", "info", "getconstants", "getupvalues",
    "getproto", "getprotos", "setupvalue"
}) do
    local value = DebugFunctions[name]
    emit("debug_surface", name, value ~= nil, Type(value))
end

local Inspector = Type(DebugFunctions.info) == "function" and DebugFunctions.info or DebugFunctions.getinfo
contract("required_executor_functions",
    Type(IsC) == "function" and Type(IsL) == "function"
        and Type(NewC) == "function" and Type(LoadString) == "function"
        and Type(TypeOf) == "function",
    "isc=" .. Type(IsC) .. ",isl=" .. Type(IsL) .. ",newc=" .. Type(NewC)
        .. ",loadstring=" .. Type(LoadString) .. ",typeof=" .. Type(TypeOf))
contract("required_debug_functions",
    Type(Inspector) == "function"
        and Type(DebugFunctions.getconstants) == "function"
        and Type(DebugFunctions.getupvalues) == "function"
        and (Type(DebugFunctions.getproto) == "function" or Type(DebugFunctions.getprotos) == "function")
        and Type(DebugFunctions.setupvalue) == "function",
    "inspector=" .. Type(Inspector)
        .. ",getconstants=" .. Type(DebugFunctions.getconstants)
        .. ",getupvalues=" .. Type(DebugFunctions.getupvalues)
        .. ",getproto=" .. Type(DebugFunctions.getproto)
        .. ",getprotos=" .. Type(DebugFunctions.getprotos)
        .. ",setupvalue=" .. Type(DebugFunctions.setupvalue))

local HookClean = true
if Type(DebugFunctions.gethook) == "function" then
    local ok, hook = call(DebugFunctions.gethook)
    HookClean = ok and hook == nil
    emit("debug", "active_hook", HookClean, hook)
else
    emit("debug", "active_hook", true, "gethook absent")
end
contract("no_active_debug_hook", HookClean, "debug.gethook must be nil when available")

local HostOK, HostResult, HostDetail = PCall(function()
    local players = Game:GetService("Players")
    local vector = Vector3.new()
    local vectorKind = TypeOf(vector)
    local metatableKind = TypeOf(Setmetatable({}, {}))
    local result = (Type(Game) == "table" or Type(Game) == "userdata")
        and Type(Instance) == "table" and Type(Vector3) == "table" and Type(Task) == "table"
        and players ~= nil and players.ClassName == "Players"
        and vectorKind == "Vector3" and metatableKind == "table"
        and Type(Instance.new) == "function"
        and Type(Task.wait) == "function"
        and Type(Task.spawn) == "function"
        and Type(Task.defer) == "function"
    return result,
        "players=" .. scalar(players and players.ClassName)
            .. ",vector_type=" .. scalar(vectorKind)
            .. ",metatable_type=" .. scalar(metatableKind)
            .. ",game=" .. Type(Game) .. ",Instance=" .. Type(Instance)
            .. ",Vector3=" .. Type(Vector3) .. ",task=" .. Type(Task)
            .. ",Instance.new=" .. Type(Instance and Instance.new)
            .. ",task.wait=" .. Type(Task and Task.wait)
            .. ",task.spawn=" .. Type(Task and Task.spawn)
            .. ",task.defer=" .. Type(Task and Task.defer)
end)
local HostPass = HostOK and HostResult == true
emit("host", "roblox_contract", HostPass,
    HostOK and HostDetail or ("error=" .. scalar(HostResult)))
contract("roblox_host_behavior", HostPass,
    HostOK and HostDetail or ("error=" .. scalar(HostResult)))

local function LuaProbe(value)
    return value
end
local ClassOK1, ByteIsC = call(IsC, string.byte)
local ClassOK2, ByteIsL = call(IsL, string.byte)
local ClassOK3, ProbeIsC = call(IsC, LuaProbe)
local ClassOK4, ProbeIsL = call(IsL, LuaProbe)
emit("classifier", "string.byte", ClassOK1 and ClassOK2,
    "isc=" .. scalar(ByteIsC) .. ",isl=" .. scalar(ByteIsL))
emit("classifier", "lua_probe", ClassOK3 and ClassOK4,
    "isc=" .. scalar(ProbeIsC) .. ",isl=" .. scalar(ProbeIsL))
contract("closure_classifier_behavior",
    ClassOK1 and ClassOK2 and ClassOK3 and ClassOK4
        and ByteIsC == true and ByteIsL == false
        and ProbeIsC == false and ProbeIsL == true,
    "byte(isc=" .. scalar(ByteIsC) .. ",isl=" .. scalar(ByteIsL)
        .. "),lua(isc=" .. scalar(ProbeIsC) .. ",isl=" .. scalar(ProbeIsL) .. ")")

local function sourceInfo(fn)
    if Type(fn) ~= "function" or Type(Inspector) ~= "function" then
        return false, false, "missing function/inspector"
    end
    if Type(DebugFunctions.info) == "function" then
        local ok, source = call(DebugFunctions.info, fn, "s")
        return ok and Type(source) == "string", ok and source == "[C]",
            "debug.info source=" .. scalar(source)
    end
    local ok, info = call(DebugFunctions.getinfo, fn, "S")
    local what = ok and Type(info) == "table" and info.what or nil
    local source = ok and Type(info) == "table" and info.source or nil
    return ok and Type(what) == "string", what == "C",
        "debug.getinfo what=" .. scalar(what) .. ",source=" .. scalar(source)
end

local PrimitiveList = {
    {"string.byte", string and string.byte},
    {"string.char", string and string.char},
    {"string.sub", string and string.sub},
    {"table.concat", table and table.concat},
    {"table.insert", table and table.insert},
    {"math.ldexp", math and math.ldexp},
    {"select", select},
    {"pcall", pcall},
    {"type", type},
    {"tostring", tostring},
    {"tonumber", tonumber},
    {"rawget", rawget},
    {"rawset", rawset},
    {"rawequal", rawequal},
    {"next", next},
    {"setmetatable", setmetatable},
    {"getmetatable", getmetatable},
    {"unpack", Unpack},
}
local PrimitiveProvenanceOK = true
for index = 1, #PrimitiveList do
    local item = PrimitiveList[index]
    local known, native, detail = sourceInfo(item[2])
    local ok = Type(item[2]) == "function" and known and native
    if not ok then
        PrimitiveProvenanceOK = false
    end
    emit("primitive_provenance", item[1], ok, detail)
end
local LuaKnown, LuaNative, LuaDetail = sourceInfo(LuaProbe)
emit("primitive_provenance", "lua_probe", LuaKnown and not LuaNative, LuaDetail)
PrimitiveProvenanceOK = PrimitiveProvenanceOK and LuaKnown and not LuaNative
local InspectorKnown, InspectorNative, InspectorDetail = sourceInfo(Inspector)
emit("primitive_provenance", "debug_inspector", InspectorKnown and InspectorNative, InspectorDetail)
PrimitiveProvenanceOK = PrimitiveProvenanceOK and InspectorKnown and InspectorNative
contract("primitive_native_provenance", PrimitiveProvenanceOK,
    "all listed primitives and inspector must be native; Lua probe must not be native")

local function containsValue(values, expected)
    if Type(values) ~= "table" then
        return false
    end
    local ok, found = PCall(function()
        for _, item in Next, values do
            if item == expected then
                return true
            end
        end
        return false
    end)
    return ok and found == true
end

local ConstantExpected = 718281828
local function ConstantProbe()
    return 718281828
end
local ConstantsOK, Constants = call(DebugFunctions.getconstants, ConstantProbe)
local ConstantFound = ConstantsOK and containsValue(Constants, ConstantExpected)
emit("debug_behavior", "getconstants_local", ConstantFound, Constants)
contract("debug_constants_behavior", ConstantFound,
    "expected=" .. ConstantExpected .. ",values=" .. tableSummary(Constants))

local UpvalueExpected = 314159265
local UpvalueChanged = 271828182
local ProbeUpvalue = UpvalueExpected
local function UpvalueProbe(value)
    return ProbeUpvalue + value
end
local UpvaluesOK, Upvalues = call(DebugFunctions.getupvalues, UpvalueProbe)
local UpvalueFound = UpvaluesOK and containsValue(Upvalues, UpvalueExpected)
emit("debug_behavior", "getupvalues_local", UpvalueFound, Upvalues)
contract("debug_upvalues_behavior", UpvalueFound,
    "expected=" .. UpvalueExpected .. ",values=" .. tableSummary(Upvalues))

local SetOK, SetResult = call(DebugFunctions.setupvalue, UpvalueProbe, 1, UpvalueChanged)
local ChangedOK = SetOK and UpvalueProbe(0) == UpvalueChanged
local RestoreOK, RestoreResult = call(DebugFunctions.setupvalue, UpvalueProbe, 1, UpvalueExpected)
local RestoredOK = RestoreOK and UpvalueProbe(0) == UpvalueExpected
emit("debug_behavior", "setupvalue_change_restore", ChangedOK and RestoredOK,
    "set_result=" .. scalar(SetResult) .. ",restore_result=" .. scalar(RestoreResult)
        .. ",changed=" .. scalar(ChangedOK) .. ",restored=" .. scalar(RestoredOK))
contract("debug_setupvalue_behavior", ChangedOK and RestoredOK,
    "index=1,set_ok=" .. scalar(SetOK) .. ",restore_ok=" .. scalar(RestoreOK))

local ProtoInput = 12345
local ProtoExpected = 987654321 + ProtoInput
local function ProtoProbe()
    local function ProtoChild(value)
        return value + 987654321
    end
    return ProtoChild
end
local ProtoCandidate = nil
local ProtoGetDetail = "none"
if Type(DebugFunctions.getproto) == "function" then
    local ok, value = call(DebugFunctions.getproto, ProtoProbe, 1, true)
    ProtoGetDetail = "getproto(fn,1,true):ok=" .. scalar(ok) .. ",value=" .. tableSummary(value)
    if ok and Type(value) == "function" then
        ProtoCandidate = value
    elseif ok and Type(value) == "table" then
        for _, item in Next, value do
            if Type(item) == "function" then
                ProtoCandidate = item
                break
            end
        end
    end
end
if not ProtoCandidate and Type(DebugFunctions.getprotos) == "function" then
    local ok, value = call(DebugFunctions.getprotos, ProtoProbe)
    ProtoGetDetail = ProtoGetDetail .. ";getprotos:ok=" .. scalar(ok) .. ",value=" .. tableSummary(value)
    if ok and Type(value) == "table" then
        for _, item in Next, value do
            if Type(item) == "function" then
                ProtoCandidate = item
                break
            end
        end
    end
end
local ProtoCallOK, ProtoResult = call(ProtoCandidate, ProtoInput)
local ProtoClassOK, ProtoIsL = call(IsL, ProtoCandidate)
local ProtoPass = Type(ProtoCandidate) == "function" and ProtoCallOK
    and ProtoResult == ProtoExpected and ProtoClassOK and ProtoIsL == true
emit("debug_behavior", "proto", ProtoPass,
    ProtoGetDetail .. ";call=" .. scalar(ProtoResult) .. ",isl=" .. scalar(ProtoIsL))
contract("debug_proto_behavior", ProtoPass,
    "expected=" .. ProtoExpected .. ",candidate=" .. Type(ProtoCandidate)
        .. ",result=" .. scalar(ProtoResult) .. ",isl=" .. scalar(ProtoIsL))

-- Additional non-gating diagnostics for common getproto signature differences.
if Type(DebugFunctions.getproto) == "function" then
    local ok, value = call(DebugFunctions.getproto, ProtoProbe, 1)
    emit("compatibility", "getproto_without_activation_flag", ok, value)
end

local LoadExpected = 424242424
local CompileOK, Loaded, LoadError = call(LoadString, "return " .. ToString(LoadExpected))
local LoadedCallOK, LoadedValue = call(Loaded)
local LoadedCOK, LoadedC = call(IsC, Loaded)
local LoadedLOK, LoadedL = call(IsL, Loaded)
local LoadedConstantsOK, LoadedConstants = call(DebugFunctions.getconstants, Loaded)
local LoadedConstantFound = LoadedConstantsOK and containsValue(LoadedConstants, LoadExpected)
local LoadedKnown, LoadedNative, LoadedSource = sourceInfo(Loaded)
local LoadPass = CompileOK and Type(Loaded) == "function" and LoadedCallOK
    and LoadedValue == LoadExpected and LoadedCOK and LoadedLOK
    and LoadedC == false and LoadedL == true and LoadedConstantFound
    and LoadedKnown and not LoadedNative
emit("loadstring", "compile_and_run", LoadPass,
    "compile=" .. scalar(CompileOK) .. ",error=" .. scalar(LoadError)
        .. ",value=" .. scalar(LoadedValue) .. ",isc=" .. scalar(LoadedC)
        .. ",isl=" .. scalar(LoadedL) .. ",constants=" .. tableSummary(LoadedConstants)
        .. ",source=" .. LoadedSource)
contract("loadstring_behavior", LoadPass,
    "value/classification/constants/source must all agree")

local function CBody(value)
    return math.abs(value)
end
local WrapOK, Wrapped = call(NewC, CBody)
local WrappedCallOK, WrappedValue = call(Wrapped, -13579)
local WrappedCOK, WrappedC = call(IsC, Wrapped)
local WrappedLOK, WrappedL = call(IsL, Wrapped)
local WrappedKnown, WrappedNative, WrappedSource = sourceInfo(Wrapped)
local WrapPass = WrapOK and Type(Wrapped) == "function" and WrappedCallOK
    and WrappedValue == 13579 and WrappedCOK and WrappedLOK
    and WrappedC == true and WrappedL == false and WrappedKnown and WrappedNative
emit("newcclosure", "wrap_call_classify_source", WrapPass,
    "value=" .. scalar(WrappedValue) .. ",isc=" .. scalar(WrappedC)
        .. ",isl=" .. scalar(WrappedL) .. ",source=" .. WrappedSource)
contract("newcclosure_behavior", WrapPass,
    "wrapped closure must call correctly and present as native C closure")

-- Read-only capability inventory. Presence is diagnostic only and is not a pass signal.
for _, name in ipairs({
    "hookfunction", "hookmetamethod", "getgc", "getreg", "getregistry",
    "getconnections", "getsenv", "getrenv", "gethui", "cloneref",
    "clonefunction", "isexecutorclosure", "is_synapse_function", "isourclosure",
    "writefile", "readfile", "isfile", "appendfile", "makefolder",
    "setclipboard", "toclipboard",
    "request", "http_request", "syn", "crypt", "Drawing"
}) do
    emit("inventory", name, true, Type(lookup(name)))
end

-- Verify snapshots did not change while this probe was running.
local CoreSnapshotChecks = {
    {"string", string, StringLibrary},
    {"table", table, TableLibrary},
    {"math", math, MathLibrary},
    {"debug", debug, DebugLibrary},
    {"pcall", pcall, PCall},
    {"type", type, Type},
    {"tostring", tostring, ToString},
    {"rawget", rawget, RawGet},
    {"rawset", rawset, RawSet},
    {"rawequal", rawequal, RawEqual},
    {"next", next, Next},
    {"setmetatable", setmetatable, Setmetatable},
    {"getmetatable", getmetatable, Getmetatable},
    {"getfenv", getfenv, GetFEnvSnapshot},
    {"string.byte", string and string.byte, StringLibrary and StringLibrary.byte},
    {"string.char", string and string.char, StringLibrary and StringLibrary.char},
    {"string.sub", string and string.sub, StringLibrary and StringLibrary.sub},
    {"table.concat", table and table.concat, TableLibrary and TableLibrary.concat},
    {"table.insert", table and table.insert, TableLibrary and TableLibrary.insert},
    {"math.ldexp", math and math.ldexp, MathLibrary and MathLibrary.ldexp},
    {"unpack", unpack, UnpackGlobal},
    {"table.unpack", table and table.unpack, TableUnpack},
    {"selected_unpack", unpack or (table and table.unpack), Unpack},
}
local SnapshotStable = true
for index = 1, #CoreSnapshotChecks do
    local item = CoreSnapshotChecks[index]
    local same = item[2] == item[3]
    if not same then
        SnapshotStable = false
    end
    emit("core_snapshot", item[1], same, same and "same reference" or "reference changed")
end

local SnapshotChecks = {
    {"identifyexecutor", Identify},
    {"getexecutorname", IdentifyAlias},
    {"executorname", ExecutorNameAlias},
    {"checkcaller", CheckCaller},
    {"iscclosure", IsC},
    {"islclosure", IsL},
    {"newcclosure", NewC},
    {"loadstring", LoadString},
    {"typeof", TypeOf},
    {"game", Game},
    {"Instance", Instance},
    {"Vector3", Vector3},
    {"task", Task},
}
for index = 1, #SnapshotChecks do
    local item = SnapshotChecks[index]
    local same = lookup(item[1]) == item[2]
    if not same then
        SnapshotStable = false
    end
    emit("snapshot", item[1], same, same and "same reference" or "reference changed")
end
for _, name in ipairs({
    "gethook", "getinfo", "info", "getconstants", "getupvalues",
    "getproto", "getprotos", "setupvalue"
}) do
    local same = safeRawGet(Debug, name) == DebugFunctions[name]
    if not same then
        SnapshotStable = false
    end
    emit("debug_snapshot", name, same, same and "same reference" or "reference changed")
end
local GetGenVFinalOK, GetGenVFinal = call(GetGenV)
local GetGenVReferenceStable = safeRawGet(BaseEnvironment, "getgenv") == GetGenV
local GetGenVResultStable = GetGenVFinalOK and GetGenVFinal == CapabilityEnvironment
emit("snapshot", "getgenv_reference", GetGenVReferenceStable,
    GetGenVReferenceStable and "same reference" or "reference changed")
emit("snapshot", "getgenv_result", GetGenVResultStable,
    GetGenVResultStable and "same table" or "result changed")
SnapshotStable = SnapshotStable and GetGenVReferenceStable and GetGenVResultStable
contract("primitive_snapshot_stability", SnapshotStable,
    "core/executor/debug/host references and getgenv result must remain stable")

Output[#Output + 1] = "IB2PROBE|summary|executor|INFO|name=" .. escape(Name1)
    .. ",version=" .. escape(Version1)
local StrictSummaryLine
if #Failures == 0 then
    StrictSummaryLine = "IB2PROBE|summary|strict_contract|PASS|all mirrored checks passed"
else
    StrictSummaryLine = "IB2PROBE|summary|strict_contract|FAIL|failure_count=" .. #Failures
        .. ",failures=" .. escape(table.concat(Failures, ","))
end
Output[#Output + 1] = StrictSummaryLine
Output[#Output + 1] = "IB2PROBE|summary|notice|INFO|This is a diagnostic approximation; do not use executor name as an allow-list."

local ReportPath = "IronBrew2_executor_probe.txt"
local Report = table.concat(Output, "\n") .. "\n"
local WriteFile = lookup("writefile")
local SaveOK, SaveError = call(WriteFile, ReportPath, Report)
local SaveLine
if SaveOK then
    SaveLine = "IB2PROBE|output|workspace_file|OK|path=" .. escape(ReportPath)
        .. ",bytes=" .. #Report
else
    SaveLine = "IB2PROBE|output|workspace_file|FAIL|path=" .. escape(ReportPath)
        .. ",writefile_type=" .. escape(Type(WriteFile)) .. ",error=" .. escape(SaveError)
end

local ReadFile = lookup("readfile")
local VerifyLine
if Type(ReadFile) == "function" then
    local ReadOK, StoredReport = call(ReadFile, ReportPath)
    local VerifyOK = ReadOK and StoredReport == Report
    VerifyLine = "IB2PROBE|output|workspace_verify|" .. (VerifyOK and "OK" or "FAIL")
        .. "|read_ok=" .. escape(ReadOK) .. ",bytes="
        .. (Type(StoredReport) == "string" and #StoredReport or 0)
        .. (VerifyOK and ",content=exact" or ",content=mismatch")
else
    VerifyLine = "IB2PROBE|output|workspace_verify|SKIP|readfile is unavailable"
end

local SetClipboard = lookup("setclipboard")
local ClipboardAPI = "setclipboard"
if Type(SetClipboard) ~= "function" then
    SetClipboard = lookup("toclipboard")
    ClipboardAPI = "toclipboard"
end
local ClipboardOK, ClipboardError = call(SetClipboard, Report)
local ClipboardLine
if ClipboardOK then
    ClipboardLine = "IB2PROBE|output|clipboard|OK|api=" .. ClipboardAPI
        .. ",bytes=" .. #Report .. "; paste the clipboard contents back to the developer"
else
    ClipboardLine = "IB2PROBE|output|clipboard|FAIL|api_type=" .. escape(Type(SetClipboard))
        .. ",error=" .. escape(ClipboardError)
end

for index = 1, #Output do
    Print(Output[index])
end
Print(SaveLine)
Print(VerifyLine)
Print(ClipboardLine)
-- Repeat the compact result near the tail because some executor consoles retain only recent entries.
Print(StrictSummaryLine)
-- Replay the complete report in one final print call. Some executor consoles retain only the
-- most recent log entry rather than the most recent lines, so per-line output disappears even
-- though the final workspace status remains visible. Keep this as the last output operation.
Print(Report)
