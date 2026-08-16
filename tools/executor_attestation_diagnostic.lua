-- IronBrew2 executor-attestation diagnostic
--
-- Runs the runtime-observable conditions used by the current production gate.
-- It prints failed checks only, followed by one success/failure summary line.
-- No executor brand is allowed or denied.
--
-- This script intentionally does not enter the production infinite sink. Every
-- challenge is protected so the remaining checks can continue. Environment
-- canaries and the mutated test upvalue are restored before results are shown.
-- Payload-specific manifest/route/seed binding cannot be observed from a
-- standalone script; the same transcript, token and seal arithmetic is tested
-- below with fixed diagnostic values.

local String0 = string
local Table0 = table
local Math0 = math
local Debug0 = debug
local UnpackGlobal0 = unpack
local TableUnpack0 = Table0 and Table0.unpack
local GetFEnvGlobal0 = getfenv

local PCall0 = pcall
local Type0 = type
local RawGet0 = rawget
local RawSet0 = rawset
local Next0 = next
local GetMetatable0 = getmetatable
local SetMetatable0 = setmetatable
local RawEqual0 = rawequal
local ToString0 = tostring
local Select0 = select
local ToNumber0 = tonumber
local Output0 = print

local Byte0 = String0 and String0.byte
local Char0 = String0 and String0.char
local Sub0 = String0 and String0.sub
local Concat0 = Table0 and Table0.concat
local Insert0 = Table0 and Table0.insert
local LDExp0 = Math0 and Math0.ldexp
local Unpack0 = UnpackGlobal0 or TableUnpack0

local successCount = 0
local failureCount = 0
local failures = {}

local function safe_text(value)
    local ok, result = PCall0(ToString0, value)
    if not ok then return "unprintable error" end
    result = result or "nil"
    result = String0.gsub(result, "[\r\n]+", " ")
    if #result > 240 then result = Sub0(result, 1, 240) .. "..." end
    return result
end

local function record(name, passed, detail)
    if passed then
        successCount = successCount + 1
    else
        failureCount = failureCount + 1
        failures[#failures + 1] = "[FAIL] " .. name .. ": " .. safe_text(detail or "condition returned false")
    end
    return passed
end

local function run(name, callback)
    local ok, passed, detail = PCall0(callback)
    if not ok then return record(name, false, "raised: " .. safe_text(passed)) end
    return record(name, passed == true, detail)
end

local function value_type(value)
    local ok, result = PCall0(Type0, value)
    return ok and result or "<type failed>"
end

local function is_function(value)
    return value_type(value) == "function"
end

local function table_contains(values, expected)
    if value_type(values) ~= "table" then return false end
    for _, item in Next0, values do
        if item == expected then return true end
    end
    return false
end

local function current_environment()
    local getter = GetFEnvGlobal0 or function() return _G end
    return PCall0(getter)
end

local envOK, ThreadEnvironment = current_environment()
record("environment.current-call", envOK, "getfenv/current environment call failed")
record("environment.current-table", envOK and value_type(ThreadEnvironment) == "table",
    "expected table, got " .. value_type(ThreadEnvironment))
if value_type(ThreadEnvironment) ~= "table" then ThreadEnvironment = nil end

-- Executor globals may be supplied through the thread environment's __index
-- chain. sUNC requires getgenv behavior; it does not require getgenv itself to
-- be a raw key of getfenv(). Prefer raw values, then use a protected ordinary
-- lookup so proxy-backed environments are diagnosed without weakening the
-- later cross-API behavior challenges.
local function environment_read(environment, key)
    if value_type(environment) ~= "table" then return false, nil, "environment is not a table" end
    local rawValue = RawGet0(environment, key)
    if rawValue ~= nil then return true, rawValue, "raw" end
    local ok, indexedValue = PCall0(function() return environment[key] end)
    if not ok then return false, nil, indexedValue end
    return true, indexedValue, "indexed"
end

local getGenReadOK, GetGenV0 = environment_read(ThreadEnvironment, "getgenv")
record("environment.getgenv-lookup", getGenReadOK, "protected environment lookup raised")
record("environment.getgenv-function", is_function(GetGenV0),
    "getgenv must resolve to a function; got " .. value_type(GetGenV0))

local capOK, ExecutorEnvironment = false, nil
if is_function(GetGenV0) then capOK, ExecutorEnvironment = PCall0(GetGenV0) end
record("environment.getgenv-call", capOK, "getgenv raised or was unavailable")
record("environment.getgenv-table", capOK and value_type(ExecutorEnvironment) == "table",
    "expected table, got " .. value_type(ExecutorEnvironment))
if value_type(ExecutorEnvironment) ~= "table" then ExecutorEnvironment = nil end

local function lookup(name)
    local _, value = environment_read(ExecutorEnvironment, name)
    if value == nil then _, value = environment_read(ThreadEnvironment, name) end
    return value
end

local Identify0 = lookup("identifyexecutor")
local CheckCaller0 = lookup("checkcaller")
local IsC0 = lookup("iscclosure")
local IsL0 = lookup("islclosure")
local NewC0 = lookup("newcclosure")
local LoadString0 = lookup("loadstring")
local TypeOf0 = lookup("typeof")
local Game0 = lookup("game")
local Instance0 = lookup("Instance")
local Vector30 = lookup("Vector3")
local Task0 = lookup("task")

local GetInfo0 = Debug0 and RawGet0(Debug0, "getinfo")
local Info0 = Debug0 and RawGet0(Debug0, "info")
local Inspector0 = is_function(Info0) and Info0 or GetInfo0
local GetConstants0 = Debug0 and RawGet0(Debug0, "getconstants")
local GetUpvalues0 = Debug0 and RawGet0(Debug0, "getupvalues")
local GetProto0 = Debug0 and RawGet0(Debug0, "getproto")
local GetProtos0 = Debug0 and RawGet0(Debug0, "getprotos")
local SetupValue0 = Debug0 and RawGet0(Debug0, "setupvalue")

record("api.debug-table", value_type(Debug0) == "table", "expected table, got " .. value_type(Debug0))

local requiredFunctions = {
    {"api.identifyexecutor", Identify0},
    {"api.checkcaller", CheckCaller0},
    {"api.iscclosure", IsC0},
    {"api.islclosure", IsL0},
    {"api.newcclosure", NewC0},
    {"api.loadstring", LoadString0},
    {"api.typeof", TypeOf0},
    {"api.debug-inspector", Inspector0},
    {"api.debug.getconstants", GetConstants0},
    {"api.debug.getupvalues", GetUpvalues0},
    {"api.debug.setupvalue", SetupValue0},
}
for index = 1, #requiredFunctions do
    local item = requiredFunctions[index]
    record(item[1], is_function(item[2]), "expected function, got " .. value_type(item[2]))
end
record("api.debug.proto-surface", is_function(GetProto0) or is_function(GetProtos0),
    "debug.getproto or debug.getprotos must be a function")

-- Isolated, writable and persistent getgenv challenge, with unconditional
-- restoration attempts matching the production guard's cleanup behavior.
local CanaryKey = "__ib2_attestation_" .. safe_text({})
local ThreadOld = ThreadEnvironment and RawGet0(ThreadEnvironment, CanaryKey)
local CapabilityOld = ExecutorEnvironment and RawGet0(ExecutorEnvironment, CanaryKey)
local ThreadMarker, CapabilityMarker = {}, {}
local threadWriteOK, capWriteOK = false, false
local separated, repeatOK, repeatSame, persistent = false, false, false, false

record("getgenv.distinct-environments",
    ThreadEnvironment ~= nil and ExecutorEnvironment ~= nil and ThreadEnvironment ~= ExecutorEnvironment,
    "getgenv returned the current thread environment")

if ThreadEnvironment and ExecutorEnvironment then
    threadWriteOK = PCall0(RawSet0, ThreadEnvironment, CanaryKey, ThreadMarker)
    if threadWriteOK then
        separated = RawGet0(ExecutorEnvironment, CanaryKey) ~= ThreadMarker
    end
    capWriteOK = PCall0(RawSet0, ExecutorEnvironment, CanaryKey, CapabilityMarker)
    local repeated
    if capWriteOK and is_function(GetGenV0) then repeatOK, repeated = PCall0(GetGenV0) end
    repeatSame = repeatOK and repeated == ExecutorEnvironment
    persistent = repeatSame and RawGet0(repeated, CanaryKey) == CapabilityMarker
end

record("getgenv.thread-raw-write", threadWriteOK, "raw write to current environment failed")
record("getgenv.no-cross-pollution", separated, "thread canary appeared in executor environment")
record("getgenv.executor-raw-write", capWriteOK, "raw write to executor environment failed")
record("getgenv.repeat-call", repeatOK, "repeated getgenv call failed")
record("getgenv.same-table", repeatSame, "repeated getgenv returned a different table")
record("getgenv.persistent-write", persistent, "executor canary did not persist")

local threadRestoreOK = ThreadEnvironment and PCall0(RawSet0, ThreadEnvironment, CanaryKey, ThreadOld) or false
local capRestoreOK = ExecutorEnvironment and PCall0(RawSet0, ExecutorEnvironment, CanaryKey, CapabilityOld) or false
record("getgenv.thread-restore", threadRestoreOK, "failed to restore the current-environment canary")
record("getgenv.executor-restore", capRestoreOK, "failed to restore the executor-environment canary")

-- identifyexecutor is a typed stability signal, never a brand allow-list.
local idOK1, name1, version1 = false, nil, nil
local idOK2, name2, version2 = false, nil, nil
if is_function(Identify0) then
    idOK1, name1, version1 = PCall0(Identify0)
    idOK2, name2, version2 = PCall0(Identify0)
end
record("identity.first-call", idOK1, "first identifyexecutor call failed")
record("identity.second-call", idOK2, "second identifyexecutor call failed")
record("identity.name-string", value_type(name1) == "string", "expected string, got " .. value_type(name1))
record("identity.version-string-1", value_type(version1) == "string", "expected string, got " .. value_type(version1))
record("identity.version-string-2", value_type(version2) == "string", "expected string, got " .. value_type(version2))
record("identity.name-length", value_type(name1) == "string" and #name1 >= 1 and #name1 <= 128,
    "name must contain 1-128 bytes")
record("identity.version-length", value_type(version1) == "string" and #version1 <= 128,
    "version must contain no more than 128 bytes")
record("identity.stable-name", idOK1 and idOK2 and name1 == name2, "name changed between calls")
record("identity.stable-version", idOK1 and idOK2 and version1 == version2, "version changed between calls")

local callerOK, callerValue = false, nil
if is_function(CheckCaller0) then callerOK, callerValue = PCall0(CheckCaller0) end
record("caller.call", callerOK, "checkcaller call failed")
record("caller.executor-thread", callerOK and callerValue == true,
    "checkcaller must return boolean true; got " .. safe_text(callerValue))

-- Roblox host contract.
record("host.game-type", value_type(Game0) == "table" or value_type(Game0) == "userdata",
    "expected table/userdata, got " .. value_type(Game0))
record("host.Instance-table", value_type(Instance0) == "table", "got " .. value_type(Instance0))
record("host.Vector3-table", value_type(Vector30) == "table", "got " .. value_type(Vector30))
record("host.task-table", value_type(Task0) == "table", "got " .. value_type(Task0))
record("host.Instance.new", value_type(Instance0) == "table" and is_function(Instance0.new),
    "Instance.new is not a function")
record("host.task.wait", value_type(Task0) == "table" and is_function(Task0.wait), "task.wait is not a function")
record("host.task.spawn", value_type(Task0) == "table" and is_function(Task0.spawn), "task.spawn is not a function")
record("host.task.defer", value_type(Task0) == "table" and is_function(Task0.defer), "task.defer is not a function")

local playersOK, Players0 = PCall0(function() return Game0:GetService("Players") end)
record("host.GetService-Players", playersOK and Players0 ~= nil, "game:GetService('Players') failed")
record("host.Players-ClassName", playersOK and Players0 and Players0.ClassName == "Players",
    "Players.ClassName was not 'Players'")
local vectorOK, VectorValue = PCall0(function() return Vector30.new() end)
record("host.Vector3.new", vectorOK, "Vector3.new failed")
local vectorTypeOK, vectorType = PCall0(function() return TypeOf0(VectorValue) end)
record("host.typeof-Vector3", vectorOK and vectorTypeOK and vectorType == "Vector3",
    "typeof(Vector3.new()) returned " .. safe_text(vectorType))
local tableTypeOK, tableType = PCall0(function() return TypeOf0(SetMetatable0({}, {})) end)
record("host.typeof-table", tableTypeOK and tableType == "table",
    "typeof(setmetatable({}, {})) returned " .. safe_text(tableType))

local function classification_result(value, expectedC)
    if not is_function(value) then return false, "value is " .. value_type(value) end
    if not is_function(IsC0) or not is_function(IsL0) then return false, "classifier API missing" end
    local cOK, cValue = PCall0(IsC0, value)
    local lOK, lValue = PCall0(IsL0, value)
    if not cOK then return false, "iscclosure raised" end
    if not lOK then return false, "islclosure raised" end
    if cValue ~= expectedC then return false, "iscclosure returned " .. safe_text(cValue) end
    if lValue ~= (not expectedC) then return false, "islclosure returned " .. safe_text(lValue) end
    return true
end

local NativePrimitives = {
    {"closure.native.string.byte", Byte0},
    {"closure.native.string.char", Char0},
    {"closure.native.string.sub", Sub0},
    {"closure.native.table.concat", Concat0},
    {"closure.native.table.insert", Insert0},
    {"closure.native.math.ldexp", LDExp0},
    {"closure.native.select", Select0},
    {"closure.native.pcall", PCall0},
    {"closure.native.type", Type0},
    {"closure.native.tostring", ToString0},
    {"closure.native.tonumber", ToNumber0},
    {"closure.native.rawget", RawGet0},
    {"closure.native.rawset", RawSet0},
    {"closure.native.rawequal", RawEqual0},
    {"closure.native.next", Next0},
    {"closure.native.setmetatable", SetMetatable0},
    {"closure.native.getmetatable", GetMetatable0},
    {"closure.native.unpack", Unpack0},
    {"closure.native.debug-inspector", Inspector0},
}
for index = 1, #NativePrimitives do
    local item = NativePrimitives[index]
    local passed, detail = classification_result(item[2], true)
    record(item[1], passed, detail)
end

local function LuaProbe(value) return value end
local luaProbeClass, luaProbeClassDetail = classification_result(LuaProbe, false)
record("closure.lua-probe", luaProbeClass, luaProbeClassDetail)

local function rejected_call(api, ...)
    if not is_function(api) then return false, "API missing" end
    local ok = PCall0(api, ...)
    if ok then return false, "call returned instead of raising" end
    return true
end

local function no_exposed_values(api, target)
    if not is_function(api) then return false, "API missing" end
    local ok, values = PCall0(api, target)
    if not ok then return true end
    if value_type(values) == "table" and Next0(values) == nil then return true end
    return false, "expected an error or empty table, got " .. value_type(values)
end

local cConstantsReject, cConstantsDetail = rejected_call(GetConstants0, Byte0)
record("debug.C-getconstants-rejected", cConstantsReject, cConstantsDetail)
local cUpvaluesProtected, cUpvaluesDetail = no_exposed_values(GetUpvalues0, Byte0)
record("debug.C-getupvalues-protected", cUpvaluesProtected, cUpvaluesDetail)
local cSetupReject, cSetupDetail = rejected_call(SetupValue0, Byte0, 1, 0)
record("debug.C-setupvalue-rejected", cSetupReject, cSetupDetail)
if is_function(GetProto0) then
    local passed, detail = rejected_call(GetProto0, Byte0, 1)
    record("debug.C-getproto-rejected", passed, detail)
else
    record("debug.C-getproto-rejected", true)
end
if is_function(GetProtos0) then
    local passed, detail = rejected_call(GetProtos0, Byte0)
    record("debug.C-getprotos-rejected", passed, detail)
else
    record("debug.C-getprotos-rejected", true)
end

-- Fixed diagnostic challenge values. These mirror the generated random probes
-- while keeping the expected transcript independently hard-coded.
local CONSTANT_EXPECTED = 731245907
local UPVALUE_EXPECTED = 318640271
local UPVALUE_CHANGED = 827154963
local PROTO_CONSTANT = 451278301
local PROTO_INPUT = 59254
local PROTO_EXPECTED = 451337555
local LOAD_EXPECTED = 613323272
local C_INPUT = 40731
local TRANSCRIPT_SEED = 197843211
local TRANSCRIPT_EXPECTED = 3515312154
local ATTESTATION_OFFSET = 1517399123
local ATTESTATION_TOKEN = 737743981

local function ConstantProbe() return 731245907 end
local UpvalueValue = UPVALUE_EXPECTED
local function UpvalueProbe(value)
    -- The assignment prevents Luau's optimizer from folding an apparently
    -- immutable captured local into a constant, so this is a real upvalue.
    UpvalueValue = (UpvalueValue + value) % 2147483647
    return UpvalueValue
end
local function ProtoProbe()
    local function ProtoChild(value)
        return (value + 451278301) % 2147483647
    end
    return ProtoChild
end
local function CBody(value) return Math0.abs(value) end

local constantsOK, constants = false, nil
if is_function(GetConstants0) then constantsOK, constants = PCall0(GetConstants0, ConstantProbe) end
local constantsTable = constantsOK and value_type(constants) == "table"
local constantsContain = constantsTable and table_contains(constants, CONSTANT_EXPECTED)
record("constants.call", constantsOK, "debug.getconstants raised")
record("constants.table", constantsTable, "expected table, got " .. value_type(constants))
record("constants.contains-random-value", constantsContain, "random numeric constant was not found")

local upvaluesOK, upvalues = false, nil
if is_function(GetUpvalues0) then upvaluesOK, upvalues = PCall0(GetUpvalues0, UpvalueProbe) end
local upvaluesTable = upvaluesOK and value_type(upvalues) == "table"
local upvaluesContain = upvaluesTable and table_contains(upvalues, UPVALUE_EXPECTED)
record("upvalues.call", upvaluesOK, "debug.getupvalues raised")
record("upvalues.table", upvaluesTable, "expected table, got " .. value_type(upvalues))
record("upvalues.contains-random-value", upvaluesContain, "private upvalue value was not found")

local setupOK = false
if is_function(SetupValue0) then setupOK = PCall0(SetupValue0, UpvalueProbe, 1, UPVALUE_CHANGED) end
local changedCallOK, changedValue = PCall0(UpvalueProbe, 0)
local changedObserved = changedCallOK and changedValue == UPVALUE_CHANGED
local restoreOK = false
if is_function(SetupValue0) then restoreOK = PCall0(SetupValue0, UpvalueProbe, 1, UPVALUE_EXPECTED) end
local restoredCallOK, restoredValue = PCall0(UpvalueProbe, 0)
local restoredObserved = restoredCallOK and restoredValue == UPVALUE_EXPECTED
record("upvalues.setupvalue-call", setupOK, "setupvalue did not complete")
record("upvalues.changed-value", changedObserved, "function did not observe the changed upvalue")
record("upvalues.restore-call", restoreOK, "setupvalue restore did not complete")
record("upvalues.restored-value", restoredObserved, "private upvalue was not restored")

local activeParentOK, ActiveProto = PCall0(ProtoProbe)
record("proto.parent-call", activeParentOK and is_function(ActiveProto), "parent did not return a function")
local activeCallOK, activeCallValue = false, nil
if is_function(ActiveProto) then activeCallOK, activeCallValue = PCall0(ActiveProto, PROTO_INPUT) end
record("proto.child-call", activeCallOK, "active child call failed")
record("proto.child-result", activeCallOK and activeCallValue == PROTO_EXPECTED,
    "expected " .. PROTO_EXPECTED .. ", got " .. safe_text(activeCallValue))
local activeClass, activeClassDetail = classification_result(ActiveProto, false)
record("proto.child-Luau-class", activeClass, activeClassDetail)

local function inactive_proto_result(value)
    local kind = value_type(value)
    if kind == "function" then
        local classOK, classDetail = classification_result(value, false)
        if not classOK then return false, "classification: " .. safe_text(classDetail) end
    elseif kind ~= "userdata" then
        return false, "expected function/userdata handle, got " .. kind
    end
    local inspectOK, protoConstants = PCall0(GetConstants0, value)
    if not inspectOK then return false, "getconstants raised" end
    if not table_contains(protoConstants, PROTO_CONSTANT) then return false, "child constant missing" end
    local callable = PCall0(value, PROTO_INPUT)
    if callable then return false, "inactive proto was callable" end
    return true
end

local getprotoEvidence = true
if is_function(GetProto0) then
    local inactiveOK, InactiveProto = PCall0(GetProto0, ProtoProbe, 1)
    record("proto.getproto-call", inactiveOK, "debug.getproto(parent, 1) raised")
    local inactiveValid, inactiveDetail = false, "getproto call failed"
    if inactiveOK then inactiveValid, inactiveDetail = inactive_proto_result(InactiveProto) end
    record("proto.getproto-inactive-contract", inactiveValid, inactiveDetail)

    local activatedOK, Activated = PCall0(GetProto0, ProtoProbe, 1, true)
    record("proto.getproto-active-call", activatedOK, "debug.getproto(parent, 1, true) raised")
    local activatedTable = activatedOK and value_type(Activated) == "table"
    record("proto.getproto-active-table", activatedTable, "expected table, got " .. value_type(Activated))
    local activatedValid = false
    if activatedTable then
        for _, item in Next0, Activated do
            local classOK = classification_result(item, false)
            if classOK then
                local callOK, value = PCall0(item, PROTO_INPUT)
                if callOK and value == PROTO_EXPECTED then activatedValid = true break end
            end
        end
    end
    record("proto.getproto-active-result", activatedValid, "no active Luau child returned the expected value")
    getprotoEvidence = inactiveOK and inactiveValid and activatedOK and activatedTable and activatedValid
else
    record("proto.getproto-call", true)
    record("proto.getproto-inactive-contract", true)
    record("proto.getproto-active-call", true)
    record("proto.getproto-active-table", true)
    record("proto.getproto-active-result", true)
end

local getprotosEvidence = true
if is_function(GetProtos0) then
    local protosOK, Protos = PCall0(GetProtos0, ProtoProbe)
    record("proto.getprotos-call", protosOK, "debug.getprotos(parent) raised")
    local protosTable = protosOK and value_type(Protos) == "table"
    record("proto.getprotos-table", protosTable, "expected table, got " .. value_type(Protos))
    local foundInactive = false
    if protosTable then
        for _, item in Next0, Protos do
            if inactive_proto_result(item) then foundInactive = true break end
        end
    end
    record("proto.getprotos-inactive-contract", foundInactive, "no valid uncallable inactive proto was found")
    getprotosEvidence = protosOK and protosTable and foundInactive
else
    record("proto.getprotos-call", true)
    record("proto.getprotos-table", true)
    record("proto.getprotos-inactive-contract", true)
end
local protoSurfaceEvidence = (is_function(GetProto0) or is_function(GetProtos0))
    and getprotoEvidence and getprotosEvidence

local invalidOK, invalidFunction, invalidError = false, nil, nil
if is_function(LoadString0) then
    invalidOK, invalidFunction, invalidError = PCall0(LoadString0, "return )", "__ib2_invalid_diagnostic")
end
record("loadstring.invalid-no-throw", invalidOK, "loadstring itself raised on invalid source")
record("loadstring.invalid-nil-function", invalidOK and invalidFunction == nil,
    "first result must be nil; got " .. value_type(invalidFunction))
record("loadstring.invalid-error-string",
    invalidOK and value_type(invalidError) == "string" and #invalidError >= 1,
    "second result must be a non-empty string")

local compileOK, Loaded = false, nil
if is_function(LoadString0) then compileOK, Loaded = PCall0(LoadString0, "return 613323272") end
record("loadstring.valid-call", compileOK, "loadstring raised on valid source")
record("loadstring.valid-function", compileOK and is_function(Loaded), "valid source did not return a function")
local loadedCallOK, loadedValue = false, nil
if is_function(Loaded) then loadedCallOK, loadedValue = PCall0(Loaded) end
record("loadstring.loaded-call", loadedCallOK, "compiled function raised")
record("loadstring.loaded-result", loadedCallOK and loadedValue == LOAD_EXPECTED,
    "expected " .. LOAD_EXPECTED .. ", got " .. safe_text(loadedValue))
local loadedClass, loadedClassDetail = classification_result(Loaded, false)
record("loadstring.loaded-Luau-class", loadedClass, loadedClassDetail)
local loadedConstantsOK, loadedConstants = false, nil
if is_function(GetConstants0) and is_function(Loaded) then
    loadedConstantsOK, loadedConstants = PCall0(GetConstants0, Loaded)
end
local loadedConstantEvidence = loadedConstantsOK and table_contains(loadedConstants, LOAD_EXPECTED)
record("loadstring.loaded-getconstants", loadedConstantsOK, "getconstants(compiledFunction) raised")
record("loadstring.loaded-constant", loadedConstantEvidence, "compiled numeric constant was not found")

local wrapOK, Wrapped = false, nil
if is_function(NewC0) then wrapOK, Wrapped = PCall0(NewC0, CBody) end
record("newcclosure.call", wrapOK, "newcclosure raised")
record("newcclosure.function", wrapOK and is_function(Wrapped), "newcclosure did not return a function")
local wrappedCallOK, wrappedValue = false, nil
if is_function(Wrapped) then wrappedCallOK, wrappedValue = PCall0(Wrapped, -C_INPUT) end
record("newcclosure.forward-call", wrappedCallOK, "wrapped callback raised")
record("newcclosure.forward-result", wrappedCallOK and wrappedValue == C_INPUT,
    "expected " .. C_INPUT .. ", got " .. safe_text(wrappedValue))
local wrappedClass, wrappedClassDetail = classification_result(Wrapped, true)
record("newcclosure.C-class", wrappedClass, wrappedClassDetail)
local wrappedUpvaluesProtected, wrappedUpvaluesDetail = no_exposed_values(GetUpvalues0, Wrapped)
record("newcclosure.getupvalues-protected", wrappedUpvaluesProtected, wrappedUpvaluesDetail)

-- Diagnostic transcript/token equivalent to the generated hard-AND challenge.
local function mix_word(state, value)
    return (state * 31 + value) % 4294967296
end
local transcript = TRANSCRIPT_SEED
transcript = mix_word(transcript, CONSTANT_EXPECTED)
transcript = mix_word(transcript, UPVALUE_EXPECTED)
transcript = mix_word(transcript, UPVALUE_CHANGED)
transcript = mix_word(transcript, PROTO_EXPECTED)
transcript = mix_word(transcript, LOAD_EXPECTED)
transcript = mix_word(transcript, C_INPUT)
local challengeEvidence = constantsContain and upvaluesContain and setupOK and changedObserved
    and restoreOK and restoredObserved and activeParentOK and activeCallOK
    and activeCallValue == PROTO_EXPECTED and activeClass and protoSurfaceEvidence
    and invalidOK and invalidFunction == nil and value_type(invalidError) == "string" and #invalidError >= 1
    and compileOK and loadedCallOK and loadedValue == LOAD_EXPECTED and loadedClass and loadedConstantEvidence
    and cUpvaluesProtected and wrapOK and wrappedCallOK and wrappedValue == C_INPUT
    and wrappedClass and wrappedUpvaluesProtected
record("attestation.transcript", challengeEvidence and transcript == TRANSCRIPT_EXPECTED,
    challengeEvidence and "transcript mismatch" or "one or more transcript-producing challenges failed")
local diagnosticToken = (transcript + ATTESTATION_OFFSET) % 4294967296
record("attestation.token", challengeEvidence and diagnosticToken == ATTESTATION_TOKEN,
    challengeEvidence and "token mismatch" or "challenge transcript unavailable")

local DIAGNOSTIC_STATE = 173421987
local DIAGNOSTIC_SALT = 91234567
local DIAGNOSTIC_INITIAL_SEAL = 1179281621
local DIAGNOSTIC_SEAL = 1917025602
local DIAGNOSTIC_NEXT_STATE = 361521531
local DIAGNOSTIC_NEXT_SEAL = 1617976796
local initialSeal = (DIAGNOSTIC_STATE * 65599 + DIAGNOSTIC_SALT) % 2147483647
record("guard.initial-seal", initialSeal == DIAGNOSTIC_INITIAL_SEAL, "initial seal mismatch")
local seal = (DIAGNOSTIC_STATE * 65599 + DIAGNOSTIC_SALT + diagnosticToken) % 2147483647
record("guard.attested-seal", challengeEvidence and seal == DIAGNOSTIC_SEAL,
    challengeEvidence and "attested seal mismatch" or "attestation token unavailable")
-- First forced probe: counter=1 and epoch=1, hence +1 + 1*17.
local nextState = (DIAGNOSTIC_STATE * 48271 + 1 + 17 + diagnosticToken % 65521) % 2147483647
local nextSeal = (nextState * 65599 + DIAGNOSTIC_SALT + diagnosticToken) % 2147483647
record("guard.state-transition", challengeEvidence and nextState == DIAGNOSTIC_NEXT_STATE,
    challengeEvidence and "next state mismatch" or "attestation token unavailable")
record("guard.transition-seal", challengeEvidence and nextSeal == DIAGNOSTIC_NEXT_SEAL,
    challengeEvidence and "next seal mismatch" or "attestation token unavailable")
local stickyTripped = false
local function simulate_guard(valid)
    if stickyTripped then return true end
    if not valid then stickyTripped = true return true end
    return false
end
simulate_guard(false)
record("guard.sticky-failure", simulate_guard(true) == true, "a failed guard became valid again")

-- End-of-run identity/reference checks. Production performs this comparison at
-- startup, after root deserialization, before the first block and periodically.
local function stable(name, current, captured)
    record("stable." .. name, current == captured, "reference changed")
end

stable("library.string", string, String0)
stable("library.table", table, Table0)
stable("library.math", math, Math0)
stable("library.debug", debug, Debug0)
stable("global.pcall", pcall, PCall0)
stable("global.type", type, Type0)
stable("global.rawget", rawget, RawGet0)
stable("global.rawset", rawset, RawSet0)
stable("global.next", next, Next0)
stable("global.getmetatable", getmetatable, GetMetatable0)
stable("global.setmetatable", setmetatable, SetMetatable0)
stable("global.rawequal", rawequal, RawEqual0)
stable("global.tostring", tostring, ToString0)
stable("global.select", select, Select0)
stable("global.tonumber", tonumber, ToNumber0)
stable("global.getfenv", getfenv, GetFEnvGlobal0)
stable("member.string.byte", String0 and String0.byte, Byte0)
stable("member.string.char", String0 and String0.char, Char0)
stable("member.string.sub", String0 and String0.sub, Sub0)
stable("member.table.concat", Table0 and Table0.concat, Concat0)
stable("member.table.insert", Table0 and Table0.insert, Insert0)
stable("member.math.ldexp", Math0 and Math0.ldexp, LDExp0)
stable("member.unpack", unpack, UnpackGlobal0)
stable("member.table.unpack", Table0 and Table0.unpack, TableUnpack0)
stable("member.selected-unpack", unpack or (table and table.unpack), Unpack0)

local _, CurrentGetGenV = environment_read(ThreadEnvironment, "getgenv")
stable("api.getgenv", CurrentGetGenV, GetGenV0)
stable("api.identifyexecutor", lookup("identifyexecutor"), Identify0)
stable("api.checkcaller", lookup("checkcaller"), CheckCaller0)
stable("api.iscclosure", lookup("iscclosure"), IsC0)
stable("api.islclosure", lookup("islclosure"), IsL0)
stable("api.newcclosure", lookup("newcclosure"), NewC0)
stable("api.loadstring", lookup("loadstring"), LoadString0)
stable("api.typeof", lookup("typeof"), TypeOf0)
stable("api.game", lookup("game"), Game0)
stable("api.Instance", lookup("Instance"), Instance0)
stable("api.Vector3", lookup("Vector3"), Vector30)
stable("api.task", lookup("task"), Task0)
stable("debug.getinfo", Debug0 and RawGet0(Debug0, "getinfo"), GetInfo0)
stable("debug.info", Debug0 and RawGet0(Debug0, "info"), Info0)
stable("debug.getconstants", Debug0 and RawGet0(Debug0, "getconstants"), GetConstants0)
stable("debug.getupvalues", Debug0 and RawGet0(Debug0, "getupvalues"), GetUpvalues0)
stable("debug.getproto", Debug0 and RawGet0(Debug0, "getproto"), GetProto0)
stable("debug.getprotos", Debug0 and RawGet0(Debug0, "getprotos"), GetProtos0)
stable("debug.setupvalue", Debug0 and RawGet0(Debug0, "setupvalue"), SetupValue0)

local repeatEndOK, repeatEndEnvironment = false, nil
if is_function(GetGenV0) then repeatEndOK, repeatEndEnvironment = PCall0(GetGenV0) end
record("stable.getgenv-call", repeatEndOK, "end-of-run getgenv call failed")
record("stable.getgenv-table", repeatEndOK and repeatEndEnvironment == ExecutorEnvironment,
    "end-of-run getgenv returned a different table")

for index = 1, #failures do Output0(failures[index]) end
Output0("成功: " .. successCount .. " 失败: " .. failureCount)
