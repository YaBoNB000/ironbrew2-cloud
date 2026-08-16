-- IronBrew2 executor compatibility probe, revision 2.
-- Standard Lua 5.1 syntax. Run directly in the executor.
-- Bounded and console-only: no files, clipboard, network, hooks, or background work.

local P = print
local T = type
local TS = tostring
local PC = pcall
local RG = rawget
local RE = rawequal
local NX = next
local SM = setmetatable
local ST = string
local TB = table
local MT = math
local DG = debug
local UP = unpack or (TB and TB.unpack)

local function clean(value, limit)
    local ok, text = PC(TS, value)
    if not ok then text = "<tostring-error>" end
    text = text:gsub("[\r\n]", " "):gsub("|", "/")
    limit = limit or 120
    if #text > limit then text = text:sub(1, limit) .. "..." end
    return text
end

local function atom(value)
    return T(value) .. ":" .. clean(value, 100)
end

local function call(fn, ...)
    if T(fn) ~= "function" then
        return false, "missing:" .. T(fn)
    end
    return PC(fn, ...)
end

local function field(container, key)
    if T(container) ~= "table" then return nil end
    local ok, value = PC(RG, container, key)
    if ok then return value end
    return nil
end

local function hasValue(values, expected)
    if T(values) ~= "table" then return false end
    local ok, found = PC(function()
        for _, value in NX, values do
            if value == expected then return true end
        end
        return false
    end)
    return ok and found == true
end

local function sample(values)
    if T(values) ~= "table" then return atom(values) end
    local parts, count = {}, 0
    local ok, err = PC(function()
        for key, value in NX, values do
            count = count + 1
            if #parts < 5 then
                parts[#parts + 1] = clean(key, 24) .. "=" .. atom(value)
            end
        end
    end)
    if not ok then return "table-error:" .. clean(err, 80) end
    return "table(" .. count .. "){" .. TB.concat(parts, ",") .. "}"
end

local Failures = {}
local function safePrint(line)
    return PC(P, line)
end

local function add(code, passed, detail)
    local status = passed and "OK" or "FAIL"
    if not passed then Failures[#Failures + 1] = code end
    local cleanOK, cleanDetail = PC(clean, detail, 420)
    if not cleanOK then cleanDetail = "<detail-format-error>" end
    safePrint("IB2P2|" .. code .. "|" .. status .. "|" .. cleanDetail)
end

-- Stream the begin marker before any executor function is touched. Every executor-facing
-- call below uses call()/pcall, and this outer pcall guarantees a final FATAL/END record if
-- an unexpected primitive or result shape still raises inside the diagnostic itself.
safePrint("IB2P2|BEGIN|INFO|lua51-console-v2-protected")

local function runProbe()
-- Resolve the same two environments used by the production guard.
local Base = T(_G) == "table" and _G or nil
local GetFEnv = field(Base, "getfenv")
local envOK, envValue = call(GetFEnv)
if envOK and T(envValue) == "table" then Base = envValue end

local GetGenV = field(Base, "getgenv")
local genOK1, Cap1 = call(GetGenV)
local genOK2, Cap2 = call(GetGenV)
if not genOK1 or T(Cap1) ~= "table" then Cap1 = nil end
if not genOK2 or T(Cap2) ~= "table" then Cap2 = nil end

local function lookup(name)
    local value = field(Cap1, name)
    if value == nil then value = field(Base, name) end
    return value
end

local Identify = lookup("identifyexecutor")
local IdentifyAlias = lookup("getexecutorname")
local ExecutorNameAlias = lookup("executorname")
local CheckCaller = lookup("checkcaller")
local IsC = lookup("iscclosure")
local IsL = lookup("islclosure")
local NewC = lookup("newcclosure")
local LoadString = lookup("loadstring")
local TypeOf = lookup("typeof")
local Game = lookup("game")
local Instance = lookup("Instance")
local Vector3 = lookup("Vector3")
local Task = lookup("task")

local GetHook = field(DG, "gethook")
local GetInfo = field(DG, "getinfo")
local Info = field(DG, "info")
local Inspector = T(Info) == "function" and Info or GetInfo
local GetConstants = field(DG, "getconstants")
local GetUpvalues = field(DG, "getupvalues")
local GetProto = field(DG, "getproto")
local GetProtos = field(DG, "getprotos")
local SetupValue = field(DG, "setupvalue")

local function LuaProbe(value) return value end
local CONSTANT = 718281828
local function ConstantProbe() return 718281828 end
local UPVALUE_ORIGINAL = 314159265
local UPVALUE_CHANGED = 271828182
local ProbeUpvalue = UPVALUE_ORIGINAL
local function UpvalueProbe(value) return ProbeUpvalue + value end
local PROTO_CONSTANT = 987654321
local PROTO_INPUT = 12345
local function ProtoProbe()
    local function Child(value) return value + 987654321 end
    return Child
end
local function CBody(value) return MT.abs(value) end

-- Capture references before behavioral tests. Only changed names are printed later.
local Snapshots = {}
local function snap(name, resolver)
    local ok, value = PC(resolver)
    Snapshots[#Snapshots + 1] = {name, ok and value or nil, resolver}
end

snap("string", function() return string end)
snap("table", function() return table end)
snap("math", function() return math end)
snap("debug", function() return debug end)
snap("pcall", function() return pcall end)
snap("type", function() return type end)
snap("tostring", function() return tostring end)
snap("tonumber", function() return tonumber end)
snap("rawget", function() return rawget end)
snap("rawset", function() return rawset end)
snap("rawequal", function() return rawequal end)
snap("next", function() return next end)
snap("select", function() return select end)
snap("setmetatable", function() return setmetatable end)
snap("getmetatable", function() return getmetatable end)
snap("getfenv", function() return getfenv end)
snap("string.byte", function() return string.byte end)
snap("string.char", function() return string.char end)
snap("string.sub", function() return string.sub end)
snap("table.concat", function() return table.concat end)
snap("table.insert", function() return table.insert end)
snap("math.ldexp", function() return math.ldexp end)
snap("unpack", function() return unpack end)
snap("table.unpack", function() return table and table.unpack end)

local ApiNames = {
    "getgenv", "identifyexecutor", "getexecutorname", "executorname", "checkcaller",
    "iscclosure", "islclosure", "newcclosure", "loadstring", "typeof",
    "game", "Instance", "Vector3", "task"
}
for index = 1, #ApiNames do
    local name = ApiNames[index]
    snap("api." .. name, function() return lookup(name) end)
end

local DebugNames = {
    "gethook", "getinfo", "info", "getconstants", "getupvalues",
    "getproto", "getprotos", "setupvalue"
}
for index = 1, #DebugNames do
    local name = DebugNames[index]
    snap("debug." .. name, function() return field(debug, name) end)
end

-- Environment and identity.
local environmentPass = T(Base) == "table" and T(GetGenV) == "function"
    and Cap1 ~= nil and Cap2 ~= nil and RE(Cap1, Cap2)
add("ENV", environmentPass,
    "base=" .. T(Base) .. ",getfenv=" .. T(GetFEnv) .. ",getgenv=" .. T(GetGenV)
    .. ",call1=" .. atom(genOK1) .. ",call2=" .. atom(genOK2)
    .. ",cap1=" .. T(Cap1) .. ",cap2=" .. T(Cap2)
    .. ",same=" .. atom(Cap1 ~= nil and RE(Cap1, Cap2)))

local idOK1, name1, version1 = call(Identify)
local idOK2, name2, version2 = call(Identify)
local versionType1, versionType2 = T(version1), T(version2)
local identityPass = idOK1 and idOK2 and T(name1) == "string" and #name1 >= 1 and #name1 <= 128
    and name1 == name2 and (versionType1 == "nil" or versionType1 == "string" or versionType1 == "number")
    and versionType1 == versionType2 and clean(version1) == clean(version2)
local aliasParts = {}
local aliasesPass = true
local aliases = {{"getexecutorname", IdentifyAlias}, {"executorname", ExecutorNameAlias}}
for index = 1, #aliases do
    local label, fn = aliases[index][1], aliases[index][2]
    if fn ~= nil then
        local ok, value = call(fn)
        local good = T(fn) == "function" and ok and value == name1
        aliasesPass = aliasesPass and good
        aliasParts[#aliasParts + 1] = label .. "=" .. atom(value) .. "/" .. atom(ok)
    else
        aliasParts[#aliasParts + 1] = label .. "=absent"
    end
end
add("ID", identityPass and aliasesPass,
    "fn=" .. T(Identify) .. ",ok1=" .. atom(idOK1) .. ",name1=" .. atom(name1)
    .. ",ver1=" .. atom(version1) .. ",ok2=" .. atom(idOK2) .. ",name2=" .. atom(name2)
    .. ",ver2=" .. atom(version2) .. ",aliases=" .. TB.concat(aliasParts, ","))

local executorSurfacePass = T(CheckCaller) == "function" and T(IsC) == "function"
    and T(IsL) == "function" and T(NewC) == "function" and T(LoadString) == "function"
    and T(TypeOf) == "function"
add("API", executorSurfacePass,
    "checkcaller=" .. T(CheckCaller) .. ",isc=" .. T(IsC) .. ",isl=" .. T(IsL)
    .. ",newc=" .. T(NewC) .. ",loadstring=" .. T(LoadString) .. ",typeof=" .. T(TypeOf))

local debugSurfacePass = T(Inspector) == "function" and T(GetConstants) == "function"
    and T(GetUpvalues) == "function" and (T(GetProto) == "function" or T(GetProtos) == "function")
    and T(SetupValue) == "function"
add("DBGAPI", debugSurfacePass,
    "inspector=" .. (T(Info) == "function" and "debug.info" or "debug.getinfo")
    .. ",getconstants=" .. T(GetConstants) .. ",getupvalues=" .. T(GetUpvalues)
    .. ",getproto=" .. T(GetProto) .. ",getprotos=" .. T(GetProtos)
    .. ",setupvalue=" .. T(SetupValue))

local callerOK, callerValue = call(CheckCaller)
add("CALLER", callerOK and callerValue == true,
    "call=" .. atom(callerOK) .. ",value=" .. atom(callerValue))

local hookPass, hookDetail = true, "absent"
if T(GetHook) == "function" then
    local ok, value = call(GetHook)
    hookPass = ok and value == nil
    hookDetail = "call=" .. atom(ok) .. ",value=" .. atom(value)
end
add("HOOK", hookPass, hookDetail)

-- Roblox host behavior.
local hostTypes = (T(Game) == "table" or T(Game) == "userdata")
    and T(Instance) == "table" and T(Vector3) == "table" and T(Task) == "table"
local hostOK, hostValue = PC(function()
    local players = Game:GetService("Players")
    local vector = Vector3.new()
    return players and players.ClassName == "Players"
        and TypeOf(vector) == "Vector3"
        and TypeOf(SM({}, {})) == "table"
        and T(Instance.new) == "function"
        and T(Task.wait) == "function" and T(Task.spawn) == "function" and T(Task.defer) == "function"
end)
add("HOST", hostTypes and hostOK and hostValue == true,
    "types=" .. T(Game) .. "/" .. T(Instance) .. "/" .. T(Vector3) .. "/" .. T(Task)
    .. ",call=" .. atom(hostOK) .. ",value=" .. atom(hostValue))

-- Closure classification.
local c1, byteIsC = call(IsC, ST.byte)
local c2, byteIsL = call(IsL, ST.byte)
local c3, probeIsC = call(IsC, LuaProbe)
local c4, probeIsL = call(IsL, LuaProbe)
local classifierPass = c1 and c2 and c3 and c4 and byteIsC == true and byteIsL == false
    and probeIsC == false and probeIsL == true
add("CLASS", classifierPass,
    "byte=" .. atom(byteIsC) .. "/" .. atom(byteIsL) .. ",lua=" .. atom(probeIsC)
    .. "/" .. atom(probeIsL) .. ",calls=" .. atom(c1) .. "/" .. atom(c2)
    .. "/" .. atom(c3) .. "/" .. atom(c4))

-- Source/provenance behavior, following production's debug.info preference.
local function nativeSource(fn)
    if T(fn) ~= "function" or T(Inspector) ~= "function" then return false, false, "missing" end
    if T(Info) == "function" then
        local ok, source = call(Info, fn, "s")
        return ok and T(source) == "string", source == "[C]", "info:" .. atom(source)
    end
    local ok, result = call(GetInfo, fn, "S")
    local known = ok and T(result) == "table" and T(result.what) == "string"
    return known, known and result.what == "C", "getinfo:" .. (T(result) == "table" and atom(result.what) or atom(result))
end

local primitives = {
    {"byte", ST.byte}, {"char", ST.char}, {"sub", ST.sub},
    {"concat", TB.concat}, {"insert", TB.insert}, {"ldexp", MT.ldexp},
    {"select", select}, {"pcall", PC}, {"type", T}, {"tostring", TS},
    {"tonumber", tonumber}, {"rawget", RG}, {"rawset", rawset},
    {"rawequal", RE}, {"next", NX}, {"setmetatable", SM},
    {"getmetatable", getmetatable}, {"unpack", UP}, {"inspector", Inspector}
}
local sourceFailures = {}
for index = 1, #primitives do
    local known, native, detail = nativeSource(primitives[index][2])
    if not known or not native then
        sourceFailures[#sourceFailures + 1] = primitives[index][1] .. "=" .. detail
    end
end
local localKnown, localNative, localDetail = nativeSource(LuaProbe)
if not localKnown or localNative then sourceFailures[#sourceFailures + 1] = "lua=" .. localDetail end
add("SOURCE", #sourceFailures == 0,
    #sourceFailures == 0 and "native primitives=19,lua=non-native" or TB.concat(sourceFailures, ","))

-- Debug constants/upvalues/setupvalue behavior.
local constantsOK, constants = call(GetConstants, ConstantProbe)
add("CONST", constantsOK and hasValue(constants, CONSTANT),
    "call=" .. atom(constantsOK) .. ",has=" .. atom(hasValue(constants, CONSTANT))
    .. ",values=" .. sample(constants))

local upvaluesOK, upvalues = call(GetUpvalues, UpvalueProbe)
add("UPVAL", upvaluesOK and hasValue(upvalues, UPVALUE_ORIGINAL),
    "call=" .. atom(upvaluesOK) .. ",has=" .. atom(hasValue(upvalues, UPVALUE_ORIGINAL))
    .. ",values=" .. sample(upvalues))

local setOK, setResult = call(SetupValue, UpvalueProbe, 1, UPVALUE_CHANGED)
local changedOK, changedValue = call(UpvalueProbe, 0)
local restoreOK, restoreResult = call(SetupValue, UpvalueProbe, 1, UPVALUE_ORIGINAL)
local restoredOK, restoredValue = call(UpvalueProbe, 0)
add("SETUP", setOK and changedOK and restoreOK and restoredOK
    and changedValue == UPVALUE_CHANGED and restoredValue == UPVALUE_ORIGINAL,
    "set=" .. atom(setOK) .. "/" .. atom(setResult)
    .. ",changed=" .. atom(changedOK) .. "/" .. atom(changedValue)
    .. ",restore=" .. atom(restoreOK) .. "/" .. atom(restoreResult)
    .. ",restored=" .. atom(restoredOK) .. "/" .. atom(restoredValue))

-- Prototype extraction behavior.
local function firstFunction(value)
    if T(value) == "function" then return value end
    if T(value) ~= "table" then return nil end
    local ok, found = PC(function()
        for _, item in NX, value do
            if T(item) == "function" then return item end
        end
    end)
    if ok then return found end
    return nil
end

local candidate, protoRoute, protoRaw = nil, "none", nil
if T(GetProto) == "function" then
    local ok, value = call(GetProto, ProtoProbe, 1, true)
    protoRaw = "getproto=" .. atom(ok) .. "/" .. atom(value)
    if ok then candidate = firstFunction(value) end
    if candidate then protoRoute = "getproto" end
end
if not candidate and T(GetProtos) == "function" then
    local ok, value = call(GetProtos, ProtoProbe)
    protoRaw = (protoRaw and protoRaw .. "," or "") .. "getprotos=" .. atom(ok) .. "/" .. sample(value)
    if ok then candidate = firstFunction(value) end
    if candidate then protoRoute = "getprotos" end
end
local protoCallOK, protoValue = call(candidate, PROTO_INPUT)
local protoClassOK, protoIsL = call(IsL, candidate)
add("PROTO", T(candidate) == "function" and protoCallOK and protoValue == PROTO_CONSTANT + PROTO_INPUT
    and protoClassOK and protoIsL == true,
    "route=" .. protoRoute .. ",raw=" .. clean(protoRaw, 150) .. ",candidate=" .. T(candidate)
    .. ",call=" .. atom(protoCallOK) .. ",value=" .. atom(protoValue)
    .. ",isl=" .. atom(protoClassOK) .. "/" .. atom(protoIsL))

-- loadstring behavior.
local LOAD_EXPECTED = 424242424
local compileOK, loaded, compileError = call(LoadString, "return " .. TS(LOAD_EXPECTED))
local loadedOK, loadedValue = call(loaded)
local loadedCOK, loadedC = call(IsC, loaded)
local loadedLOK, loadedL = call(IsL, loaded)
local loadedConstantsOK, loadedConstants = call(GetConstants, loaded)
local loadedKnown, loadedNative, loadedSource = nativeSource(loaded)
local loadPass = compileOK and T(loaded) == "function" and loadedOK and loadedValue == LOAD_EXPECTED
    and loadedCOK and loadedLOK and loadedC == false and loadedL == true
    and loadedConstantsOK and hasValue(loadedConstants, LOAD_EXPECTED)
    and loadedKnown and loadedNative == false
add("LOAD", loadPass,
    "compile=" .. atom(compileOK) .. ",fn=" .. T(loaded) .. ",error=" .. atom(compileError)
    .. ",run=" .. atom(loadedOK) .. "/" .. atom(loadedValue)
    .. ",class=" .. atom(loadedCOK) .. "/" .. atom(loadedC) .. "/" .. atom(loadedLOK) .. "/" .. atom(loadedL)
    .. ",const=" .. atom(loadedConstantsOK) .. "/" .. atom(hasValue(loadedConstants, LOAD_EXPECTED))
    .. ",source=" .. atom(loadedKnown) .. "/" .. atom(loadedNative) .. "/" .. loadedSource)

-- newcclosure behavior.
local wrapOK, wrapped = call(NewC, CBody)
local wrappedOK, wrappedValue = call(wrapped, -12345)
local wrappedCOK, wrappedC = call(IsC, wrapped)
local wrappedLOK, wrappedL = call(IsL, wrapped)
local wrappedKnown, wrappedNative, wrappedSource = nativeSource(wrapped)
local newcPass = wrapOK and T(wrapped) == "function" and wrappedOK and wrappedValue == 12345
    and wrappedCOK and wrappedLOK and wrappedC == true and wrappedL == false
    and wrappedKnown and wrappedNative == true
add("NEWC", newcPass,
    "wrap=" .. atom(wrapOK) .. ",fn=" .. T(wrapped) .. ",run=" .. atom(wrappedOK) .. "/" .. atom(wrappedValue)
    .. ",class=" .. atom(wrappedCOK) .. "/" .. atom(wrappedC) .. "/" .. atom(wrappedLOK) .. "/" .. atom(wrappedL)
    .. ",source=" .. atom(wrappedKnown) .. "/" .. atom(wrappedNative) .. "/" .. wrappedSource)

-- Reference and getgenv-result stability after all behavior checks.
local changed = {}
for index = 1, #Snapshots do
    local item = Snapshots[index]
    local ok, value = PC(item[3])
    if not ok or not RE(item[2], value) then changed[#changed + 1] = item[1] end
end
local genOK3, Cap3 = call(GetGenV)
local getgenvReferenceSame = field(Base, "getgenv") == GetGenV
local capSame = genOK3 and T(Cap3) == "table" and Cap1 ~= nil and RE(Cap1, Cap3)
add("STABLE", #changed == 0 and getgenvReferenceSame and capSame,
    "changed=" .. (#changed == 0 and "none" or TB.concat(changed, ","))
    .. ",getgenv_ref=" .. atom(getgenvReferenceSame)
    .. ",call3=" .. atom(genOK3) .. ",cap_same=" .. atom(capSame))

end

local probeOK, probeError = PC(runProbe)
if not probeOK then
    add("FATAL", false, probeError)
end

-- Emit the end marker even after a protected diagnostic failure. There are no file or
-- clipboard fallbacks, so every successfully formatted record is streamed directly.
safePrint("IB2P2|END|" .. (#Failures == 0 and "PASS" or "FAIL")
    .. "|count=" .. #Failures .. ",codes=" .. (#Failures == 0 and "none" or TB.concat(Failures, ",")))
