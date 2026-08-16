-- Trusted executor-semantics harness for positive-path Linux tests.
-- This is test infrastructure, not a production bypass: generated artifacts do
-- not inspect a marker and must still satisfy every public behavior challenge.
local mode = assert(arg[1], "mode required")
local path = assert(arg[2], "obfuscated script required")

local native_getinfo = assert(debug and debug.getinfo)
local native_getupvalue = assert(debug and debug.getupvalue)
local native_setupvalue = assert(debug and debug.setupvalue)
local native_byte = string.byte
local native_rawset = rawset
local native_loadstring = loadstring
local inactive_targets = setmetatable({}, {__mode = "k"})
local lua_constants_calls = 0
local lua_upvalues_calls = 0
local lua_setupvalue_calls = 0

local function closure_kind(value)
    if type(value) ~= "function" then return nil end
    local information = native_getinfo(value, "S")
    return information and information.what or nil
end

local function inspect_constants(value)
    if closure_kind(value) == "C" then error("C closures have no accessible constants") end
    lua_constants_calls = lua_constants_calls + 1
    if mode == "removed-root-contracts" and lua_constants_calls == 1 then
        -- The generated constant probe remains callable, but its randomized
        -- value is not visible through this executor's constants API.
        return {}
    end
    -- Lua 5.1 cannot expose an inactive proto object. The harness associates a
    -- wrapper with its real child so constants inspection remains independent
    -- from whether that executor representation is callable.
    local target = inactive_targets[value] or value
    local ok, result = pcall(target, 0)
    if ok and (type(result) == "number" or type(result) == "string" or type(result) == "boolean") then
        return {result}
    end
    return {}
end

local function inspect_upvalues(value)
    if closure_kind(value) == "C" then
        if mode == "compat-representations" then return {} end
        if mode == "c-upvalue-leak" then return {197843211} end
        error("C closures have no accessible upvalues")
    end
    lua_upvalues_calls = lua_upvalues_calls + 1
    if mode == "removed-root-contracts" and lua_upvalues_calls == 1 then
        -- The API succeeds with the required table shape but does not expose
        -- the private randomized probe value.
        return {}
    end
    local values = {}
    local index = 1
    while true do
        local name, item = native_getupvalue(value, index)
        if not name then break end
        values[index] = item
        index = index + 1
    end
    return values
end

local function inactive_proto(target)
    if mode == "callable-proto" then return target end
    local wrapper
    if mode == "compat-representations" then
        wrapper = newproxy(true)
    elseif mode == "wrong-callable-proto" or mode == "removed-root-contracts" then
        wrapper = function() return -197843211 end
    else
        wrapper = function() error("inactive prototype") end
    end
    inactive_targets[wrapper] = target
    return wrapper
end

local function inspect_proto(value, activated)
    if closure_kind(value) == "C" then error("C closures have no prototypes") end
    local ok, result = pcall(value)
    if not ok or type(result) ~= "function" then error("prototype not found") end
    if activated then
        if mode == "removed-root-contracts" then
            return {function() return -197843211 end}
        end
        return {result}
    end
    return inactive_proto(result)
end

local executor_environment = {}
local baseline_globals
local getgenv_calls = 0
function getgenv()
    getgenv_calls = getgenv_calls + 1
    if mode == "polluted-genv" then return _G end
    if mode == "canary-error" and getgenv_calls == 3 then
        -- The first challenge writes its random canary to both environments
        -- before this call. Observe the later sink from outside that challenge
        -- and encode cleanup success only in the process status.
        debug.sethook(function()
            local clean = next(executor_environment) == nil
            for key, value in pairs(_G) do
                if baseline_globals[key] ~= value then clean = false break end
            end
            if clean then
                for key, value in pairs(baseline_globals) do
                    if _G[key] ~= value then clean = false break end
                end
            end
            os.exit(clean and 42 or 43)
        end, "", 10000)
        error("injected getgenv failure")
    end
    return executor_environment
end
function identifyexecutor() return "Arena Test Executor", "1.0" end
if mode ~= "no-alias" then
    getexecutorname = identifyexecutor
    executorname = identifyexecutor
end
function checkcaller() return true end
function iscclosure(value) return closure_kind(value) == "C" end
function islclosure(value)
    local kind = closure_kind(value)
    -- Lua 5.1 labels loadstring chunks as "main" even though executor
    -- classifiers correctly treat them as Lua closures.
    return kind ~= nil and kind ~= "C"
end
function newcclosure(_) return math.abs end

-- Lua 5.1 already provides native loadstring. The negative mode models an
-- implementation that incorrectly throws instead of returning nil + message.
if mode == "invalid-load" then
    loadstring = function(source, chunkname)
        local loaded, message = native_loadstring(source, chunkname)
        if not loaded then error(message) end
        return loaded
    end
end

typeof = function(value)
    if type(value) == "table" and rawget(value, "__roblox_type") then
        return rawget(value, "__roblox_type")
    end
    return type(value)
end

local players = {ClassName = "Players", __roblox_type = "Instance"}
game = {
    GetService = function(_, service)
        if service == "Players" then return players end
        error("unknown test service")
    end,
}
Instance = {new = function(class_name) return {ClassName = class_name, __roblox_type = "Instance"} end}
Vector3 = {new = function() return {__roblox_type = "Vector3"} end}
task = {
    wait = function() end,
    spawn = function(callback, ...) return callback(...) end,
    defer = function(callback, ...) return callback(...) end,
}

debug.getconstants = inspect_constants
debug.getupvalues = inspect_upvalues
debug.getproto = function(value, _, activated) return inspect_proto(value, activated) end
debug.getprotos = function(value) return {inspect_proto(value, false)} end
debug.setupvalue = function(value, index, replacement)
    if closure_kind(value) == "C" then error("C closure upvalues are protected") end
    lua_setupvalue_calls = lua_setupvalue_calls + 1
    if mode == "removed-root-contracts" and lua_setupvalue_calls <= 2 then
        -- Both setup and restore calls succeed, but the interim write is not
        -- observable; the private probe consequently remains at its original
        -- value for the retained final-restore check.
        return "upvalue"
    end
    return native_setupvalue(value, index, replacement)
end

if mode == "c-debug-leak" then
    debug.getconstants = function(value)
        if closure_kind(value) == "C" then return {} end
        return inspect_constants(value)
    end
end

if mode == "signed-bit" then
    local function unsigned_bxor(left, right)
        left = left % 4294967296
        right = right % 4294967296
        local result, bit_value = 0, 1
        for _ = 0, 31 do
            local left_bit, right_bit = left % 2, right % 2
            if left_bit ~= right_bit then result = result + bit_value end
            left = (left - left_bit) / 2
            right = (right - right_bit) / 2
            bit_value = bit_value * 2
        end
        return result
    end
    bit = {
        bxor = function(left, right)
            local result = unsigned_bxor(left, right)
            return result >= 2147483648 and result - 4294967296 or result
        end,
    }
elseif mode == "primitive-hook" then
    string.byte = function(...) return native_byte(...) end
elseif mode == "raw-hook" then
    rawset = function(...) return native_rawset(...) end
elseif mode == "debug-api-hook" then
    debug.getinfo = function(...) return native_getinfo(...) end
elseif mode == "classifier-spoof" then
    iscclosure = function() return true end
    islclosure = function() return false end
elseif mode == "identity-spoof" then
    local counter = 0
    identifyexecutor = function()
        counter = counter + 1
        return "Unstable Executor " .. counter, "1.0"
    end
elseif mode == "version-number" then
    identifyexecutor = function() return "Arena Test Executor", 1 end
elseif mode == "missing-debug" then
    debug.getproto = nil
    debug.getprotos = nil
elseif mode == "trusted" or mode == "no-alias" or mode == "compat-representations"
    or mode == "polluted-genv" or mode == "invalid-load" or mode == "callable-proto"
    or mode == "c-debug-leak" or mode == "c-upvalue-leak" or mode == "wrong-callable-proto"
    or mode == "removed-root-contracts" or mode == "canary-error" then
    -- Behavior for these modes is installed above before the generated chunk.
else
    error("unknown executor harness mode: " .. tostring(mode))
end

if mode == "compat-representations" then
    -- Model real executors that expose APIs through the thread environment's
    -- __index path rather than as raw getfenv keys.
    local proxy_names = {
        "getgenv", "identifyexecutor", "getexecutorname", "executorname", "checkcaller",
        "iscclosure", "islclosure", "newcclosure", "loadstring", "typeof", "game",
        "Instance", "Vector3", "task",
    }
    for _, name in ipairs(proxy_names) do
        executor_environment[name] = rawget(_G, name)
        rawset(_G, name, nil)
    end
    setmetatable(_G, {__index = executor_environment})
end

baseline_globals = {}
for key, value in pairs(_G) do baseline_globals[key] = value end

dofile(path)
