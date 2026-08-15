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

local function closure_kind(value)
    if type(value) ~= "function" then return nil end
    local information = native_getinfo(value, "S")
    return information and information.what or nil
end

local function inspect_constants(value)
    -- The generated challenges use side-effect-free, zero-argument canaries.
    -- Returning their observed primitive result mirrors an executor constants
    -- API closely enough to exercise the cross-API contract under Lua 5.1.
    local ok, result = pcall(value)
    if ok and (type(result) == "number" or type(result) == "string" or type(result) == "boolean") then
        return {result}
    end
    return {}
end

local function inspect_upvalues(value)
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

local function inspect_proto(value)
    local ok, result = pcall(value)
    if ok and type(result) == "function" then return result end
    return nil
end

function getgenv() return _G end
function identifyexecutor() return "Arena Test Executor", "1.0" end
getexecutorname = identifyexecutor
executorname = identifyexecutor
function checkcaller() return true end
function iscclosure(value) return closure_kind(value) == "C" end
function islclosure(value)
    local kind = closure_kind(value)
    -- Lua 5.1 labels loadstring chunks as "main" even though executor
    -- classifiers correctly treat them as Lua closures.
    return kind ~= nil and kind ~= "C"
end
function newcclosure(_) return math.abs end

-- Lua 5.1 already provides native loadstring.
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
debug.getproto = function(value) return inspect_proto(value) end
debug.getprotos = function(value)
    local result = inspect_proto(value)
    return result and {result} or {}
end
debug.setupvalue = native_setupvalue

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
elseif mode == "debug-hook" then
    debug.sethook(function() end, "", 1)
elseif mode == "classifier-spoof" then
    iscclosure = function() return true end
    islclosure = function() return false end
elseif mode == "identity-spoof" then
    local counter = 0
    identifyexecutor = function()
        counter = counter + 1
        return "Unstable Executor " .. counter, "1.0"
    end
elseif mode == "missing-debug" then
    debug.getproto = nil
    debug.getprotos = nil
elseif mode ~= "trusted" then
    error("unknown executor harness mode: " .. tostring(mode))
end

dofile(path)
