local mode = assert(arg[1], "mode required")
local path = assert(arg[2], "obfuscated script required")

local originalByte = string.byte
local originalRawSet = rawset
local originalDebugGetInfo = debug and debug.getinfo
local originalHookFunction = rawget(_G, "hookfunction")
local originalGetGenV = rawget(_G, "getgenv")
local originalIsC = rawget(_G, "iscclosure")
local originalIsL = rawget(_G, "islclosure")
local sentinelHookFunction = function() return "sentinel" end
hookfunction = sentinelHookFunction

local capabilityModes = {
    capabilities = true,
    ["primitive-hook"] = true,
    ["debug-api-hook"] = true,
    ["raw-hook"] = true,
}

if capabilityModes[mode] then
    getgenv = function() return _G end
    iscclosure = function(value)
        local info = originalDebugGetInfo(value, "S")
        return info and info.what == "C" or false
    end
    islclosure = function(value)
        return not iscclosure(value)
    end
elseif mode == "capability-spoof" then
    getgenv = function() return _G end
    iscclosure = function() return true end
    islclosure = function() return false end
end

if mode == "primitive-hook" then
    string.byte = function(...)
        return originalByte(...)
    end
elseif mode == "raw-hook" then
    rawset = function(...)
        return originalRawSet(...)
    end
elseif mode == "debug-api-hook" then
    debug.getinfo = function(...)
        return originalDebugGetInfo(...)
    end
elseif mode == "debug-hook" then
    debug.sethook(function() end, "", 1)
elseif mode ~= "capabilities" and mode ~= "capability-spoof" then
    error("unknown mode: " .. tostring(mode))
end

local installedGetGenV = getgenv
local installedIsC = iscclosure
local installedIsL = islclosure
local ok, result = pcall(dofile, path)
if debug and debug.sethook then debug.sethook() end
string.byte = originalByte
rawset = originalRawSet
if debug then debug.getinfo = originalDebugGetInfo end
assert(hookfunction == sentinelHookFunction, "generated VM modified hookfunction")
assert(getgenv == installedGetGenV, "generated VM modified getgenv")
assert(iscclosure == installedIsC, "generated VM modified iscclosure")
assert(islclosure == installedIsL, "generated VM modified islclosure")
hookfunction = originalHookFunction
getgenv = originalGetGenV
iscclosure = originalIsC
islclosure = originalIsL
assert(ok, result)
