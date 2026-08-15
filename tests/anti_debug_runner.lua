local mode = assert(arg[1], "mode required")
local path = assert(arg[2], "obfuscated script required")

local originalByte = string.byte
local originalHookFunction = rawget(_G, "hookfunction")
local sentinelHookFunction = function() return "sentinel" end
hookfunction = sentinelHookFunction

if mode == "capabilities" or mode == "primitive-hook" then
    iscclosure = function(value)
        local info = debug.getinfo(value, "S")
        return info and info.what == "C" or false
    end
    islclosure = function(value)
        return not iscclosure(value)
    end
end

if mode == "primitive-hook" then
    string.byte = function(...)
        return originalByte(...)
    end
elseif mode == "debug-hook" then
    debug.sethook(function() end, "", 1)
elseif mode ~= "capabilities" then
    error("unknown mode: " .. tostring(mode))
end

local ok, result = pcall(dofile, path)
if debug.sethook then debug.sethook() end
string.byte = originalByte
assert(hookfunction == sentinelHookFunction, "generated VM modified an executor global")
hookfunction = originalHookFunction
iscclosure, islclosure = nil, nil
assert(ok, result)
