local original_loadstring = loadstring
loadstring = function()
    return function()
        return -1
    end
end
local compiled = original_loadstring("return 321")
return {__ib2_test_output = "hook-bypass:" .. tostring(compiled())}
