local output = {}

local function branch(value)
    local merged
    if value % 2 == 0 then
        merged = value + 7
    else
        merged = value * 3
    end
    output[#output + 1] = tostring(merged)
    return merged
end

local first = branch(4)
local second = branch(5)
local result = table.concat(output, ":") .. ":" .. tostring(first + second)
print(result)
return {__ib2_test_output = result}
