local function unsigned_bxor(a, b)
    a = a % 4294967296
    b = b % 4294967296
    local result = 0
    local bit_value = 1
    for _ = 0, 31 do
        local aa = a % 2
        local bb = b % 2
        if aa ~= bb then
            result = result + bit_value
        end
        a = (a - aa) / 2
        b = (b - bb) / 2
        bit_value = bit_value * 2
    end
    return result
end

bit = {
    bxor = function(a, b)
        local result = unsigned_bxor(a, b)
        if result >= 2147483648 then
            return result - 4294967296
        end
        return result
    end
}

dofile(assert(arg[1], "expected Lua file path"))
