local probe = rawget(_G, "__ib2_lazy_opaque")
local opaque = probe and probe() or -1
if probe then
    assert(opaque > 0, "unexecuted instruction blocks were decoded eagerly")
end

local unreachable = false
local value
if unreachable then
    value = "opaque-only-constant"
else
    value = "executed-constant"
end

local function makeAdder(base)
    return function(delta)
        return base + delta
    end
end

local items = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60
}

local total = 0
for index = 1, #items do
    if index % 2 == 0 then
        total = total + items[index]
    else
        total = total - items[index]
    end
end

print("lazy-blocks:" .. opaque .. ":" .. value .. ":" .. makeAdder(total)(7))
