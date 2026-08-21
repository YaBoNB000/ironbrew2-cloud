local emitted = {}
local function emit(label, ...)
    local values = {...}
    local parts = {label}
    for i = 1, #values do
        parts[#parts + 1] = tostring(values[i])
    end
    local line = table.concat(parts, ":")
    emitted[#emitted + 1] = line
    print(line)
end

local truth = true
local lie = false
local integer = 123456
local fraction = -17.25
local binary = "A\000B\255Z"
emit("constants", truth, lie, integer, fraction, #binary,
    string.byte(binary, 1), string.byte(binary, 2), string.byte(binary, 4))

local function makeCounter(start)
    local value = start
    local function step(delta, ...)
        local extras = {...}
        for i = 1, #extras do
            value = value + extras[i]
        end
        value = value + delta
        return value, #extras
    end
    return step
end

local counter = makeCounter(10)
local c1, n1 = counter(2, 3, 4)
local c2, n2 = counter(-5)
emit("closure", c1, n1, c2, n2)

local function layer(a)
    return function(b)
        return function(c)
            a = a + 1
            return a + b + c
        end
    end
end
local middle = layer(5)
local inner = middle(7)
emit("nested", inner(11), inner(11))

local total = 0
for i = 1, 8 do
    if i % 3 == 0 then
        total = total - i
    elseif i % 2 == 0 then
        total = total + i * 2
    else
        total = total + i
    end
end

local w = 0
while w < 4 do
    total = total + w
    w = w + 1
end
repeat
    total = total - 2
    w = w - 1
until w == 0
emit("flow", total, w)

local function multiple(a, b)
    return a + b, a * b, a - b
end
local m1, m2, m3 = multiple(9, 4)
emit("returns", m1, m2, m3)

local function recurse(n)
    if n <= 1 then
        return 1
    end
    return n * recurse(n - 1)
end
emit("recurse", recurse(7))

local data = {alpha = 3, beta = 8, [1] = "x", [2] = "y"}
local sum = 0
for key, value in pairs(data) do
    if type(key) == "string" then
        sum = sum + value
    end
end
emit("table", data[1] .. data[2], sum)

return {__ib2_test_output = table.concat(emitted, "\n")}
