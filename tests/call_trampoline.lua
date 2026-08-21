local output = {}

local function emit(label, ...)
    local count = select("#", ...)
    local parts = {label, tostring(count)}
    for index = 1, count do
        local value = select(index, ...)
        parts[#parts + 1] = value == nil and "<nil>" or tostring(value)
    end
    output[#output + 1] = table.concat(parts, ":")
end

local function producer()
    return 4, nil, 6
end

local function single(value)
    return value + 1, value + 2, nil
end

local function many(left, middle, right)
    return left + middle + right, left * middle * right, nil
end

local function capture(...)
    return select("#", ...), ...
end

-- Fixed, single and discarded result paths with no, one and several arguments.
local no_a, no_b, no_c = producer()
local no_one = producer()
producer()
emit("no-args", no_a, no_b, no_c, no_one)

local one_a, one_b, one_c = single(10)
local one_one = single(20)
single(30)
emit("one-arg", one_a, one_b, one_c, one_one)

local fixed_a, fixed_b, fixed_c = many(2, 3, 4)
local fixed_one = many(3, 4, 5)
many(4, 5, 6)
emit("fixed-args", fixed_a, fixed_b, fixed_c, fixed_one)

-- C == 0 inner calls feed B == 0 outer calls. Exercise fixed, one,
-- discarded and variable result consumers while retaining embedded nils.
local top_fixed_count, top_fixed_a, top_fixed_b, top_fixed_c = capture(producer())
local top_one = capture(producer())
capture(producer())
local top_variable_count, top_variable_inner_count,
    top_variable_a, top_variable_b, top_variable_c = capture(capture(producer()))
emit("top-args", top_fixed_count, top_fixed_a, top_fixed_b, top_fixed_c,
    top_one, top_variable_count, top_variable_inner_count,
    top_variable_a, top_variable_b, top_variable_c)

local no_variable_count, no_variable_a, no_variable_b, no_variable_c = capture(producer())
local one_variable_count, one_variable_a, one_variable_b, one_variable_c = capture(single(40))
local fixed_variable_count, fixed_variable_a, fixed_variable_b, fixed_variable_c = capture(many(5, 6, 7))
emit("variable-results", no_variable_count, no_variable_a, no_variable_b, no_variable_c,
    one_variable_count, one_variable_a, one_variable_b, one_variable_c,
    fixed_variable_count, fixed_variable_a, fixed_variable_b, fixed_variable_c)

-- SELF must leave the receiver in A+1; the trampoline sees it as the first
-- ordinary argument and must not collapse the method-call window.
local object = {base = 9}
function object:combine(left, right)
    return self.base + left + right, self == object
end
local method_value, method_self = object:combine(4, 8)
emit("self", method_value, method_self)

-- Reproduce the high-value HttpGet -> loadstring -> compiled chunk -> options
-- call chain, including loadstring's chunk-name argument.
local mock_game = {}
function mock_game:HttpGet(url, cached)
    assert(url == "https://example.invalid/saveinstance.luau")
    assert(cached == true)
    return "return function(options) return options.NilInstances and options.TreatUnionsAsParts, options.IgnoreNonArchivable, options.IsolateLocalPlayerCharacter end"
end
local compiled, compile_message = loadstring(
    mock_game:HttpGet("https://example.invalid/saveinstance.luau", true),
    "saveinstance"
)
assert(type(compiled) == "function", compile_message)
local save_instance = compiled()
local loader_a, loader_b, loader_c = save_instance({
    NilInstances = true,
    IgnoreNonArchivable = false,
    IsolateLocalPlayer = true,
    IsolateLocalPlayerCharacter = true,
    TreatUnionsAsParts = true,
})
emit("loader-chain", loader_a, loader_b, loader_c)

-- Keep all three TAILCALL argument forms live. The recursive case is deep
-- enough to catch an accidental result-capture wrapper around the tail target.
local function tail_no_arguments()
    return producer()
end

local function tail_fixed_arguments(left, right)
    return many(left, right, 2)
end

local function tail_top_arguments(...)
    return capture(...)
end

local function bounce(remaining, total)
    if remaining == 0 then
        return total
    end
    return bounce(remaining - 1, total + remaining)
end

local tail_no_a, tail_no_b, tail_no_c = tail_no_arguments()
local tail_fixed_a, tail_fixed_b, tail_fixed_c = tail_fixed_arguments(7, 8)
local tail_top_count, tail_top_a, tail_top_b, tail_top_c = tail_top_arguments(11, nil, 13)
emit("tail", tail_no_a, tail_no_b, tail_no_c,
    tail_fixed_a, tail_fixed_b, tail_fixed_c,
    tail_top_count, tail_top_a, tail_top_b, tail_top_c, bounce(750, 0))

local result = table.concat(output, "\n")
print(result)
return {__ib2_test_output = result}
