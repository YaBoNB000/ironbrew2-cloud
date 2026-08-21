local values = {}
local dynamic_key = "dynamic"
local register_value = 41
values[dynamic_key] = register_value
values.fixed = register_value
values[dynamic_key] = 17
values.both = 23
local test_output = values.dynamic .. ":" .. values.fixed .. ":" .. values.both
print(test_output)
return {__ib2_test_output = test_output}
