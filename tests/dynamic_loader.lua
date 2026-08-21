local compiled, message = loadstring("return 321")
assert(type(compiled) == "function", message)
local value = compiled()
assert(value == 321)
return {__ib2_test_output = "dynamic-loader:" .. value}
