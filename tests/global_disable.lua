local print_result = print("payload-print-must-be-hidden")
local error_result = error("payload-error-must-be-hidden")
local warn_result = warn("payload-warn-must-be-hidden")
return print_result, error_result, warn_result
