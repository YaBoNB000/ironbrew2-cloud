-- Backward-compatible signed-bit entry point.
local path = assert(arg[1], "expected Lua file path")
arg[1], arg[2] = "signed-bit", path
dofile("tests/executor_runner.lua")
