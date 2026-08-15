-- Backward-compatible entry point for older local invocations.
local aliases = {
    capabilities = "trusted",
    ["capability-spoof"] = "classifier-spoof",
}
arg[1] = aliases[arg[1]] or arg[1]
dofile("tests/executor_runner.lua")
