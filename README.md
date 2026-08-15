# IronBrew2

VM-based Lua 5.1 bytecode obfuscation with Luau/Roblox-aware runtime defenses.

## Build and run

Requirements:

- .NET 8 SDK
- Lua 5.1 and `luac` 5.1 in `PATH`

```bash
dotnet build "IronBrew2 CLI/IronBrew2 CLI.csproj" -c Release
dotnet "IronBrew2 CLI/bin/Release/net8.0/IronBrew2 CLI.dll" input.lua
```

The CLI has one supported configuration. Control-flow processing, DEFLATE and VM-integrated AntiDump are enabled. The strict `EnvironmentLock` fingerprint gate, destructive executor hooks, Mutation and SuperOperator remain disabled. Use `--line-info` only when original-line error reporting is required.

AntiDump uses capability-gated checks rather than requiring one executor API set. It snapshots native primitives, uses `debug.gethook`, `iscclosure` and `islclosure` only when the host exposes them, and rechecks the snapshot during dispatch. A high-confidence signal selects a bounded silent decoy path; it does not print a detection message, modify `getgenv()` APIs, start background scanners, allocate unbounded memory, or loop forever.

Generated files use the v3 protected payload with feature value `7`: prototype-local schemas and opcode banks, authenticated lazy basic blocks, invocation-local CFG state, and route-state dispatcher framing. With AntiDump enabled, opaque block bodies are retained and plaintext instructions exist only in the current invocation's `Flow` cache; the shared prototype instruction table remains empty. A non-sequential transfer replaces that cache and a later re-entry authenticates and decodes the opaque body again.

Multi-block prototypes are selected automatically for dispatcher flattening only after conservative CFG, jump-companion, `SETLIST C==0`, and Closure-binding checks. Unsupported or malformed shapes fall back atomically to the protected real-PC path without partial dispatcher metadata; no source marker is required.

The source frontend and build pipeline still consume Lua 5.1 bytecode. Luau/Roblox priority in this release applies to the runtime anti-debug capability probes; Luau-only source syntax still requires a future native frontend.

## Hardening and tests

- Implementation plan: [`HARDENING_PLAN.md`](HARDENING_PLAN.md)
- Implementation/test report: [`HARDENING_REPORT.md`](HARDENING_REPORT.md)
- Anti-dump summary: [`反dump优化总结.md`](反dump优化总结.md)
- Linux differential suite: [`tests/run_linux_tests.sh`](tests/run_linux_tests.sh). Set `IB2_RANDOM_RUNS=20` for the full randomized matrix; it includes Luau capability simulations, active-hook and replaced-primitive decoy checks, executor-global preservation, ephemeral block-cache probes, automatic dispatcher selection, safe fallback, route-state tamper rejection, Closure/SETLIST boundaries, and Lua 5.1 semantic checks.
- CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the full Linux suite and Release publish builds for Linux x64, Windows x64, and macOS arm64.
