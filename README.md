# IronBrew2

VM-based Lua 5.1 obfuscation.

## Build and run

Requirements:

- .NET 8 SDK
- Lua 5.1 and `luac` 5.1 in `PATH`

```bash
dotnet build "IronBrew2 CLI/IronBrew2 CLI.csproj" -c Release
dotnet "IronBrew2 CLI/bin/Release/net8.0/IronBrew2 CLI.dll" input.lua
```

The CLI has one supported configuration, equivalent to the former `mid` behavior: control-flow processing and DEFLATE are enabled, while executor-specific AntiDump and EnvironmentLock gates remain disabled. Use `--line-info` only when original-line error reporting is required.

Generated files use the v3 protected payload with feature value `7`: prototype-local schemas and opcode banks, authenticated lazy basic blocks, invocation-local CFG state, and route-state dispatcher framing. Multi-block prototypes are selected automatically for dispatcher flattening only after conservative CFG, jump-companion, `SETLIST C==0`, and Closure-binding checks. Unsupported or malformed shapes fall back atomically to the protected real-PC path without partial dispatcher metadata; no source marker is required.

## Hardening and tests

- Implementation plan: [`HARDENING_PLAN.md`](HARDENING_PLAN.md)
- Implementation/test report: [`HARDENING_REPORT.md`](HARDENING_REPORT.md)
- Linux differential suite: [`tests/run_linux_tests.sh`](tests/run_linux_tests.sh). Set `IB2_RANDOM_RUNS=20` for the full randomized matrix; it includes automatic dispatcher selection, safe fallback, route-state tamper rejection, Closure/SETLIST boundaries, lazy blocks, and Lua 5.1 semantic checks.
- CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the full Lua 5.1 suite on Linux and Release publish builds for Linux x64, Windows x64, and macOS arm64.
