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

## Hardening and tests

- Implementation plan: [`HARDENING_PLAN.md`](HARDENING_PLAN.md)
- Implementation/test report: [`HARDENING_REPORT.md`](HARDENING_REPORT.md)
- Linux differential suite: [`tests/run_linux_tests.sh`](tests/run_linux_tests.sh)
