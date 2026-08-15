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

AntiDump uses capability-gated checks rather than requiring one executor API set. It snapshots native primitives and capability providers, cross-checks `debug.gethook`, `debug.getinfo`/`debug.info`, `iscclosure` and `islclosure` only when the host exposes them, and combines identity, provenance and behavior signals with a weighted threshold. A sealed guard state drives jittered scheduling so checks occur at VM startup, immediately after root deserialization, and periodically during dispatch. A high-confidence result becomes sticky and selects a bounded silent decoy path; it does not print a detection message, modify `getgenv()` APIs, perform network/file probes, start background scanners, allocate unbounded memory, or loop forever.

Generated files use the v4 protected payload with feature value `15`. After the real serialized body is DEFLATE-compressed, it is state-masked, split into records, and interleaved with 64–96 KiB of independent CSPRNG entropy records. An entropy digest participates in the inner body-mask state, while a separate envelope tag authenticates framing and physical record order before inflate; deleting, modifying, or reordering a record is rejected even if the outer payload tag is recomputed.

V4 authenticates every complete prototype slice before parsing its schema or child framing. Constants remain independently masked and tagged opaque capsules at startup. A complete block manifest binds its range, route token, ordered constant references and referenced capsule bytes, flow verifier, ordered successor/state records, and instruction body. Only after that manifest passes are the referenced capsules restored into a block-decoder-local cache. With AntiDump enabled, plaintext constants and instructions therefore exist only during the current invocation's block decode/execution; the shared prototype instruction table remains empty and its constant store contains only opaque capsules.

Each generation also independently permutes the numeric ABI of all 15 `Chunk`, 9 `Block`, 4 `Flow`, and 3 `FlowCache` slots. Constructors use keyed assignments, block aliases share one layout, and opcode handlers are rewritten with the same build-wide maps. A non-sequential transfer replaces the invocation-local cache and a later re-entry reauthenticates and decodes the opaque body and its referenced capsules. The envelope increases each generated payload by 64–96 KiB before basE91 expansion; this is an intentional fixed protection/size tradeoff, not removable padding.

Multi-block prototypes are selected automatically for dispatcher flattening only after conservative CFG, jump-companion, `SETLIST C==0`, and Closure-binding checks. Unsupported or malformed shapes fall back atomically to the protected real-PC path without partial dispatcher metadata; no source marker is required.

The source frontend and build pipeline still consume Lua 5.1 bytecode. Luau/Roblox priority in this release applies to the runtime anti-debug capability probes; Luau-only source syntax still requires a future native frontend.

## Hardening and tests

- Implementation plan: [`HARDENING_PLAN.md`](HARDENING_PLAN.md)
- Implementation/test report: [`HARDENING_REPORT.md`](HARDENING_REPORT.md)
- Anti-dump summary: [`反dump优化总结.md`](反dump优化总结.md)
- Linux differential suite: [`tests/run_linux_tests.sh`](tests/run_linux_tests.sh). Set `IB2_RANDOM_RUNS=20` for the full randomized matrix; it verifies the 64–96 KiB entropy envelope, outer-tag-valid record tamper rejection, v4 prototype/block/capsule authentication, all four non-identity runtime slot layouts and cross-build ABI variation, Luau capability simulations, all three guard checkpoints, ephemeral block/constant-cache behavior, dispatcher selection/fallback, flow tamper rejection, Closure/SETLIST boundaries, and Lua 5.1 semantics.
- CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the full Linux suite and Release publish builds for Linux x64, Windows x64, and macOS arm64.
