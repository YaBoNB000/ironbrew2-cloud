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

The CLI has one supported configuration. Control-flow processing, DEFLATE, VM-integrated AntiDump and strict `EnvironmentLock` executor attestation are enabled. Mutation, SuperOperator and destructive executor hooks remain disabled. Use `--line-info` only when original-line error reporting is required.

Generated scripts are executor-only by default. Admission is brand-neutral: `identifyexecutor()` must be stable and non-empty, but no executor name or version is compared with an allow-list. Every required contract is a hard AND, including Roblox host behavior, stable `getgenv()`, `checkcaller()`, C/L closure classification, `newcclosure`, `loadstring`, debug constant/upvalue/prototype/setupvalue behavior, native primitive provenance, primitive snapshots and a randomized behavioral transcript. Plain Lua/Luau, Roblox Studio, incomplete shims and any environment that changes after startup do not execute the payload.

Successful attestation restores a per-build token that derives the real payload seed and also binds the initial flow state, route token, transition keys, block verifiers and block manifests. The guard runs at VM startup, after root deserialization, before first-block entry and periodically during dispatch. Failure is sticky: invocation-local plaintext references are cleared where available, then the current thread enters a randomized, non-yielding bit-mixing state graph that never returns and uses fixed O(1) memory. It prints and throws no detection message, does not modify executor globals, and performs no network/file probes or background scans. An external watchdog may still terminate the busy thread.

This is a client-side cost amplifier, not an unforgeable executor oracle. A sufficiently capable environment can simulate all contracts or patch the shipped guard and token derivation.

Generated files use the v4 protected payload with feature value `15`. After the real serialized body is DEFLATE-compressed, it is state-masked, split into records, and interleaved with 64–96 KiB of independent CSPRNG entropy records. An entropy digest participates in the inner body-mask state, while a separate envelope tag authenticates framing and physical record order before inflate; deleting, modifying, or reordering a record is rejected even if the outer payload tag is recomputed.

V4 authenticates every complete prototype slice before parsing its schema or child framing. Constants remain independently masked and tagged opaque capsules at startup. A complete block manifest binds its range, route token, ordered constant references and referenced capsule bytes, flow verifier, ordered successor/state records, and instruction body. Each block body is a five-page columnar IR: descriptor, opcode, A, B and C streams are independently length-framed and physically reordered by a non-identity permutation derived from that block's execution state and prototype keys. The runtime authenticates the manifest before recovering page roles and rejects any framing mismatch, invalid descriptor, or under/over-consumed column. Only then are referenced capsules restored into a block-decoder-local cache. With AntiDump enabled, plaintext constants and instructions therefore exist only during the current invocation's block decode/execution; the shared prototype instruction table remains empty and its constant store contains only opaque capsules.

Each generation also independently permutes the numeric ABI of all 15 `Chunk`, 9 `Block`, 4 `Flow`, and 3 `FlowCache` slots. Constructors use keyed assignments, block aliases share one layout, and opcode handlers are rewritten with the same build-wide maps. A non-sequential transfer replaces the invocation-local cache and a later re-entry reauthenticates and decodes the opaque body and its referenced capsules. The envelope increases each generated payload by 64–96 KiB before basE91 expansion; this is an intentional fixed protection/size tradeoff, not removable padding.

Multi-block prototypes are selected automatically for dispatcher flattening only after conservative CFG, jump-companion, `SETLIST C==0`, and Closure-binding checks. Unsupported or malformed shapes fall back atomically to the protected real-PC path without partial dispatcher metadata; no source marker is required.

The source frontend and build pipeline still consume Lua 5.1 bytecode. Luau/Roblox priority in this release applies to strict runtime executor attestation; Luau-only source syntax still requires a future native frontend.

## Hardening and tests

- Implementation plan: [`HARDENING_PLAN.md`](HARDENING_PLAN.md)
- Implementation/test report: [`HARDENING_REPORT.md`](HARDENING_REPORT.md)
- Anti-dump summary: [`反dump优化总结.md`](反dump优化总结.md)
- Linux differential suite: [`tests/run_linux_tests.sh`](tests/run_linux_tests.sh). Set `IB2_RANDOM_RUNS=20` for the full randomized matrix; it verifies the 64–96 KiB entropy envelope, outer-tag-valid record tamper rejection, v4 prototype/block/capsule authentication, per-block non-identity column-role maps and authenticated column framing/consumption rejection, all four non-identity runtime slot layouts and cross-build ABI variation, all four guard checkpoints, ephemeral block/constant-cache behavior, dispatcher selection/fallback, flow tamper rejection, Closure/SETLIST boundaries, and Lua 5.1 semantics. Positive semantic tests run through [`tests/executor_runner.lua`](tests/executor_runner.lua)'s trusted executor contract; plain and malformed environments are launched under an external timeout and must stay silent and non-returning.
- CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the full Linux suite and Release publish builds for Linux x64, Windows x64, and macOS arm64.
