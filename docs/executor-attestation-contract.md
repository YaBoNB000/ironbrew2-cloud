# Executor attestation behavior contract

Research date: 2026-08-16

The runtime guard is deliberately brand-neutral. It does not treat an executor
name, a claimed UNC/sUNC percentage, or the presence of global names as proof.
Admission requires a cross-API behavior transcript, and every failure normally
enters the same silent non-yielding fixed-memory sink.

> **Enforcement state:** `TemporaryGlobalSinkBypass` is `false`. Retained guard
> failures therefore enter the production silent non-yielding sink; the
> standalone checker is the non-blocking diagnostic path.

This is a client-side compatibility contract, not an unforgeable executor
oracle. An environment that completely emulates every admitted behavior can
also emulate the contract. The purpose of the hard-AND challenge is to reject
ordinary Lua/Luau/Studio and shallow API stubs without relying on brands.

## Primary references

- sUNC overview: <https://docs.sunc.su/About/what-is-sunc/>
- `getgenv`: <https://docs.sunc.su/Environment/getgenv/>
- `identifyexecutor`: <https://docs.sunc.su/Miscellaneous/identifyexecutor/>
- `checkcaller`: <https://docs.sunc.su/Closures/checkcaller/>
- `iscclosure`: <https://docs.sunc.su/Closures/iscclosure/>
- `islclosure`: <https://docs.sunc.su/Closures/islclosure/>
- `newcclosure`: <https://docs.sunc.su/Closures/newcclosure/>
- `loadstring`: <https://docs.sunc.su/Closures/loadstring/>
- `debug.getconstants`: <https://docs.sunc.su/Debug/getconstants/>
- `debug.getupvalues`: <https://docs.sunc.su/Debug/getupvalues/>
- `debug.setupvalue`: <https://docs.sunc.su/Debug/setupvalue/>
- `debug.getproto`: <https://docs.sunc.su/Debug/getproto/>
- `debug.getprotos`: <https://docs.sunc.su/Debug/getprotos/>
- Luau standard library (`debug.info`): <https://luau.org/library/#debug-library>
- Public executor API cross-check (Potassium debug API):
  <https://potassium.gitbook.io/api/environment/debug>

sUNC is preferred where old executor documentation conflicts with it because
sUNC explicitly tests whether functions work in realistic scenarios; old UNC
name-presence checks are described by sUNC as outdated and spoofable.

## Required consensus behaviors

| Area | Runtime requirement | Reason |
| --- | --- | --- |
| Executor globals | `getgenv()` repeatedly returns the same writable executor-global table, separate from the current thread global table; raw writes to one do not pollute the other. Both canary values are restored before rejection, including when the challenge raises midway. Executor APIs may be raw keys or may resolve through a protected environment `__index` path; their references and behavior must remain stable either way. | The sUNC `getgenv` contract explicitly distinguishes executor globals from thread globals and requires persistence, but does not require `getgenv` or the other APIs to be raw keys of `getfenv()`. |
| Identity | Two `identifyexecutor()` calls return the same non-empty name and string version. | sUNC specifies a `(string, string)` tuple. Values are stability inputs only; no name is allowed or denied. |
| Caller | `checkcaller()` returns `true` on the executor-created thread. | This is the documented executor-thread behavior. |
| Host | Roblox `game`, `Players`, `Instance`, `Vector3`, `typeof`, and `task` operations agree. | Separates a real Roblox host from ordinary Lua/Luau and simple API-only shims. |
| Closures | Native primitives and generated/loaded Luau functions are classified consistently by `iscclosure` and `islclosure`; `newcclosure` forwards a challenge and classifies as C. | Uses documented observable behavior instead of exact debug formatting. |
| Compilation | Valid source compiles and executes as Luau; invalid source returns `nil` plus a non-empty error string without `loadstring` itself throwing. | This is the explicit sUNC `loadstring` success/failure contract. |
| Constants/upvalues | `debug.getconstants` and `debug.getupvalues` must succeed on generated Luau probes and return tables. `debug.setupvalue` setup and restore calls must succeed, and the probe must end with its private value restored. The tables need not expose the randomized probe values, and the interim replacement need not be observable. C-closure mutation/data exposure remains rejected: a C-closure upvalue query may throw or return an empty table, but it may not expose values. | Preserves API availability, result shape, cleanup and the C-closure security boundary while avoiding false rejection from executor-specific visibility and mutation semantics. The final restoration check still protects payload state. |
| Prototypes | The generated local child must execute its randomized challenge and classify as Luau. Each available proto API must complete successfully; `getproto(..., true)` and `getprotos(...)` must return tables. C-closure proto access remains rejected. No returned inactive or activated item is invoked or required to expose a particular constant/result. | Retains the API surface, call/shape checks, active local-child behavior and C-closure isolation without treating executor-specific proto handle/result semantics as an authenticity boundary. |
| Integrity | Captured primitives, API references, guard seal, transcript, and attestation token remain stable at startup and later checkpoints. | Detects post-capture replacement and binds admission to the payload path. |

## Deliberately non-required details

| Detail | Policy |
| --- | --- |
| Executor brand or version text | Never allow-listed or deny-listed. |
| `getexecutorname` / `executorname` aliases | Not required. They are not part of the cited sUNC identity contract and alias equality is not an executor-authenticity property. |
| Exact `debug.info` source string such as `[C]` | Not required. Luau documents the returned source category but does not promise this exact spelling as an attestation boundary. Closure classifiers are used instead. |
| Random value visibility in probe constant/upvalue tables | Not required. Successful calls and table result shapes remain required. |
| Observable interim `setupvalue` replacement | Not required. Setup and restore calls must still succeed, and the final restored value must match. |
| Inactive or activated proto item behavior | Not gated. Returned items need not expose the generated child constant or execute its randomized result; only the retained proto calls/table shapes, active local child and C-closure isolation are required. |
| `debug.gethook` state | Neither required nor inspected. Hook occupancy is host-managed state and does not reliably prove that the payload was modified. |
| `newcclosure` timing, absolute yield duration, or exact error text | Not gated. These are scheduler/implementation-sensitive; the guard tests forwarding, classification, and protected C-closure introspection instead. |
| API name presence alone | Never sufficient. Each required surface participates in an observable challenge. |

## Diagnostic coverage

`tools/executor_sink_trigger_check.lua` non-short-circuit evaluates the 162
retained production conditions, prints only failures, then prints its dynamic
summary and overall conclusion. The following former root records are removed
from both the production challenge and the checker's transcript evidence:

- `constants.contains-random-value`
- `upvalues.contains-random-value`
- `upvalues.changed-value`
- `proto.getproto-inactive-contract`
- `proto.getproto-active-result`
- `proto.getprotos-inactive-contract`

The transcript, token, attested seal and state-transition checks remain. They now
depend on the retained API call/shape, setup/restore, local-child, isolation,
compilation and closure evidence rather than on those six removed roots.
