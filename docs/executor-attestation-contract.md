# Executor attestation behavior contract

Research date: 2026-08-16

The runtime guard is deliberately brand-neutral. It does not treat an executor
name, a claimed UNC/sUNC percentage, or the presence of global names as proof.
Admission requires a cross-API behavior transcript, and every failure normally
enters the same silent non-yielding fixed-memory sink.

> **Temporary diagnostic state:** `TemporaryGlobalSinkBypass` is currently
> enabled so the obfuscated sink checker can finish printing on a failing real
> executor. The existing checks are unchanged and the guard still latches its
> first failure, but the expected payload token is supplied and execution
> continues instead of entering the sink. This must be set back to `false` after
> the comparison.

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
| Constants/upvalues | Generated constants are discoverable, a deliberately mutable private upvalue can be changed and restored, and C-closure mutation/data exposure is rejected. A C-closure upvalue query may throw or return an empty table, but it may not expose values. | Preserves the positive Luau mutation challenge and the C-closure security boundary without treating error-vs-empty representation as executor identity. The probe mutates its upvalue in source so Luau optimization cannot fold it into a constant. |
| Prototypes | Retrieved proto handles may be functions or userdata. They must expose the generated child constant; an uncallable handle is accepted, while a callable handle must execute the exact randomized child result. `getproto(..., true)` must still return active Luau functions that execute correctly. | Callable-vs-uncallable is an executor implementation/compliance distinction, not reliable evidence that the host is or is not an executor. Cross-checking constants and the randomized result preserves behavioral attestation without using sUNC conformance as an authenticity oracle. |
| Integrity | Captured primitives, API references, guard seal, transcript, and attestation token remain stable at startup and later checkpoints. | Detects post-capture replacement and binds admission to the payload path. |

## Deliberately non-required details

| Detail | Policy |
| --- | --- |
| Executor brand or version text | Never allow-listed or deny-listed. |
| `getexecutorname` / `executorname` aliases | Not required. They are not part of the cited sUNC identity contract and alias equality is not an executor-authenticity property. |
| Exact `debug.info` source string such as `[C]` | Not required. Luau documents the returned source category but does not promise this exact spelling as an attestation boundary. Closure classifiers are used instead. |
| Callable inactive proto | Not used as an executor-authenticity rejection. Although sUNC treats callable inactive protos as non-compliant, a callable handle is admitted only when its inspected constant and randomized execution result both match the generated child. |
| `debug.gethook` state | Neither required nor inspected. Hook occupancy is host-managed state and does not reliably prove that the payload was modified. |
| `newcclosure` timing, absolute yield duration, or exact error text | Not gated. These are scheduler/implementation-sensitive; the guard tests forwarding, classification, and protected C-closure introspection instead. |
| API name presence alone | Never sufficient. Each required surface participates in an observable challenge. |
