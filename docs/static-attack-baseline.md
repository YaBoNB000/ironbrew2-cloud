# Final-output static attack baseline

Date: 2026-08-21

## Scope

The repository now keeps two attacker-side tools. Both accept only the final production Lua file; neither reads `temp/t2.lua`, generator logs, BuildSeed state, `luac.out`, compiler assemblies, or the original source.

- `tests/static_attack_baseline.py` restores the authenticated carrier, payload, prototypes, blocks, capsules, strings and canonical physical opcode IDs.
- `tests/static_decompiler.py` continues from that result and adapts to the public runtime implementation: it recovers the runtime ABI, evaluates the randomized opcode selector, follows continuation tokens, classifies terminal handlers, expands fused-member token machines, decodes operands and reconstructs selected register/table/call data flows.

This is intentional. Merely breaking an older parser is not counted as a protection milestone when an analyst can adapt it to formulas and handlers shipped in the same client file.

## Current baseline

The tracked `test.lua` is a small `pcall` fixture. A final-file-only run still recovers its carrier, constants, five logical instructions, CALL mode and real RETURN instructions:

```bash
python3 tests/static_attack_baseline.py test_obf.lua \
  --require-current-baseline \
  --report /tmp/static-attack-report.json

python3 tests/static_decompiler.py test_obf.lua \
  --report /tmp/static-decompiler-report.json
```

`tests/call_trampoline.lua` is the material decompiler fixture. It includes all 16 Lua 5.1 CALL B/C families, all three TAILCALL argument families, SELF, NEWTABLE/SETTABLE, embedded nils, discarded calls, true returns and this chain:

```text
HttpGet -> loadstring(source, chunkName) -> compiled chunk -> options call
```

A current randomized build is required to recover, from the final Lua alone:

- all call-chain strings;
- the SELF receiver and method target;
- exact fixed/no/single/Top argument-window classes;
- fixed/single/variable/discarded result classes;
- the second `loadstring` argument;
- `compiledChunk()` and the function it returns;
- options-table NEWTABLE plus its SETTABLE fields and boolean values;
- discarded calls as statements, separately from genuine RETURN instructions;
- every physical fused record's logical member count and token-defined semantic order.

A representative run recovered 333 logical instructions from roughly 270–305 physical records, classified over 300 logical instructions, expanded 24 fused programs, recovered 57 calls, two SELF instructions, six NEWTABLE instructions, eleven SETTABLE instructions, sixteen discarded calls and twenty-four true returns. Physical counts and classification totals vary because fusion, aliases, layouts and handlers are randomized.

Run it with:

```bash
python3 tests/static_decompiler.py /path/to/final-call-fixture.lua \
  --require-call-chain \
  --report /tmp/static-decompiler-call-report.json
```

## Adapted recovery stages

1. **Carrier and environment binding** — locates nested Base91 segments, derives the shipped attestation candidate, authenticates the entropy envelope and restores protected pages.
2. **Prototype/block parsing** — derives build-local schemas, validates manifests and restores shuffled instruction columns.
3. **Constants and operands** — replays cross-capsule chains, opens per-use handles, reassembles sharded strings and decodes masked A/B/C fields, including supplemental fusion members.
4. **Canonical opcode IDs** — derives prototype-local opcode banks and replays chained opcode state.
5. **Runtime ABI** — recovers Chunk/Block/Flow slots and the partitioned invocation-state carrier directly from the final minified runtime.
6. **Opcode selector** — parses and evaluates the randomized comparison tree for every canonical ID.
7. **Continuation graph** — follows each entry token through its 3–5 node lane/state path to the terminal handler.
8. **CALL trampoline** — expands the 19 mode-token paths and 92 phase tokens, then classifies argument and result tokens from the shared fragments.
9. **Fusion program** — finds each member-token state machine, follows token successors rather than physical branch order, and associates each recovered member with its supplemental descriptor/operands.
10. **Data-flow rendering** — tracks GETGLOBAL/LOADK/MOVE/CLOSURE, SELF, NEWTABLE/SETTABLE and CALL results sufficiently to render the loader chain and options table. CALL-discard and RETURN are counted separately.

The classifier intentionally reports unknown operations rather than inventing semantics. It currently focuses on the operations needed to measure loader/table/call-chain recovery; it is not a complete general-purpose Lua source regenerator.

## Interpretation

This remains an **expected successful attack baseline**, not a secrecy claim. Tokenized CALL phases, continuation graphs, fusion programs, per-use handles and shuffled runtime ABIs substantially increase the work needed by fixed-pattern tools. They do not create a server-held secret or cryptographic irreversibility.

A sufficiently capable analyst can still:

- evaluate every client-shipped token transition;
- classify shared fragments by data flow;
- simulate constant and operand materialization;
- hook the same runtime dynamically;
- reconstruct high-value call chains and table arguments.

CI runs both the structural baseline and the adapted decompiler so future changes cannot be credited merely because these attacker tools silently became stale.
