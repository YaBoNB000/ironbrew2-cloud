# Final-output static attack baseline

Date: 2026-08-20

## Scope

`tests/static_attack_baseline.py` is an attacker-side harness that accepts only the final production Lua file. It does not read `temp/t2.lua`, build logs, compiler state, `luac.out`, intermediate bytecode, or original source.

The harness mirrors formulas and format coordinates delivered in the wrapper. This is intentional: breaking an old parser is not a security milestone when an analyst can adapt it to the public runtime.

## Current tracked result

For the tracked `test.lua` (`local aop = 9`), a current build still yields a successful final-file-only recovery of:

- Base91 carrier topology and source order;
- environment-derived outer binding and authenticated envelope;
- complete prototype/block framing;
- the number constant `9`;
- physical canonical head-opcode IDs;
- IR-fusion supplemental-member counts and logical widths.

Exact entropy size, carrier segments, seeds, opcode IDs and hashes vary every build. `tests/semantic.lua` is the material fusion fixture: recent validation recovered roughly 140–145 physical records representing 224 logical instructions, with 25–26 fused records of widths 2–6. The exact values are randomized and are not fixed expectations.

Run the tracked baseline with:

```bash
python3 tests/static_attack_baseline.py test_obf.lua \
  --require-current-baseline \
  --report /tmp/static-attack-report.json
```

## Adapted recovery stages

1. **Carrier location** — identifies nested Base91 segments and restores authenticated source order.
2. **Environment binding** — derives the envelope stream state and independent outer-integrity key from shipped formulas.
3. **Payload restoration** — validates entropy/framing, reverses page transforms and inflates bounded pages.
4. **Prototype parsing** — derives build-local schema and validates prototype/block manifests.
5. **Constant recovery** — opens state-bound capsules, including constants referenced only by supplemental fused members.
6. **Opcode recovery** — derives each prototype opcode bank and chained opcode state to recover the canonical head-opcode ID of every physical record.
7. **Fusion recovery** — parses descriptor bit 6, supplemental member descriptors, physical/logical widths and fused constant references.

The harness stops before assigning Lua semantic names to every canonical handler or every member operation. The final wrapper still contains the randomized fusion handler and shared-fragment implementations, so a sufficiently capable static analyzer can continue with control/data-flow classification.

## Current interpretation

This remains an **expected successful attack baseline**, not a secrecy claim. The implemented defenses change exposure and classifier cost:

- constants are not decoded during record parsing or four replay stages; a capsule opens only when a handler indexes that operand;
- terminal handlers compose shared acquisition/operation/writeback/PC fragments instead of each carrying one complete repeated dataflow;
- safe IR sequences become one physical record with a combined descriptor and one cross-member register dataflow proxy instead of replaying serialized member PCs.

None of those creates a server-held secret. All formulas and handler code remain client-side, so full static simulation or runtime instrumentation remains possible.

CI uses `--require-current-baseline` to prevent the attack harness from silently becoming stale. Any future hardening change must first adapt this harness to the new public format, then measure whether recovery actually decreased.
