# Final-output static attack baseline

Date: 2026-08-19

## Scope

`tests/static_attack_baseline.py` is the attacker-side counterpart to the white-box
payload verifier. It accepts only the final production Lua file. It does not read:

- `temp/t2.lua`;
- obfuscator logs;
- BuildSeed/compiler state;
- `luac.out` or intermediate bytecode;
- the original source file.

The harness mirrors formulas and format coordinates that are shipped in the final
wrapper. This is intentional: deleting an internal verifier does not prevent an
analyst or AI from rebuilding it from delivered runtime code.

## Current result for `test_obf.lua`

The current materializer build remains fully recoverable before handler semantic
classification:

```text
carrier segments:       13 (build-random)
encoded payload:        87,213 bytes (build-random)
plain protected body:   245 bytes
prototypes:             1
blocks:                 1
instructions:           4
constant capsules:      2
recovered strings:      "print", "idk"
canonical opcode IDs:   recovered for all 4 PCs
```

The exact carrier count, entropy size, seed, attestation value and opcode IDs vary
per build. The security-relevant baseline is that a final-file-only analyzer can
still recover all of them.

The attack harness has already been adapted to the first M2–M5 changes: nested
segment tables, 2 KiB decoded-ciphertext chunks, four prototype-local column
families and two-stage materializer replay. It still recovers the complete body,
constants and canonical opcode IDs. This prevents us from mistaking structural
novelty for a broken static recovery chain.

Run it with:

```bash
python3 tests/static_attack_baseline.py test_obf.lua \
  --expect-string print --expect-string idk \
  --require-current-baseline \
  --report /tmp/static-attack-report.json
```

## Recovery stages measured

1. **Carrier location** — identifies the final file's large Base91 segments and
   restores their authenticated source order.
2. **Environment binding** — recovers shipped attestation candidates, derives the
   envelope stream seed and independent outer-integrity key, then validates the
   randomized envelope header.
3. **Payload restoration** — decrypts records, validates entropy/framing, reverses
   the page pipeline and inflates bounded pages.
4. **Prototype parsing** — derives Build-local schema, verifies prototype/block
   manifests and reconstructs the prototype tree.
5. **Constant recovery** — opens state-bound constant capsules and records strings,
   numbers and booleans.
6. **Opcode recovery** — derives the prototype opcode bank and chained opcode state
   to recover canonical virtual opcode IDs for every serialized instruction.

The harness intentionally stops before assigning Lua semantic names to canonical
handler IDs. The final wrapper still contains handler implementations, so AI can
currently finish that mapping with def-use analysis.

## Milestone policy

This baseline is currently an **expected successful attack**, not a protection
claim. CI uses `--require-current-baseline` so the attack harness cannot silently
rot while defenses change.

Each hardening milestone must update the expected result deliberately:

| Milestone | Required attack regression |
|---|---|
| M1 multi-word guard/key state | no single attestation candidate yields every payload key |
| M2 streaming carrier/pages | no complete encoded/decrypted payload buffer is recoverable |
| M3 prototype-local decoder families | one recovered parser cannot decode all prototypes |
| M4 staged materialization | initial records do not expose final opcode/all operands |
| M5 handler semantic polymorphism | canonical IDs cannot be mapped by one stable handler classifier |

A milestone is not complete merely because this script breaks syntactically. The
replacement attack harness must first be adapted to the new public runtime; only
then is a reduced recovery result meaningful.
