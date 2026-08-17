#!/usr/bin/env python3
"""Enforce that build randomization is rooted in purpose-separated BuildSeed streams."""

from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
CORE = [
    ROOT / "IronBrew2" / "Obfuscator" / "BuildDomains.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "ObfuscationContext.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "EnvBinder.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "AntiDump" / "AntiDumpGenerator.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "Encryption" / "ConstantEncryption.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "Opcodes" / "OpMutated.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "VM Generation" / "DispatcherTemplate.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "VM Generation" / "VMLayout.cs",
    ROOT / "IronBrew2" / "Obfuscator" / "VM Generation" / "Generator.cs",
    ROOT / "IronBrew2" / "Bytecode Library" / "Bytecode" / "Serializer.cs",
    *sorted((ROOT / "IronBrew2" / "Obfuscator" / "Control Flow").rglob("*.cs")),
]

for path in CORE:
    source = path.read_text(encoding="utf-8-sig")
    if re.search(r"\bRandomNumberGenerator\b|\bnew\s+Random\s*\(", source):
        raise SystemExit(f"process-global random source remains in build-randomized core: {path.relative_to(ROOT)}")
    if re.search(r"\.Shuffle\s*\(\s*\)", source):
        raise SystemExit(f"unscoped shuffle remains in build-randomized core: {path.relative_to(ROOT)}")

all_source = "\n".join(path.read_text(encoding="utf-8-sig") for path in CORE)
purposes = set(re.findall(r'GetStream\("([a-z0-9.-]+)"\)', all_source))
expected = {
    "bytecode.schema",
    "dispatcher.template",
    "environment.binding",
    "opcode.mutations",
    "payload.domains",
    "payload.outer-seed",
    "payload.serializer",
    "runtime.guard",
    "vm.generator",
    "vm.layout",
}
if purposes != expected:
    raise SystemExit(f"unexpected core BuildSeed purposes: recovered={sorted(purposes)}, expected={sorted(expected)}")

program = (ROOT / "IronBrew2" / "Program.cs").read_text(encoding="utf-8-sig")
program_purposes = set(re.findall(r'buildSeed\.GetStream\("([a-z0-9.-]+)"\)', program))
if program_purposes != {"constant-encryption", "control-flow"}:
    raise SystemExit(f"entry-point BuildSeed wiring is incomplete: {sorted(program_purposes)}")
if program.count("new BuildSeed()") != 1:
    raise SystemExit("CLI must create exactly one CSPRNG BuildSeed per obfuscation")
if "new ObfuscationContext(lChunk, settings, buildSeed)" not in program:
    raise SystemExit("ObfuscationContext does not receive the entry-point BuildSeed")

seed_source = (ROOT / "IronBrew2" / "Obfuscator" / "BuildSeed.cs").read_text(encoding="utf-8-sig")
if seed_source.count("RandomNumberGenerator.GetBytes(MasterSeedBytes)") != 1:
    raise SystemExit("BuildSeed does not have exactly one CSPRNG master-seed acquisition point")
if "HMACSHA256.HashData(_masterSeed, message)" not in seed_source:
    raise SystemExit("BuildSeed purpose derivation is not HMAC-separated")
if "CryptographicOperations.ZeroMemory(_masterSeed)" not in seed_source:
    raise SystemExit("BuildSeed master material is not cleared on disposal")

print(f"PASS unified BuildSeed wiring: {len(expected) + len(program_purposes)} purpose-separated streams")
