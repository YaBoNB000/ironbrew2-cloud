#!/usr/bin/env python3
"""Reject regression to the v4 outer-tag stream-seed inversion oracle."""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import verify_v4_payload as verifier_module
SERIALIZER = ROOT / "IronBrew2" / "Bytecode Library" / "Bytecode" / "Serializer.cs"
VM_STRINGS = ROOT / "IronBrew2" / "Obfuscator" / "VM Generation" / "VMStrings.cs"
DERIVATION = ROOT / "IronBrew2" / "Obfuscator" / "PayloadDerivationProfile.cs"
ANTI_DUMP = ROOT / "IronBrew2" / "Obfuscator" / "AntiDump" / "AntiDumpGenerator.cs"
VERIFIER = ROOT / "tests" / "verify_v4_payload.py"

serializer = SERIALIZER.read_text(encoding="utf-8-sig")
vm = VM_STRINGS.read_text(encoding="utf-8-sig")
derivation = DERIVATION.read_text(encoding="utf-8-sig")
anti_dump = ANTI_DUMP.read_text(encoding="utf-8-sig")
verifier = VERIFIER.read_text(encoding="utf-8-sig")

if "private const byte FormatVersion = 5;" not in serializer:
    raise SystemExit("protected payload format was not advanced to v5")

integrity_region_match = re.search(
    r"private\s+uint\s+ComputeIntegrity\s*\([^)]*\)\s*\{(?P<body>.*?)\n\s*\}\n\n\s*private",
    serializer,
    re.S,
)
if not integrity_region_match:
    raise SystemExit("could not isolate Serializer.ComputeIntegrity")
integrity_region = integrity_region_match.group("body")
legacy_csharp = re.compile(
    r"\(seed\s*\^\s*_context\.Domains\.IntegrityDomain\)\s*\*\s*31u\s*\+\s*flags"
)
if legacy_csharp.search(integrity_region):
    raise SystemExit("serializer restored the reversible v4 polynomial seed prefix")
if "hash = unchecked(hash * 31u + value)" in integrity_region:
    raise SystemExit("serializer restored the reversible v4 outer byte recurrence")
if "ComputeIntegrity(encrypted, _context.OuterIntegrityKey, flags)" not in serializer:
    raise SystemExit("serializer does not separate the outer-auth key from XorSeed")
if "DeriveBindingWords" not in derivation or "DeriveOuterIntegrityKey" not in derivation or "DerivePayloadBinding" not in derivation:
    raise SystemExit("outer-auth and payload keys do not use the four-word binding state")
if "__IB2_ATTESTATION_TOKEN__" in anti_dump or "GuardAttestation" in anti_dump:
    raise SystemExit("guard restored a shipped/final compatibility scalar")

if "PayloadVersion ~= 5" not in vm:
    raise SystemExit("generated runtime does not require the v5 payload")
if re.search(r"BitXOR\(Xs,\s*__IB2_DOMAIN_INTEGRITY__\)\s*\*\s*31", vm):
    raise SystemExit("generated runtime restored the reversible v4 outer seed prefix")
for required in (
    "PayloadRotate16",
    "PayloadAuthA = (BitXOR(Xi, __IB2_DOMAIN_INTEGRITY__)",
    "PayloadAuthB = (Xi + PayloadRotate16(__IB2_DOMAIN_INTEGRITY__)",
    "BitXOR(PayloadAuthA, PayloadRotate16(PayloadAuthB))",
):
    if required not in vm:
        raise SystemExit(f"generated runtime is missing v5 outer-auth component: {required}")

if "def recover_outer_seed" in verifier or "POLY31_INVERSE" in verifier:
    raise SystemExit("white-box verifier still contains the direct outer-tag seed inverse")
if "def outer_integrity" not in verifier or "def recover_attestation_binding" not in verifier:
    raise SystemExit("white-box verifier does not model the v5 binding/authenticator boundary")

# Stable arithmetic vectors catch accidental changes to Python's unsigned-word
# model. Serializer/runtime parity is then exercised by every generated-payload
# test in the full suite.
verifier_module.INTEGRITY_DOMAIN = 0x12345678
vectors = (
    (b"", 0x89ABCDEF, 0x5F, 0x072C8031),
    (bytes(range(32)), 0x10203040, 0x5E, 0xA2E06411),
    (b"IronBrew2-v5-outer-auth", 0xDEADBEEF, 0x5F, 0x153E20C2),
)
for data, integrity_key, flags, expected in vectors:
    actual = verifier_module.outer_integrity(data, integrity_key, flags)
    if actual != expected:
        raise SystemExit(
            f"v5 outer-auth vector mismatch: expected={expected:08x}, actual={actual:08x}"
        )

verifier_module.BINDER_INITIAL = 0x11223344
verifier_module.BINDER_FINAL_XOR = 0x55667788
verifier_module.BINDER_MULTIPLIER = 65521
verifier_module.BINDER_INCREMENT = 32749
if verifier_module.binder_seed(123456789, 987654321) != 0x9BDBA850:
    raise SystemExit("four-word environment stream-seed derivation vector changed")
if verifier_module.binder_integrity_key(123456789, 987654321) != 0x5D271662:
    raise SystemExit("four-word outer-integrity-key derivation vector changed")
if verifier_module.binder_payload_binding(123456789, 987654321) != 0x944CCFB5:
    raise SystemExit("four-word payload-state binding vector changed")

print("PASS v5 outer tag has no direct polynomial stream-seed inverse")
