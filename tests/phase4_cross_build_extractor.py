#!/usr/bin/env python3
"""Freeze Build A's extractor profile and score direct reuse on Builds B-E."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v4_payload as payload
from build_domains import extract_build_domains
from runtime_layout import derive_runtime_layout

MASK32 = 0xFFFFFFFF


def frozen_payload_recognized(source: str, domains, layout) -> tuple[bool, str]:
    """Apply only A's domains and grammar to a target's bytes.

    This intentionally does not call parse_and_verify(target), because that
    function derives the target's own Build-local model and would not represent
    reuse of an existing extractor.
    """
    try:
        payload.activate_domains(domains)
        _literals, raw = payload.extract_payload(source)
        values: dict[str, int] = {}
        offset = 0
        for field in layout.outer_order:
            width = 1 if field == "flags" else 4
            values[field] = payload.read_uint(raw, offset, width)
            offset += width
        if offset != 9:
            raise ValueError("outer-width")
        flags = values["flags"]
        if flags >> 4 != 4 or flags & 0x0F not in (14, 15):
            raise ValueError("version/features")
        encrypted = raw[offset:]
        seed = payload.recover_outer_seed(values["integrity"], flags, encrypted)
        integrity = payload.hash_bytes(((seed ^ payload.INTEGRITY_DOMAIN) * 31 + flags) & MASK32, encrypted)
        if seed == 0 or integrity != values["integrity"]:
            raise ValueError("outer-authentication")
        envelope = payload.payload_stream_xor(encrypted, seed)
        if len(envelope) < 32:
            raise ValueError("envelope-width")
        envelope_values = {
            field: payload.read_uint(envelope, slot * 4, 4)
            for slot, field in enumerate(layout.envelope_order)
        }
        record_count = envelope_values["record_count"]
        data_count = envelope_values["data_count"]
        entropy_count = envelope_values["entropy_count"]
        header_width = 1 + layout.record_ordinal_width + layout.record_length_width
        expected = 32 + record_count * header_width + envelope_values["real_length"] + envelope_values["entropy_length"]
        if record_count != data_count + entropy_count or expected != len(envelope):
            raise ValueError("envelope-framing")
        integrity_slot = layout.envelope_order.index("integrity") * 4
        authenticated = envelope[:integrity_slot] + envelope[integrity_slot + 4:]
        tag = payload.hash_bytes(((seed ^ payload.ENVELOPE_INTEGRITY_DOMAIN) * 31) & MASK32, authenticated)
        if tag != envelope_values["integrity"]:
            raise ValueError("envelope-authentication")
        return True, "authenticated"
    except (IndexError, KeyError, ValueError) as error:
        return False, str(error)


def role_placements(layout: dict[str, object]) -> dict[str, object]:
    placements: dict[str, object] = {}
    for family in ("chunk", "block", "flow", "flow_cache"):
        for semantic, physical in layout[family].items():
            placements[f"{family}:{semantic}"] = physical
    vm = layout["vm_layout"]
    for role, physical in vm["role_slots"].items():
        placements[f"vm:{role}"] = (physical["frame"], physical["slot"])
    for role in vm["direct_roles"]:
        placements[f"vm:{role}"] = "direct"
    return placements


def prototype_totals(root) -> tuple[int, int, int]:
    chunks = constants = instructions = 0
    stack = [root]
    while stack:
        current = stack.pop()
        chunks += 1
        constants += current.constant_count
        instructions += current.instruction_count
        stack.extend(current.children)
    return chunks, constants, instructions


def score(profile_source: str, profile_vm: str, target_payload: Path, target_vm: Path, baseline: bool = False):
    a_domains = extract_build_domains(profile_source)
    a_layout = payload.derive_payload_layout(a_domains)
    a_runtime = derive_runtime_layout(profile_vm)
    target_source = target_payload.read_text("latin1")
    target_runtime = derive_runtime_layout(target_vm.read_text("latin1"))
    target_info = payload.parse_and_verify(target_payload)
    totals = prototype_totals(target_info.root)

    recognized, reason = frozen_payload_recognized(target_source, a_domains, a_layout)
    a_roles = role_placements(a_runtime)
    target_roles = role_placements(target_runtime)
    common_roles = set(target_roles)
    vm_hits = sum(a_roles.get(role) == target_roles[role] for role in common_roles)
    vm_rate = vm_hits / len(common_roles)

    a_tokens = set(a_runtime["continuation"]["entry_tokens"])
    target_tokens = set(target_runtime["continuation"]["entry_tokens"])
    opcode_rate = len(a_tokens & target_tokens) / len(target_tokens)

    # Passing the complete frozen framing/authentication boundary is necessary
    # before any prototype, capsule or record can be attributed to this model.
    # A domain/layout equality check prevents a chance outer collision from
    # being counted as successful deep recovery.
    exact_payload_model = (
        recognized
        and asdict(a_domains) == asdict(target_info.domains)
        and a_layout == target_info.layout
    )
    deep_rate = 1.0 if exact_payload_model else 0.0
    rates = {
        "vm": vm_rate,
        "chunks": deep_rate,
        "opcodes": opcode_rate,
        "constants": deep_rate,
        "instructions": deep_rate,
    }
    if baseline and any(abs(value - 1.0) > 1e-12 for value in rates.values()):
        raise ValueError(f"Build A extractor does not recover its own Build: {rates}, reason={reason}")
    return rates, reason, totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile_payload", type=Path)
    parser.add_argument("profile_vm", type=Path)
    parser.add_argument("targets", nargs="+", help="payload.lua:vm.lua pairs for Builds B-E")
    args = parser.parse_args()
    if len(args.targets) != 4:
        raise SystemExit("exactly four Build B-E payload:VM pairs are required")
    pairs: list[tuple[Path, Path]] = []
    for value in args.targets:
        payload_name, separator, vm_name = value.partition(":")
        if not separator:
            raise SystemExit(f"invalid target pair: {value}")
        pairs.append((Path(payload_name), Path(vm_name)))

    try:
        profile_source = args.profile_payload.read_text("latin1")
        profile_vm = args.profile_vm.read_text("latin1")
        baseline_rates, baseline_reason, _ = score(
            profile_source, profile_vm, args.profile_payload, args.profile_vm, baseline=True
        )
        print("EXTRACTOR A->A " + " ".join(f"{name}={value:.3f}" for name, value in baseline_rates.items()))
        target_means: list[float] = []
        vm_rates: list[float] = []
        for index, (target_payload, target_vm) in enumerate(pairs, start=2):
            rates, reason, totals = score(profile_source, profile_vm, target_payload, target_vm)
            mean = sum(rates.values()) / len(rates)
            target_means.append(mean)
            vm_rates.append(rates["vm"])
            print(
                f"EXTRACTOR A->{chr(64 + index)} "
                + " ".join(f"{name}={value:.3f}" for name, value in rates.items())
                + f" mean={mean:.3f} target={totals[0]}chunks/{totals[1]}constants/{totals[2]}instructions"
                + f" frozen-payload={reason}"
            )
        if max(vm_rates) > 0.45:
            raise ValueError(f"Build A VM role model reused too reliably: {vm_rates}")
        if max(target_means) > 0.15 or sum(target_means) / len(target_means) > 0.08:
            raise ValueError(f"Build A extractor remained stable across Builds B-E: {target_means}")
        print(
            f"PASS Build-A frozen extractor instability across B-E: "
            f"max-VM={max(vm_rates):.3f}, max-mean={max(target_means):.3f}, "
            f"mean={sum(target_means)/len(target_means):.3f}"
        )
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
