#!/usr/bin/env python3
"""Recover per-build serializer/runtime domains from generated Lua structure."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Dict

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
WS = r"\s*"


@dataclass(frozen=True)
class BuildDomains:
    integrity: int
    block_integrity: int
    flow: int
    envelope_integrity: int
    entropy_digest: int
    envelope_mask: int
    constant_integrity: int
    constant_mask: int
    prototype_integrity: int
    opcode_permutation: int
    schema_permutation: int
    constant_tag_permutation: int
    block_column: int
    flow_verifier_mask: int
    block_field_stride: int
    entropy_record_kind: int
    data_record_kind: int

    def as_dict(self) -> Dict[str, int]:
        return asdict(self)


def _one(source: str, pattern: str, label: str) -> int:
    values = {int(value) for value in re.findall(pattern, source, re.S)}
    if len(values) != 1:
        raise ValueError(f"could not uniquely recover {label}: {sorted(values)}")
    return values.pop()


def extract_build_domains(source: str) -> BuildDomains:
    ident = IDENT

    integrity = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*\*\s*31\s*\+\s*{ident}\s*\)\s*%\s*4294967296\s*;\s*"
        rf"for\s+{ident}\s*=\s*10\s*,\s*#{ident}",
        "payload integrity domain",
    )
    envelope_integrity = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*\*\s*31\s*\)\s*%\s*4294967296\s*;\s*for\s+{ident}\s*=\s*1\s*,\s*#{ident}\s+do\s*"
        rf"if\s+{ident}\s*<\s*29\s+or\s+{ident}\s*>\s*32",
        "envelope integrity domain",
    )
    # This pattern also captures the hash identifier for its back-reference, so recover
    # the numeric group explicitly while retaining the usual uniqueness invariant.
    entropy_matches = {
        int(match.group(2))
        for match in re.finditer(
            rf"local\s+({ident})\s*=\s*\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)\s*\*\s*31"
            rf"\s*\+\s*{ident}\s*\)\s*%\s*4294967296\s*;\s*\1\s*=\s*\(\s*\1\s*\*\s*31\s*\+\s*(?!#){ident}\s*\)",
            source,
            re.S,
        )
    }
    if len(entropy_matches) != 1:
        raise ValueError(f"could not uniquely recover entropy digest domain: {sorted(entropy_matches)}")
    entropy_digest = entropy_matches.pop()

    envelope_mask = _one(
        source,
        rf"local\s+{ident}\s*=\s*{ident}\(\s*{ident}\(\s*{ident}\(\s*{ident}\(\s*{ident}\s*,\s*{ident}\s*\)"
        rf"\s*,\s*{ident}\s*\)\s*,\s*(\d+)\s*\)\s*,\s*{ident}\s*\)\s*%\s*4294967296",
        "envelope mask domain",
    )
    flow = _one(
        source,
        rf"\+\s*{ident}\s*\*\s*17\s*\+\s*{ident}\s*\+\s*(\d+)\s*\+\s*{ident}\s*\)\s*%\s*4294967296"
        rf"\s*;\s*return\s*\(\s*{ident}\s*\*\s*1664525",
        "flow domain",
    )
    flow_verifier_mask = _one(
        source,
        rf"return\s+{ident}\(\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*\)\s*;",
        "flow verifier mask",
    )
    block_field_stride = _one(
        source,
        rf"return\s*\(\s*{ident}\s*\*\s*\(\s*\(\s*\(\s*{ident}\s*\+\s*{ident}\s*\*\s*29\s*\)"
        rf"\s*%\s*251\s*\)\s*\+\s*1\s*\)\s*\+\s*{ident}\s*\*\s*17.+?"
        rf"\+\s*{ident}\s*\*\s*(\d+)\s*\)\s*%\s*65536\s*;",
        "block field stride",
    )
    constant_mask = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\s*\*\s*65537\s*\+\s*{ident}\s*\*\s*257"
        rf"\s*\+\s*{ident}\s*\*\s*17\s*\+\s*{ident}\s*\+\s*(\d+)\s*\)\s*%\s*4294967296",
        "constant mask domain",
    )
    constant_integrity = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)\s*\*\s*31"
        rf"\s*\+\s*{ident}\s*\)\s*%\s*4294967296\s*;\s*{ident}\s*=\s*\(\s*{ident}\s*\*\s*31\s*\+\s*#{ident}",
        "constant integrity domain",
    )
    prototype_integrity = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)\s*\*\s*31"
        rf"\s*\+\s*#{ident}\s*\)\s*%\s*4294967296\s*;\s*for\s+{ident}\s*=\s*1\s*,\s*#{ident}",
        "prototype integrity domain",
    )
    block_integrity = _one(
        source,
        rf"local\s+{ident}\s*=\s*\(\s*{ident}\(\s*{ident}\(\s*{ident}\s*,\s*(\d+)\s*\)\s*,\s*{ident}\s*\)"
        rf"\s*\*\s*31\s*\+\s*{ident}\s*\)\s*%\s*4294967296",
        "block integrity domain",
    )

    opcode_permutation = _one(
        source,
        rf"local\s+{ident}\s*=\s*{ident}\(\s*\d+\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*;\s*{ident}\s*\[\s*\d+\s*\]\s*=\s*{ident}\s*;",
        "opcode permutation domain",
    )
    schema_permutation = _one(
        source,
        rf"local\s+{ident}\s*=\s*{ident}\(\s*5\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*;\s*for\s+{ident}\s*=\s*1\s*,\s*5\s+do",
        "schema permutation domain",
    )
    constant_tag_permutation = _one(
        source,
        rf"local\s+{ident}\s*=\s*{ident}\(\s*4\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*;\s*local\s+{ident}\s*=\s*\{{\s*\}}\s*;\s*for\s+{ident}\s*=\s*1\s*,\s*#{ident}",
        "constant-tag permutation domain",
    )
    block_column = _one(
        source,
        rf"local\s+{ident}\s*=\s*{ident}\(\s*5\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,\s*(\d+)\s*\)"
        rf"\s*;\s*local\s+{ident}\s*=\s*\{{\s*\}}",
        "block-column permutation domain",
    )

    record_candidates = {
        (int(match.group(1)), int(match.group(2)))
        for match in re.finditer(
            rf"{ident}\s*=\s*{ident}\s*\+\s*7\s*;(?:(?!elseif).){{1,700}}?"
            rf"if\s+{ident}\s*==\s*(\d+)\s+then\b(?:(?!elseif).){{1,900}}?"
            rf"elseif\s+{ident}\s*==\s*(\d+)\s+then\b",
            source,
            re.S,
        )
        if 1 <= int(match.group(1)) <= 255
        and 1 <= int(match.group(2)) <= 255
        and int(match.group(1)) != int(match.group(2))
    }
    if len(record_candidates) != 1:
        raise ValueError(f"could not uniquely recover envelope record kinds: {sorted(record_candidates)}")
    data_record_kind, entropy_record_kind = record_candidates.pop()

    values = BuildDomains(
        integrity=integrity,
        block_integrity=block_integrity,
        flow=flow,
        envelope_integrity=envelope_integrity,
        entropy_digest=entropy_digest,
        envelope_mask=envelope_mask,
        constant_integrity=constant_integrity,
        constant_mask=constant_mask,
        prototype_integrity=prototype_integrity,
        opcode_permutation=opcode_permutation,
        schema_permutation=schema_permutation,
        constant_tag_permutation=constant_tag_permutation,
        block_column=block_column,
        flow_verifier_mask=flow_verifier_mask,
        block_field_stride=block_field_stride,
        entropy_record_kind=entropy_record_kind,
        data_record_kind=data_record_kind,
    )

    uint_domains = [
        values.integrity,
        values.block_integrity,
        values.flow,
        values.envelope_integrity,
        values.entropy_digest,
        values.envelope_mask,
        values.constant_integrity,
        values.constant_mask,
        values.prototype_integrity,
        values.opcode_permutation,
        values.schema_permutation,
        values.constant_tag_permutation,
        values.block_column,
        values.block_field_stride,
    ]
    if any(value <= 0 or value > 0xFFFFFFFF for value in uint_domains):
        raise ValueError("recovered build domain is outside uint32/nonzero range")
    if len(set(uint_domains)) != len(uint_domains):
        raise ValueError("recovered build domains are not pairwise distinct")
    if values.flow_verifier_mask <= 0 or values.flow_verifier_mask > 0xFFFF:
        raise ValueError("flow verifier mask is outside nonzero uint16 range")
    legacy_effective = {113, 911, 1777, 3253, 0x5A5A}
    effective_words = [
        values.opcode_permutation & 0xFFFF,
        values.schema_permutation & 0xFFFF,
        values.constant_tag_permutation & 0xFFFF,
        values.block_column & 0xFFFF,
        values.block_field_stride & 0xFFFF,
        values.flow_verifier_mask,
    ]
    if 0 in effective_words or legacy_effective.intersection(effective_words):
        raise ValueError(f"recovered effective build word is zero or legacy: {effective_words}")
    if len(set(effective_words)) != len(effective_words):
        raise ValueError(f"recovered effective build words are not distinct: {effective_words}")
    if values.block_field_stride & 1 == 0:
        raise ValueError("block field stride is not odd")
    if values.entropy_record_kind == values.data_record_kind or not (
        1 <= values.entropy_record_kind <= 255 and 1 <= values.data_record_kind <= 255
    ):
        raise ValueError("recovered envelope record kinds are invalid")
    return values
