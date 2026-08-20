#!/usr/bin/env python3
"""Verify and tamper-test IronBrew2's authenticated v5 payload format.

The filename is retained so existing CI/tooling imports keep working.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import math
from pathlib import Path
import re
import struct
import sys
import zlib

from build_domains import BuildDomains, extract_build_domains

MASK32 = 0xFFFFFFFF
MOD32 = 1 << 32
# Activated from each generated Lua file before its payload is parsed or rebuilt.
INTEGRITY_DOMAIN = 0
BLOCK_INTEGRITY_DOMAIN = 0
FLOW_DOMAIN = 0
CHUNK_STATE_DOMAIN = 0
PAYLOAD_ATTESTATION = 0
ENVELOPE_INTEGRITY_DOMAIN = 0
ENTROPY_DIGEST_DOMAIN = 0
ENVELOPE_MASK_DOMAIN = 0
CONSTANT_INTEGRITY_DOMAIN = 0
CONSTANT_MASK_DOMAIN = 0
PROTOTYPE_INTEGRITY_DOMAIN = 0
OPCODE_PERMUTATION_DOMAIN = 0
SCHEMA_DOMAIN = 0
CONSTANT_TAG_DOMAIN = 0
BLOCK_COLUMN_DOMAIN = 0
CODE_DATA_PERMUTATION_DOMAIN = 0
INSTRUCTION_STATE_DOMAIN = 0
OPCODE_STATE_DOMAIN = 0
PAYLOAD_FORMAT_DOMAIN = 0
DECODE_PIPELINE_DOMAIN = 0
FLOW_VERIFIER_MASK = 0
BLOCK_FIELD_STRIDE = 0
ENTROPY_KIND = 0
DATA_KIND = 0
ENTROPY_MIN = 64 * 1024
ENTROPY_MAX = 96 * 1024
LCG_MULTIPLIER = 1664525
LCG_INCREMENT = 1013904223
LCG_INVERSE = pow(LCG_MULTIPLIER, -1, MOD32)
STREAM_MULTIPLIER = 0
STREAM_INCREMENT = 0
BINDER_MULTIPLIER = 0
BINDER_INCREMENT = 0
BINDER_INITIAL = 0
BINDER_FINAL_XOR = 0


def activate_domains(domains: BuildDomains) -> None:
    global INTEGRITY_DOMAIN, BLOCK_INTEGRITY_DOMAIN, FLOW_DOMAIN, CHUNK_STATE_DOMAIN
    global ENVELOPE_INTEGRITY_DOMAIN, ENTROPY_DIGEST_DOMAIN, ENVELOPE_MASK_DOMAIN
    global CONSTANT_INTEGRITY_DOMAIN, CONSTANT_MASK_DOMAIN, PROTOTYPE_INTEGRITY_DOMAIN
    global OPCODE_PERMUTATION_DOMAIN, SCHEMA_DOMAIN, CONSTANT_TAG_DOMAIN, BLOCK_COLUMN_DOMAIN
    global CODE_DATA_PERMUTATION_DOMAIN, INSTRUCTION_STATE_DOMAIN, OPCODE_STATE_DOMAIN
    global PAYLOAD_FORMAT_DOMAIN, DECODE_PIPELINE_DOMAIN
    global FLOW_VERIFIER_MASK, BLOCK_FIELD_STRIDE, ENTROPY_KIND, DATA_KIND
    global STREAM_MULTIPLIER, STREAM_INCREMENT
    global BINDER_MULTIPLIER, BINDER_INCREMENT, BINDER_INITIAL, BINDER_FINAL_XOR
    INTEGRITY_DOMAIN = domains.integrity
    BLOCK_INTEGRITY_DOMAIN = domains.block_integrity
    FLOW_DOMAIN = domains.flow
    CHUNK_STATE_DOMAIN = domains.chunk_state
    ENVELOPE_INTEGRITY_DOMAIN = domains.envelope_integrity
    ENTROPY_DIGEST_DOMAIN = domains.entropy_digest
    ENVELOPE_MASK_DOMAIN = domains.envelope_mask
    CONSTANT_INTEGRITY_DOMAIN = domains.constant_integrity
    CONSTANT_MASK_DOMAIN = domains.constant_mask
    PROTOTYPE_INTEGRITY_DOMAIN = domains.prototype_integrity
    OPCODE_PERMUTATION_DOMAIN = domains.opcode_permutation
    SCHEMA_DOMAIN = domains.schema_permutation
    CONSTANT_TAG_DOMAIN = domains.constant_tag_permutation
    BLOCK_COLUMN_DOMAIN = domains.block_column
    CODE_DATA_PERMUTATION_DOMAIN = domains.code_data_permutation
    INSTRUCTION_STATE_DOMAIN = domains.instruction_state
    OPCODE_STATE_DOMAIN = domains.opcode_state
    PAYLOAD_FORMAT_DOMAIN = domains.payload_format
    DECODE_PIPELINE_DOMAIN = domains.decode_pipeline
    FLOW_VERIFIER_MASK = domains.flow_verifier_mask
    BLOCK_FIELD_STRIDE = domains.block_field_stride
    ENTROPY_KIND = domains.entropy_record_kind
    DATA_KIND = domains.data_record_kind
    BINDER_MULTIPLIER = ((domains.flow ^ domains.payload_format) & 0xFFFF) | 1
    if BINDER_MULTIPLIER == 1:
        BINDER_MULTIPLIER = 3
    BINDER_INCREMENT = ((domains.chunk_state ^ domains.decode_pipeline) & 0xFFFF) | 1
    BINDER_INITIAL = domains.envelope_mask ^ domains.prototype_integrity
    BINDER_FINAL_XOR = domains.integrity ^ domains.block_integrity
    stream_seed = (domains.envelope_mask ^ domains.decode_pipeline) % 1048572
    STREAM_MULTIPLIER = (stream_seed & 0xFFFFFC) + 5
    STREAM_INCREMENT = ((domains.entropy_digest ^ domains.payload_format) & 0x3FFFFFFF) | 1


@dataclass(frozen=True)
class Literal:
    content_start: int
    content_end: int
    content: str


@dataclass(frozen=True)
class PayloadLayout:
    outer_order: tuple[str, ...]
    envelope_order: tuple[str, ...]
    record_order: tuple[str, ...]
    record_ordinal_width: int
    record_length_width: int
    page_length_width: int
    page_length_suffix: bool
    pipeline_variant: int
    byte_transform_variant: int
    byte_transform_parameter: int


@dataclass(frozen=True)
class Record:
    start: int
    end: int
    kind: int
    ordinal: int
    data: bytes
    data_offset: int


@dataclass
class Capsule:
    index: int
    start: int
    end: int
    tag_offset: int
    encoded_start: int
    block_start: int
    entry_state: int
    chunk_state: int
    logical_slot: int
    chain_state: int = 0


@dataclass
class Block:
    start_pc: int
    count: int
    route_token: int
    references: list[int]
    verifier: int
    tag: int
    tag_offset: int
    successors: list[tuple[int, int, int]]
    successor_offsets: list[int]
    body_start: int
    body_end: int
    entry_state: int
    fragment_order: list[int] = field(default_factory=list)
    fragment_spans: dict[int, tuple[int, int, int]] = field(default_factory=dict)
    record_column_orders: list[tuple[int, ...]] = field(default_factory=list)
    record_column_spans: list[dict[int, tuple[int, int, int]]] = field(default_factory=list)
    descriptors: list[int] = field(default_factory=list)
    fused_counts: list[int] = field(default_factory=list)
    capsules: dict[int, Capsule] = field(default_factory=dict)
    final_instruction_state: int = 0
    final_instruction_seal: int = 0


@dataclass
class Prototype:
    start: int
    end: int
    k1: int
    k2: int
    k3: int
    tag_offset: int
    binding: int
    parameter_offset: int | None = None
    instruction_count: int = 0
    constant_count: int = 0
    initial_wrapped_state: int = 0
    initial_wrapped_chunk_state: int = 0
    initial_wrapped_chunk_offset: int = 0
    initial_route: int = 0
    capsules: list[Capsule] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    children: list["Prototype"] = field(default_factory=list)


@dataclass
class PayloadInfo:
    path: Path
    source: str
    domains: BuildDomains
    layout: PayloadLayout
    literals: list[Literal]
    payload: bytes
    head: int
    seed: int
    attestation_token: int
    flags: int
    envelope: bytes
    records: list[Record]
    entropy: bytes
    protected_body: bytes
    body: bytes
    root: Prototype
    entropy_length: int
    entropy_digest: int
    nonce: int
    data_count: int
    entropy_count: int
    page_lengths: list[int]
    shannon_entropy: float


class Cursor:
    def __init__(self, data: bytes, position: int, end: int):
        self.data = data
        self.position = position
        self.end = end

    def take(self, length: int) -> bytes:
        if length < 0 or self.position + length > self.end:
            raise ValueError("truncated prototype framing")
        start = self.position
        self.position += length
        return self.data[start:self.position]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]


def decode_base91(data: str) -> bytes:
    output = bytearray()
    value = -1
    accumulator = 0
    bits = 0
    for character in data:
        code = ord(character)
        digit = code - 33
        if code > 39:
            digit -= 1
        if code > 92:
            digit -= 1
        if not 0 <= digit <= 90:
            continue
        if value < 0:
            value = digit
            continue
        value += digit * 91
        accumulator += value << bits
        bits += 13 if value % 8192 > 88 else 14
        while bits >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
        value = -1
    if value >= 0:
        accumulator += value << bits
        bits += 7
        while bits >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
    return bytes(output)


def base91_character(value: int) -> str:
    code = value + 33
    if code >= 39:
        code += 1
    if code >= 92:
        code += 1
    return chr(code)


def encode_base91(data: bytes) -> str:
    output: list[str] = []
    accumulator = 0
    bits = 0
    for value in data:
        accumulator |= value << bits
        bits += 8
        if bits > 13:
            encoded = accumulator & 8191
            if encoded > 88:
                accumulator >>= 13
                bits -= 13
            else:
                encoded = accumulator & 16383
                accumulator >>= 14
                bits -= 14
            output.append(base91_character(encoded % 91))
            output.append(base91_character(encoded // 91))
    if bits:
        output.append(base91_character(accumulator % 91))
        if bits > 7 or accumulator > 90:
            output.append(base91_character(accumulator // 91))
    return "".join(output)


def scan_string_literals(source: str) -> list[Literal]:
    literals: list[Literal] = []
    index = 0
    while index < len(source):
        if source[index] not in "'\"":
            index += 1
            continue
        quote = source[index]
        content_start = index + 1
        index += 1
        while index < len(source):
            if source[index] == "\\":
                index += 2
                continue
            if source[index] == quote:
                literals.append(Literal(content_start, index, source[content_start:index]))
                index += 1
                break
            index += 1
    return literals


def is_base91_literal(value: str) -> bool:
    return bool(value) and all(33 <= ord(char) <= 126 and char not in "'\\" for char in value)


def extract_payload(source: str) -> tuple[list[Literal], bytes]:
    # Carrier assignments are injected into five guard stages as contiguous
    # logical runs. Their tables, nested tables and writer closures randomize
    # physical placement while source order remains the authenticated order
    # needed by this mutation harness.
    candidates = [
        literal
        for literal in scan_string_literals(source)
        if len(literal.content) >= 1024 and is_base91_literal(literal.content)
    ]
    candidates.sort(key=lambda item: item.content_start)
    if not 7 <= len(candidates) <= 14:
        raise ValueError(f"expected 7–14 large base91 payload segments, found {len(candidates)}")
    payload = decode_base91("".join(item.content for item in candidates))
    if len(payload) < 9:
        raise ValueError("decoded payload is shorter than the fixed v5 header")
    return candidates, payload


def _permute_layout(values: list[str], seed: int, salt: int) -> tuple[str, ...]:
    result = values[:]
    state = (seed ^ salt) & MASK32
    for size in range(len(result), 1, -1):
        state = (state * LCG_MULTIPLIER + LCG_INCREMENT + size * salt) & MASK32
        swap = state % size
        result[size - 1], result[swap] = result[swap], result[size - 1]
    return tuple(result)


def derive_payload_layout(domains: BuildDomains) -> PayloadLayout:
    domain = domains.payload_format
    return PayloadLayout(
        outer_order=_permute_layout(["head", "integrity", "flags"], domain, 0x13579BDF),
        envelope_order=_permute_layout(
            ["real_length", "entropy_length", "record_count", "data_count", "entropy_count", "nonce", "entropy_digest", "integrity"],
            domain,
            0x2468ACE1,
        ),
        record_order=_permute_layout(["kind", "ordinal", "length"], domain, 0x9E3779B9),
        record_ordinal_width=2 if ((domain >> 3) & 1) == 0 else 4,
        record_length_width=3 if ((domain >> 7) & 1) == 0 else 4,
        page_length_width=2 if ((domain >> 11) & 1) == 0 else 4,
        page_length_suffix=((domain >> 15) & 1) != 0,
        pipeline_variant=domains.decode_pipeline % 3,
        byte_transform_variant=(domains.decode_pipeline >> 8) % 4,
        byte_transform_parameter=(
            ((domains.decode_pipeline >> 18) % 7) + 1
            if ((domains.decode_pipeline >> 8) % 4) == 3
            else ((domains.decode_pipeline >> 16) ^ domains.payload_format) & 0xFF
        ),
    )


def read_uint(data: bytes, offset: int, width: int) -> int:
    if offset < 0 or offset + width > len(data):
        raise ValueError("truncated polymorphic payload field")
    return int.from_bytes(data[offset:offset + width], "little")


def append_uint(output: bytearray, value: int, width: int) -> None:
    output.extend((value & ((1 << (width * 8)) - 1)).to_bytes(width, "little"))


def hash_word(initial: int, value: int) -> int:
    return (initial * 31 + value) & MASK32


def hash_bytes(initial: int, data: bytes) -> int:
    value = initial & MASK32
    for item in data:
        value = hash_word(value, item)
    return value


def stream_xor(data: bytes, seed: int) -> bytes:
    output = bytearray(len(data))
    state = seed & MASK32
    for index, value in enumerate(data):
        output[index] = value ^ (state >> 24)
        state = (state * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32
    return bytes(output)


def payload_stream_xor(data: bytes, seed: int) -> bytes:
    output = bytearray(len(data))
    state = seed & MASK32
    for index, value in enumerate(data):
        output[index] = value ^ (state >> 24)
        state = (state * STREAM_MULTIPLIER + STREAM_INCREMENT) & MASK32
    return bytes(output)


def rotate16(value: int) -> int:
    value &= MASK32
    return ((value << 16) | (value >> 16)) & MASK32


def outer_integrity(encrypted: bytes, integrity_key: int, flags: int) -> int:
    """Mirror v5's two-lane outer authenticator.

    Unlike v4's polynomial, the public tag is a compression of two coupled
    states and cannot be walked backwards byte-by-byte to recover a key. The
    authenticator key is also derived separately from the envelope stream seed.
    Both remain client-side state; this helper deliberately does not claim
    server-backed authenticity.
    """
    left = ((integrity_key ^ INTEGRITY_DOMAIN) + 0xA5C3F1E7 + flags * 257) & MASK32
    right = (integrity_key + rotate16(INTEGRITY_DOMAIN) + 0x7F4A7C15 + len(encrypted) * 17) & MASK32
    for index, value in enumerate(encrypted, start=1):
        mixed_byte = (value + index * 257 + flags * 17) & MASK32
        left = ((left ^ mixed_byte) * 65599 + 0x9E3779B9) & MASK32
        right = ((right + mixed_byte + (left >> 16)) * 48271 + 0x6D2B79F5) & MASK32
        left = (left ^ rotate16(right)) & MASK32
    left = ((left ^ right ^ len(encrypted)) * 65599 + INTEGRITY_DOMAIN) & MASK32
    right = ((right ^ rotate16(left) ^ flags) * 48271 + 0xC4D29A6B) & MASK32
    return (left ^ rotate16(right)) & MASK32


def evidence_words(attestation: int) -> tuple[int, int, int, int]:
    return (
        (attestation * 65599 + 0x9E3779B9) & MASK32,
        (attestation * 48271 + 0x6D2B79F5) & MASK32,
        ((attestation + 0xA5C3F1E7) * 131071 + 0x7F4A7C15) & MASK32,
        ((attestation + 0xC4D29A6B) * 524287 + 0xC2B2AE35) & MASK32,
    )


def binder_words(head: int, attestation: int) -> tuple[int, int, int, int]:
    evidence = evidence_words(attestation)
    words = [
        BINDER_INITIAL ^ evidence[0],
        BINDER_INITIAL ^ 0xA5C3F1E7 ^ evidence[1],
        BINDER_FINAL_XOR ^ 0x6D2B79F5 ^ evidence[2],
        head ^ evidence[3] ^ 0x9E3779B9,
    ]
    transcript = f"{head}|{'|'.join(map(str, evidence))}"
    for index, item in enumerate(transcript.encode("ascii"), start=1):
        words[0] = (words[0] * BINDER_MULTIPLIER + item + BINDER_INCREMENT) & MASK32
        words[1] = (
            words[1] * (BINDER_MULTIPLIER + 2)
            + item + BINDER_INCREMENT + index * 17
        ) & MASK32
        words[2] = (words[2] * 65599 + item + (words[0] >> 16)) & MASK32
        words[3] = (words[3] * 48271 + item + (words[1] & 0xFFFF) + index) & MASK32
    return tuple(words)


def binder_seed(head: int, attestation: int) -> int:
    a, b, c, d = binder_words(head, attestation)
    return a ^ rotate16(b) ^ c ^ d ^ BINDER_FINAL_XOR


def binder_payload_binding(head: int, attestation: int) -> int:
    a, b, c, d = binder_words(head, attestation)
    return ((a ^ b) + (c ^ d) + 0xC2B2AE35) & MASK32


def binder_integrity_key(head: int, attestation: int) -> int:
    _a, b, c, d = binder_words(head, attestation)
    result = b ^ rotate16(c) ^ d ^ BINDER_FINAL_XOR ^ 0xC4D29A6B
    return 0xC4D29A6B if result == 0 else result


def _attestation_candidates(source: str) -> set[int]:
    # The strict guard still ships client-side evidence. The white-box verifier
    # may evaluate raw uint literals and generated arithmetic spellings, but it
    # must no longer obtain the stream seed by reversing the outer tag.
    candidates = {
        int(value)
        for value in re.findall(r"(?<![\w.])(\d+)(?![\w.])", source)
    }
    for left, operator, right in re.findall(r"\(\s*(\d+)\s*([+\-*])\s*(\d+)\s*\)", source):
        lhs, rhs = int(left), int(right)
        candidates.add(lhs + rhs if operator == "+" else lhs - rhs if operator == "-" else lhs * rhs)

    # The production guard no longer ships or compares the final token literal.
    # It restores the compatibility scalar as transcript + a Build-local offset;
    # combine that public offset with numeric transcript candidates before the
    # envelope/framing oracle filters them.
    ident = r"[A-Za-z_]\w*"
    offsets = {
        int(value)
        for value in re.findall(
            rf"if\s+not\s+{ident}\s+then\s+(?:local\s+)?{ident}\s*=\s*\(\s*{ident}\s*\+\s*(\d+)\s*\)"
            rf"\s*%\s*4294967296\s*;",
            source,
            re.S,
        )
    }
    # Minification/control-flow rewriting can separate the surrounding `if not`
    # anchor. The compatibility scalar remains uniquely tied to its first evidence
    # lane, so recover the same public offset from that local def-use shape.
    for _compatibility_name, value in re.findall(
        rf"local\s+({ident})\s*=\s*\(\s*{ident}\s*\+\s*(\d+)\s*\)\s*%\s*4294967296\s*;"
        rf"\s*{ident}\s*=\s*\(\s*\1\s*\*\s*65599\s*\+\s*2654435769\s*\)",
        source,
        re.S,
    ):
        offsets.add(int(value))
    base_candidates = list(candidates)
    for offset in offsets:
        candidates.update((candidate + offset) & MASK32 for candidate in base_candidates)
    return {candidate for candidate in candidates if 0 < candidate <= MASK32}


def recover_attestation_binding(
    source: str,
    head: int,
    flags: int,
    encrypted: bytes,
    stored_integrity: int,
    layout: PayloadLayout,
) -> tuple[list[int], int, int]:
    """Recover candidate shipped attestation values without a tag inverse.

    Candidate seeds first have to decrypt a structurally valid randomized
    envelope header; only the surviving candidate is checked against the v5
    authenticator. This keeps the white-box mutation harness functional while
    making any remaining client-side recoverability explicit and separate from
    the removed O(n) outer-seed oracle.
    """
    if len(encrypted) < 32:
        raise ValueError("encrypted entropy envelope is shorter than its header")
    record_header_width = 1 + layout.record_ordinal_width + layout.record_length_width
    matches: list[tuple[int, int, int]] = []
    for candidate in _attestation_candidates(source):
        seed = binder_seed(head, candidate)
        integrity_key = binder_integrity_key(head, candidate)
        if seed == 0 or integrity_key == 0:
            continue
        prefix = payload_stream_xor(encrypted[:32], seed)
        values = {
            field_name: read_uint(prefix, slot * 4, 4)
            for slot, field_name in enumerate(layout.envelope_order)
        }
        record_count = values["record_count"]
        data_count = values["data_count"]
        entropy_count = values["entropy_count"]
        expected = 32 + record_count * record_header_width + values["real_length"] + values["entropy_length"]
        if not ENTROPY_MIN <= values["entropy_length"] <= ENTROPY_MAX:
            continue
        if not (1 <= data_count <= 65535 and 8 <= entropy_count <= 64):
            continue
        if record_count != data_count + entropy_count or values["nonce"] == 0 or expected != len(encrypted):
            continue
        if outer_integrity(encrypted, integrity_key, flags) == stored_integrity:
            matches.append((candidate, seed, integrity_key))
    if not matches:
        raise ValueError("could not recover any shipped environment-binding candidate")
    key_pairs = {(seed, integrity_key) for _candidate, seed, integrity_key in matches}
    if len(key_pairs) != 1:
        raise ValueError(f"environment-binding candidates disagree on payload keys: {matches}")
    seed, integrity_key = key_pairs.pop()
    return [candidate for candidate, _seed, _key in matches], seed, integrity_key


def shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def derive_permutation(count: int, k1: int, k2: int, k3: int, domain: int) -> list[int]:
    values = list(range(count))
    state = (k1 * 251 + k2 * 17 + k3 + domain) & 0xFFFF
    for size in range(count, 1, -1):
        state = (state * 251 + k3 + size * k1 + k2 + domain) & 0xFFFF
        target = state % size
        values[size - 1], values[target] = values[target], values[size - 1]
    return values


def derive_block_permutation(
    count: int, entry_state: int, k1: int, k2: int, k3: int, domain: int
) -> list[int]:
    """Mirror the serializer/runtime's block-local physical-to-logical page map."""
    values = list(range(count))
    low = entry_state & 0xFFFF
    high = entry_state >> 16
    state = (low * 251 + high * 17 + k1 * 13 + k2 * 7 + k3 + domain) & 0xFFFF
    for size in range(count, 1, -1):
        state = (state * 251 + k3 + size * (k1 + low) + k2 + high + domain) & 0xFFFF
        target = state % size
        values[size - 1], values[target] = values[target], values[size - 1]
    if values == list(range(count)) and count > 1:
        values[0], values[1] = values[1], values[0]
    return values


def derive_code_data_permutation(
    instruction_count: int, constant_count: int, state_value: int, prototype: Prototype
) -> list[int]:
    values = derive_block_permutation(
        instruction_count + constant_count, state_value,
        prototype.k1, prototype.k2, prototype.k3, CODE_DATA_PERMUTATION_DOMAIN
    )
    if not instruction_count or not constant_count or len(values) <= 2:
        return values

    previous_data = values[0] >= instruction_count
    transitions = 0
    first_boundary = 0
    for position in range(1, len(values)):
        current_data = values[position] >= instruction_count
        if current_data != previous_data:
            transitions += 1
            if not first_boundary:
                first_boundary = position
        previous_data = current_data
    if transitions < 2:
        values[first_boundary - 1], values[first_boundary] = (
            values[first_boundary], values[first_boundary - 1]
        )
    return values


def block_field_mask(entry_state: int, pc: int, slot: int, prototype: Prototype) -> int:
    low = entry_state & 0xFFFF
    high = entry_state >> 16
    return (
        low * ((pc + slot * 29) % 251 + 1)
        + high * 17
        + prototype.k1 * 13
        + prototype.k2 * 7
        + prototype.k3
        + slot * BLOCK_FIELD_STRIDE
    ) & 0xFFFF


def prototype_decoder_mode(prototype: Prototype) -> int:
    return (
        prototype.k1 * 13
        + prototype.k2 * 7
        + prototype.k3 * 11
        + DECODE_PIPELINE_DOMAIN
    ) % 4


def _column_mask(
    prototype: Prototype, block: Block, role: int, pc: int, index: int
) -> int:
    low, high = block.entry_state & 0xFFFF, block.entry_state >> 16
    return (
        low
        + high * 3
        + prototype.k1 * 5
        + prototype.k2 * 7
        + prototype.k3 * 11
        + pc * 13
        + role * 17
        + index * 29
        + DECODE_PIPELINE_DOMAIN
    ) & 0xFF


def encode_prototype_column(
    column: bytes, prototype: Prototype, block: Block, role: int, pc: int
) -> bytes:
    mode = prototype_decoder_mode(prototype)
    output = bytearray(len(column))
    for index, value in enumerate(column):
        mask = _column_mask(prototype, block, role, pc, index)
        if mode == 0:
            encoded = value ^ mask
        elif mode == 1:
            encoded = (value + mask) & 0xFF
        elif mode == 2:
            encoded = (((value << 4) | (value >> 4)) & 0xFF) ^ mask
        else:
            shift = ((role + pc + index) % 7) + 1
            encoded = (((value << shift) | (value >> (8 - shift))) + mask) & 0xFF
        destination = len(column) - index - 1 if mode in (1, 3) else index
        output[destination] = encoded
    return bytes(output)


def decode_prototype_column(
    column: bytes, prototype: Prototype, block: Block, role: int, pc: int
) -> bytes:
    mode = prototype_decoder_mode(prototype)
    output = bytearray(len(column))
    for encoded_index, encoded in enumerate(column):
        index = len(column) - encoded_index - 1 if mode in (1, 3) else encoded_index
        mask = _column_mask(prototype, block, role, pc, index)
        if mode == 0:
            value = encoded ^ mask
        elif mode == 1:
            value = (encoded - mask) & 0xFF
        elif mode == 2:
            value = encoded ^ mask
            value = ((value << 4) | (value >> 4)) & 0xFF
        else:
            value = (encoded - mask) & 0xFF
            shift = ((role + pc + index) % 7) + 1
            value = ((value >> shift) | (value << (8 - shift))) & 0xFF
        output[index] = value
    return bytes(output)


def validate_instruction_record(
    record: bytes, prototype: Prototype, block: Block, offset: int,
    record_start: int, record_end: int,
) -> tuple[int, int, tuple[int, ...], dict[int, tuple[int, int, int]]]:
    order = derive_block_permutation(
        5, block.entry_state, prototype.k1, prototype.k2, prototype.k3, BLOCK_COLUMN_DOMAIN
    )
    if sorted(order) != list(range(5)) or order == list(range(5)):
        raise ValueError("invalid or identity instruction-column role permutation")
    cursor = Cursor(record, 0, len(record))
    columns: dict[int, bytes] = {}
    spans: dict[int, tuple[int, int, int]] = {}
    for role in order:
        frame_start = cursor.position
        length = cursor.u32()
        data_start = cursor.position
        columns[role] = cursor.take(length)
        spans[role] = (record_start + frame_start, record_start + data_start, record_start + cursor.position)
    if cursor.position != len(record) or set(columns) != set(range(5)):
        raise ValueError("instruction record columns were not consumed exactly")
    pc = block.start_pc + offset
    columns = {
        role: decode_prototype_column(value, prototype, block, role, pc)
        for role, value in columns.items()
    }
    if not columns[0]:
        raise ValueError("instruction descriptor page is empty")
    descriptor = columns[0][0] ^ (block_field_mask(block.entry_state, pc, 7, prototype) & 0xFF)
    fused_count = 0
    if descriptor & 1:
        if descriptor != 1 or len(columns[0]) != 1:
            raise ValueError("invalid data-word instruction descriptor")
        expected = {0: 1, 1: 0, 2: 0, 3: 4, 4: 0}
    else:
        if descriptor >= 128:
            raise ValueError("invalid high bits in instruction descriptor")
        fused = descriptor >= 64
        base_descriptor = descriptor - 64 if fused else descriptor
        instruction_type = (base_descriptor >> 1) & 3
        expected = {
            0: 1, 1: 2, 2: 2,
            3: 2 if instruction_type == 0 else 4,
            4: 2 if instruction_type in (0, 3) else 0,
        }
        if fused:
            if len(columns[0]) < 3:
                raise ValueError("IR fusion descriptor is incomplete")
            fused_count = columns[0][1]
            if fused_count < 1 or fused_count > 5 or len(columns[0]) != fused_count + 2:
                raise ValueError("IR fusion member count/framing mismatch")
            expected[0] += fused_count + 1
            for member_descriptor in columns[0][2:]:
                if member_descriptor >= 64 or member_descriptor & 1:
                    raise ValueError("invalid IR fusion member descriptor")
                member_type = (member_descriptor >> 1) & 3
                expected[2] += 2
                expected[3] += 2 if member_type == 0 else 4
                expected[4] += 2 if member_type in (0, 3) else 0
    actual = {role: len(value) for role, value in columns.items()}
    if actual != expected:
        raise ValueError(f"instruction record field lengths mismatch: {actual} != {expected}")
    return descriptor, fused_count, tuple(order), spans


def validate_block_fragments(data: bytes, prototype: Prototype, block: Block) -> None:
    source_chunk_state = chunk_state(block.entry_state, block.start_pc, block.count, prototype)
    order = derive_code_data_permutation(
        block.count, len(block.references), block.entry_state ^ source_chunk_state, prototype
    )
    if sorted(order) != list(range(block.count + len(block.references))):
        raise ValueError("invalid code/data fragment permutation")
    if block.references and len(order) > 2:
        type_runs = 1 + sum(
            (order[position] >= block.count) != (order[position - 1] >= block.count)
            for position in range(1, len(order))
        )
        if type_runs < 3:
            raise ValueError("code and constant fragments remain contiguous type partitions")

    cursor = Cursor(data, block.body_start, block.body_end)
    fragments: dict[int, bytes] = {}
    spans: dict[int, tuple[int, int, int]] = {}
    for logical_slot in order:
        frame_start = cursor.position
        length = cursor.u32()
        data_start = cursor.position
        fragments[logical_slot] = cursor.take(length)
        spans[logical_slot] = (frame_start, data_start, cursor.position)
    if cursor.position != block.body_end or len(fragments) != len(order):
        raise ValueError("block fragments were not consumed exactly")

    instruction_state = instruction_state_begin(
        source_chunk_state, block.entry_state, block.start_pc, block.tag, prototype
    )
    descriptors: list[int] = []
    fused_counts: list[int] = []
    orders: list[tuple[int, ...]] = []
    column_spans: list[dict[int, tuple[int, int, int]]] = []
    for offset in range(block.count):
        record = fragments[offset]
        _, record_start, record_end = spans[offset]
        descriptor, fused_count, column_order, record_spans = validate_instruction_record(
            record, prototype, block, offset, record_start, record_end
        )
        descriptors.append(descriptor)
        fused_counts.append(fused_count)
        orders.append(column_order)
        column_spans.append(record_spans)
        digest = instruction_digest(
            record, block.start_pc + offset, prototype, source_chunk_state, block.entry_state
        )
        instruction_state = instruction_state_advance(
            instruction_state, digest, block.start_pc + offset,
            source_chunk_state, block.entry_state,
        )

    capsules: dict[int, Capsule] = {}
    constant_chain_state = begin_constant_chain(prototype, block)
    for reference_offset, constant_index in enumerate(block.references):
        logical_slot = block.count + reference_offset
        capsule_data = fragments[logical_slot]
        _, capsule_start, capsule_end = spans[logical_slot]
        if len(capsule_data) < 5:
            raise ValueError("block-local constant capsule is too short")
        capsule = Capsule(
            constant_index, capsule_start, capsule_end, capsule_start, capsule_start + 4,
            block.start_pc, block.entry_state, source_chunk_state, logical_slot,
            constant_chain_state,
        )
        validate_capsule(data, prototype, capsule)
        capsules[constant_index] = capsule
        prototype.capsules.append(capsule)
        constant_chain_state = advance_constant_chain(constant_chain_state, capsule_data, constant_index)

    block.fragment_order = order
    block.fragment_spans = spans
    block.record_column_orders = orders
    block.record_column_spans = column_spans
    block.descriptors = descriptors
    block.fused_counts = fused_counts
    block.capsules = capsules
    block.final_instruction_state = instruction_state
    block.final_instruction_seal = instruction_state_seal(
        instruction_state, block.start_pc + block.count - 1,
        source_chunk_state, block.entry_state, block.tag,
    )


def constant_mask_state(index: int, prototype: Prototype, capsule: Capsule) -> int:
    value = (
        index * 65537
        + capsule.entry_state * 22695477
        + capsule.chunk_state * LCG_MULTIPLIER
        + capsule.block_start * 257
        + prototype.k1 * 257
        + prototype.k2 * 17
        + prototype.k3
        + CONSTANT_MASK_DOMAIN
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def begin_constant_chain(prototype: Prototype, block: Block) -> int:
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    source_chunk_state = chunk_state(
        block.entry_state, block.start_pc, block.count, prototype
    )
    value = (
        (block.entry_state ^ rotate16(source_chunk_state))
        + block.start_pc * 65537
        + keyed
        + CONSTANT_MASK_DOMAIN
        + 0xC2B2AE35
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def advance_constant_chain(state: int, capsule_bytes: bytes, index: int) -> int:
    value = state ^ ((index * 0x9E3779B1) & MASK32)
    for offset, byte in enumerate(capsule_bytes, 1):
        value = (value * 65599 + byte + offset * 257) & MASK32
    return (value ^ rotate16((len(capsule_bytes) * 65537 + index) & MASK32)) & MASK32


def string_shard_state(index: int, shard_index: int, length: int,
                       prototype: Prototype, capsule: Capsule) -> int:
    value = (
        constant_mask_state(index, prototype, capsule)
        + shard_index * 65537
        + length * 257
        + capsule.chain_state * 257
        + CONSTANT_MASK_DOMAIN
        + 0x9E3779B9
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def decode_string_shards(raw: bytes, index: int, prototype: Prototype,
                         capsule: Capsule) -> tuple[bytes, int]:
    if len(raw) < 6:
        raise ValueError("sharded string constant header is truncated")
    length = struct.unpack_from("<I", raw, 1)[0]
    shard_count = raw[5]
    if shard_count < 1 or shard_count > 7 or (length > 1 and shard_count < 2)             or (length > 0 and shard_count > length):
        raise ValueError("invalid sharded string count")
    order = derive_permutation(
        shard_count, prototype.k1, prototype.k2, prototype.k3,
        (CONSTANT_MASK_DOMAIN + 0x9E3779B9) & MASK32,
    )
    output = bytearray(length)
    cursor = 6
    for logical_shard in order:
        if cursor + 4 > len(raw):
            raise ValueError("sharded string length frame is truncated")
        shard_length = struct.unpack_from("<I", raw, cursor)[0]
        cursor += 4
        positions = list(range(logical_shard, length, shard_count))
        if shard_length != len(positions) or cursor + shard_length > len(raw):
            raise ValueError("sharded string member framing mismatch")
        state = string_shard_state(index, logical_shard, length, prototype, capsule)
        for position in positions:
            encoded = raw[cursor]
            cursor += 1
            output[position] = encoded ^ (state >> 24)
            state = (
                state * LCG_MULTIPLIER + LCG_INCREMENT
                + encoded + (position + 1) * 257
            ) & MASK32
    if cursor != len(raw):
        raise ValueError("sharded string capsule has trailing bytes")
    return bytes(output), shard_count


def constant_integrity(encoded: bytes, index: int, prototype: Prototype, capsule: Capsule) -> int:
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    left = keyed ^ CONSTANT_INTEGRITY_DOMAIN ^ capsule.entry_state ^ rotate16(capsule.chunk_state)
    right = capsule.chunk_state ^ rotate16(keyed) ^ (capsule.block_start * 257 & MASK32) ^ index
    counter = 1

    def absorb(word: int) -> None:
        nonlocal left, right, counter
        mixed = (word + counter * 257) & MASK32
        left = ((left ^ mixed) * 65599 + 0x9E3779B9) & MASK32
        right = ((right + mixed + (left >> 16)) * 48271 + 0x6D2B79F5) & MASK32
        left = (left ^ rotate16(right)) & MASK32
        counter += 1

    absorb(capsule.block_start)
    absorb(index)
    absorb(len(encoded))
    for value in encoded:
        absorb(value)
    left = ((left ^ right ^ len(encoded)) * 65599 + CONSTANT_INTEGRITY_DOMAIN) & MASK32
    right = ((right ^ rotate16(left) ^ index) * 48271 + 0xC4D29A6B) & MASK32
    return (left ^ rotate16(right)) & MASK32


def instruction_digest(
    record: bytes, index: int, prototype: Prototype, current_chunk_state: int, entry_state: int
) -> int:
    domain = INSTRUCTION_STATE_DOMAIN
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    left = keyed ^ domain ^ index ^ entry_state
    right = current_chunk_state ^ rotate16(keyed) ^ (index * 257 & MASK32) ^ rotate16(entry_state)
    counter = 1

    def absorb(word: int) -> None:
        nonlocal left, right, counter
        mixed = (word + counter * 257) & MASK32
        left = ((left ^ mixed) * 65599 + 0x9E3779B9) & MASK32
        right = ((right + mixed + (left >> 16)) * 48271 + 0x6D2B79F5) & MASK32
        left = (left ^ rotate16(right)) & MASK32
        counter += 1

    for word in (index, prototype.k1, prototype.k2, prototype.k3, len(record)):
        absorb(word)
    for value in record:
        absorb(value)
    left = ((left ^ right ^ len(record)) * 65599 + domain) & MASK32
    right = ((right ^ rotate16(left) ^ index) * 48271 + 0xC4D29A6B) & MASK32
    return (left ^ rotate16(right)) & MASK32


def instruction_state_begin(
    current_chunk_state: int, entry_state: int, block_start: int, block_tag: int, prototype: Prototype,
) -> int:
    value = (
        current_chunk_state * 22695477 + entry_state * LCG_MULTIPLIER
        + block_start * 65537 + block_tag + prototype.k1 * 251 + prototype.k2 * 17
        + prototype.k3 + INSTRUCTION_STATE_DOMAIN + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def instruction_state_advance(
    state: int, digest: int, index: int, current_chunk_state: int, entry_state: int,
) -> int:
    value = (
        state * LCG_MULTIPLIER + digest + index * 65537
        + current_chunk_state * 257 + entry_state
        + INSTRUCTION_STATE_DOMAIN + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * 22695477 + 1) & MASK32


def instruction_state_seal(
    state: int, index: int, current_chunk_state: int, entry_state: int, block_tag: int,
) -> int:
    value = (
        state * 22695477 + index * 257 + current_chunk_state
        + entry_state * LCG_MULTIPLIER + block_tag
        + INSTRUCTION_STATE_DOMAIN + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def prototype_integrity(data: bytes | bytearray, prototype: Prototype) -> int:
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    length = prototype.end - prototype.start
    left = keyed ^ PROTOTYPE_INTEGRITY_DOMAIN ^ length
    right = rotate16(keyed) ^ prototype.binding ^ (length * 257 & MASK32)
    counter = 1

    def absorb(word: int) -> None:
        nonlocal left, right, counter
        mixed = (word + counter * 257) & MASK32
        left = ((left ^ mixed) * 65599 + 0x9E3779B9) & MASK32
        right = ((right + mixed + (left >> 16)) * 48271 + 0x6D2B79F5) & MASK32
        left = (left ^ rotate16(right)) & MASK32
        counter += 1

    absorb(length)
    for relative, byte in enumerate(data[prototype.start:prototype.end]):
        if not 6 <= relative < 10:
            absorb(byte)
    left = ((left ^ right ^ length) * 65599 + PROTOTYPE_INTEGRITY_DOMAIN) & MASK32
    right = ((right ^ rotate16(left) ^ keyed) * 48271 + 0xC4D29A6B) & MASK32
    return (left ^ rotate16(right)) & MASK32


def flow_key(entry_state: int, from_pc: int, to_pc: int, prototype: Prototype) -> int:
    value = (
        entry_state * LCG_MULTIPLIER
        + from_pc * 257
        + to_pc * 65537
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + FLOW_DOMAIN
        + prototype.binding
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def chunk_state(entry_state: int, block_start: int, count: int, prototype: Prototype) -> int:
    value = (
        entry_state * 22695477
        + block_start * 65537
        + count * 257
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + CHUNK_STATE_DOMAIN
        + prototype.binding
        + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def initial_chunk_key(prototype: Prototype) -> int:
    value = (
        prototype.k1 * 65537
        + prototype.k2 * 257
        + prototype.k3
        + CHUNK_STATE_DOMAIN
        + prototype.binding
        + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * 22695477 + 1) & MASK32


def chunk_chain_key(
    source_chunk_state: int,
    source_entry_state: int,
    from_pc: int,
    to_pc: int,
    prototype: Prototype,
) -> int:
    value = (
        source_chunk_state * LCG_MULTIPLIER
        + source_entry_state * 22695477
        + from_pc * 257
        + to_pc * 65537
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + CHUNK_STATE_DOMAIN
        + prototype.binding
        + PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def recover_entry_state(verifier: int, block_start: int, prototype: Prototype) -> int:
    to_pc = block_start ^ FLOW_VERIFIER_MASK
    value = ((verifier - LCG_INCREMENT) * LCG_INVERSE) & MASK32
    constant = (
        block_start * 257
        + to_pc * 65537
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + FLOW_DOMAIN
        + prototype.binding
    ) & MASK32
    return ((value - constant) * LCG_INVERSE) & MASK32


def block_integrity(data: bytes | bytearray, prototype: Prototype, block: Block) -> int:
    domain = BLOCK_INTEGRITY_DOMAIN
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    left = block.entry_state ^ domain ^ prototype.binding ^ rotate16(keyed)
    right = prototype.binding ^ rotate16(block.entry_state) ^ keyed ^ (block.start_pc * 257 & MASK32)
    counter = 1

    def absorb(word: int) -> None:
        nonlocal left, right, counter
        mixed = (word + counter * 257) & MASK32
        left = ((left ^ mixed) * 65599 + 0x9E3779B9) & MASK32
        right = ((right + mixed + (left >> 16)) * 48271 + 0x6D2B79F5) & MASK32
        left = (left ^ rotate16(right)) & MASK32
        counter += 1

    for word in (
        block.start_pc, block.count, prototype.k1, prototype.k2, prototype.k3,
        block.route_token, len(block.references),
    ):
        absorb(word)
    for index in block.references:
        absorb(index)
    absorb(block.verifier)
    absorb(len(block.successors))
    for destination, wrapped_state, wrapped_chunk_state in block.successors:
        absorb(destination)
        absorb(wrapped_state)
        absorb(wrapped_chunk_state)
    encoded_body = bytes(data[block.body_start:block.body_end])
    absorb(len(encoded_body))
    for value in encoded_body:
        absorb(value)
    left = ((left ^ right ^ len(encoded_body)) * 65599 + domain) & MASK32
    right = ((right ^ rotate16(left) ^ block.start_pc ^ block.count) * 48271 + 0xC4D29A6B) & MASK32
    return (left ^ rotate16(right)) & MASK32


def validate_capsule(data: bytes, prototype: Prototype, capsule: Capsule) -> None:
    stored = struct.unpack_from("<I", data, capsule.tag_offset)[0]
    encoded = data[capsule.encoded_start:capsule.end]
    if constant_integrity(encoded, capsule.index, prototype, capsule) != stored:
        raise ValueError(f"constant capsule {capsule.index} authentication mismatch")
    raw = stream_xor(encoded, constant_mask_state(capsule.index, prototype, capsule))
    if not raw:
        raise ValueError("empty decoded constant capsule")
    tags = derive_permutation(4, prototype.k1, prototype.k2, prototype.k3, CONSTANT_TAG_DOMAIN)
    try:
        constant_type = tags.index(raw[0])
    except ValueError as error:
        raise ValueError("invalid decoded constant type tag") from error
    expected = {0: 1, 1: 2, 2: 9}.get(constant_type)
    if expected is not None and len(raw) != expected:
        raise ValueError("invalid fixed-width decoded constant capsule")
    if constant_type == 1 and raw[1] > 1:
        raise ValueError("invalid decoded boolean constant")
    if constant_type == 3:
        decode_string_shards(raw, capsule.index, prototype, capsule)


def parse_prototype(
    data: bytes, start: int, length: int, binding: int, preserve_line_info: bool = False
) -> Prototype:
    end = start + length
    if length < 10 or start < 0 or end > len(data):
        raise ValueError("invalid prototype slice length")
    k1, k2, k3 = struct.unpack_from("<HHH", data, start)
    prototype = Prototype(start, end, k1, k2, k3, start + 6, binding)
    stored_tag = struct.unpack_from("<I", data, prototype.tag_offset)[0]
    if prototype_integrity(data, prototype) != stored_tag:
        raise ValueError("prototype slice authentication mismatch")

    cursor = Cursor(data, start + 10, end)
    schema = derive_permutation(5, k1, k2, k3, SCHEMA_DOMAIN)
    for step in schema:
        if step == 0:
            prototype.parameter_offset = cursor.position
            cursor.u8()
        elif step == 1:
            prototype.constant_count = cursor.u32()
            if prototype.constant_count > 1_000_000:
                raise ValueError("unreasonable prototype constant count")
        elif step == 2:
            prototype.instruction_count = cursor.u32()
            block_count = cursor.u32()
            prototype.initial_wrapped_state = cursor.u32()
            prototype.initial_wrapped_chunk_offset = cursor.position
            prototype.initial_wrapped_chunk_state = cursor.u32()
            prototype.initial_route = cursor.u32() ^ binding
            if prototype.instruction_count < 1 or block_count < 1 or block_count > prototype.instruction_count:
                raise ValueError("invalid block/instruction count")
            for _ in range(block_count):
                start_pc = cursor.u32()
                count = cursor.u32()
                route = cursor.u32()
                reference_count = cursor.u32()
                references = [cursor.u32() for _ in range(reference_count)]
                verifier = cursor.u32()
                tag_offset = cursor.position
                tag = cursor.u32()
                successor_count = cursor.u32()
                successors: list[tuple[int, int, int]] = []
                successor_offsets: list[int] = []
                for _ in range(successor_count):
                    successor_offsets.append(cursor.position)
                    successors.append((cursor.u32(), cursor.u32(), cursor.u32()))
                body_length = cursor.u32()
                body_start = cursor.position
                cursor.take(body_length)
                if start_pc < 1 or count < 1 or start_pc + count - 1 > prototype.instruction_count:
                    raise ValueError("invalid block range")
                if references != sorted(set(references)):
                    raise ValueError("invalid ordered constant references")
                destinations = [item[0] for item in successors]
                if destinations != sorted(set(destinations)):
                    raise ValueError("invalid ordered successor records")
                entry_state = recover_entry_state(verifier, start_pc, prototype)
                if flow_key(entry_state, start_pc, start_pc ^ FLOW_VERIFIER_MASK, prototype) != verifier:
                    raise ValueError("flow verifier inversion mismatch")
                prototype.blocks.append(
                    Block(start_pc, count, route, references, verifier, tag, tag_offset, successors,
                          successor_offsets, body_start, cursor.position, entry_state)
                )
        elif step == 3:
            child_count = cursor.u32()
            if child_count > 1_000_000:
                raise ValueError("unreasonable child prototype count")
            for _ in range(child_count):
                child_length = cursor.u32()
                child_start = cursor.position
                cursor.take(child_length)
                prototype.children.append(parse_prototype(data, child_start, child_length, binding, preserve_line_info))
        elif step == 4 and preserve_line_info:
            line_count = cursor.u32()
            if line_count != prototype.instruction_count:
                raise ValueError("line-info count does not match instructions")
            cursor.take(line_count * 4)

    # The schema may place Instructions before StringTable, so checks that bind
    # block manifests to capsules run only after all five fields are parsed.
    occupied = [False] * (prototype.instruction_count + 1)
    starts = {block.start_pc for block in prototype.blocks}
    for block in prototype.blocks:
        if any(not 1 <= item <= prototype.constant_count for item in block.references):
            raise ValueError("block references a missing prototype constant")
        for pc in range(block.start_pc, block.start_pc + block.count):
            if occupied[pc]:
                raise ValueError("overlapping instruction blocks")
            occupied[pc] = True
        if any(destination not in starts for destination, _, _ in block.successors):
            raise ValueError("successor does not name a block start")
        if block_integrity(data, prototype, block) != block.tag:
            raise ValueError("complete block manifest authentication mismatch")
        validate_block_fragments(data, prototype, block)
        source_chunk_state = chunk_state(block.entry_state, block.start_pc, block.count, prototype)
        for destination, wrapped_state, wrapped_chunk_state in block.successors:
            destination_block = next(item for item in prototype.blocks if item.start_pc == destination)
            recovered = wrapped_state ^ flow_key(
                block.entry_state, block.start_pc + block.count - 1, destination, prototype
            )
            if recovered != destination_block.entry_state:
                raise ValueError("wrapped successor state mismatch")
            recovered_chunk_state = wrapped_chunk_state ^ chunk_chain_key(
                source_chunk_state,
                block.entry_state,
                block.start_pc + block.count - 1,
                destination,
                prototype,
            )
            expected_chunk_state = chunk_state(
                destination_block.entry_state,
                destination_block.start_pc,
                destination_block.count,
                prototype,
            )
            if recovered_chunk_state != expected_chunk_state:
                raise ValueError("attestation-bound wrapped successor chunk-state mismatch")
    if not prototype.blocks or not all(occupied[1:]):
        raise ValueError("instruction blocks do not cover the prototype")
    entry = next((block for block in prototype.blocks if block.start_pc == 1), None)
    if entry is None:
        raise ValueError("prototype has no entry block")
    initial_key_value = (k1 * 65537 + k2 * 257 + k3 + FLOW_DOMAIN + binding) & MASK32
    initial_key = (initial_key_value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32
    if prototype.initial_wrapped_state ^ initial_key != entry.entry_state:
        raise ValueError("initial block state mismatch")
    recovered_initial_chunk_state = prototype.initial_wrapped_chunk_state ^ initial_chunk_key(prototype)
    expected_initial_chunk_state = chunk_state(entry.entry_state, entry.start_pc, entry.count, prototype)
    if recovered_initial_chunk_state != expected_initial_chunk_state:
        raise ValueError("attestation-bound initial chunk-state mismatch")
    routed = [block for block in prototype.blocks if block.route_token != 0]
    if prototype.initial_route:
        if len(routed) != len(prototype.blocks) or entry.route_token != prototype.initial_route:
            raise ValueError("incomplete dispatcher route manifest")
        routes = [block.route_token for block in prototype.blocks]
        if len(routes) != len(set(routes)) or any(route <= prototype.instruction_count for route in routes):
            raise ValueError("invalid dispatcher route token")
    elif routed:
        raise ValueError("partial dispatcher route manifest")
    if cursor.position != end or prototype.parameter_offset is None:
        raise ValueError("prototype slice was not consumed exactly")
    return prototype


def transform_pipeline_byte(value: int, layout: PayloadLayout, ordinal: int, inverse: bool) -> int:
    if layout.byte_transform_variant == 0:
        return value
    if layout.byte_transform_variant == 1:
        return ((value & 0x0F) << 4) | (value >> 4)
    if layout.byte_transform_variant == 2:
        return value ^ ((layout.byte_transform_parameter + ordinal * 29) & 0xFF)
    shift = layout.byte_transform_parameter
    if inverse:
        return ((value >> shift) | (value << (8 - shift))) & 0xFF
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def pipeline_inverse(data: bytes, layout: PayloadLayout, seed: int, nonce: int, digest: int, ordinal: int) -> bytes:
    if layout.pipeline_variant == 0:
        transformed = data
    elif layout.pipeline_variant == 1:
        transformed = data[::-1]
    else:
        state = (seed ^ nonce ^ digest ^ DECODE_PIPELINE_DOMAIN ^ ((ordinal * 0x9E3779B9) & MASK32)) & MASK32
        output = bytearray(len(data))
        for index, encoded in enumerate(data):
            plain = encoded ^ ((state >> 24) & 0xFF)
            output[index] = plain
            state = (state * STREAM_MULTIPLIER + STREAM_INCREMENT + plain + index) & MASK32
        transformed = bytes(output)
    return bytes(transform_pipeline_byte(value, layout, ordinal, True) for value in transformed)


def pipeline_forward(data: bytes, layout: PayloadLayout, seed: int, nonce: int, digest: int, ordinal: int) -> bytes:
    transformed = bytes(transform_pipeline_byte(value, layout, ordinal, False) for value in data)
    if layout.pipeline_variant == 0:
        return transformed
    if layout.pipeline_variant == 1:
        return transformed[::-1]
    state = (seed ^ nonce ^ digest ^ DECODE_PIPELINE_DOMAIN ^ ((ordinal * 0x9E3779B9) & MASK32)) & MASK32
    output = bytearray(len(transformed))
    for index, plain in enumerate(transformed):
        output[index] = plain ^ ((state >> 24) & 0xFF)
        state = (state * STREAM_MULTIPLIER + STREAM_INCREMENT + plain + index) & MASK32
    return bytes(output)


def parse_and_verify(path: Path) -> PayloadInfo:
    global PAYLOAD_ATTESTATION
    source = path.read_text("latin1")
    domains = extract_build_domains(source)
    activate_domains(domains)
    literals, payload = extract_payload(source)
    layout = derive_payload_layout(domains)
    outer_values: dict[str, int] = {}
    outer_offset = 0
    for field_name in layout.outer_order:
        width = 1 if field_name == "flags" else 4
        outer_values[field_name] = read_uint(payload, outer_offset, width)
        outer_offset += width
    if outer_offset != 9:
        raise ValueError("invalid Build-local outer header width")
    head = outer_values["head"]
    stored_integrity = outer_values["integrity"]
    flags = outer_values["flags"]
    version, features = flags >> 4, flags & 0x0F
    if version != 5:
        raise ValueError(f"expected payload version 5, found {version}")
    if features not in (14, 15):
        raise ValueError(f"unexpected v5 feature bits (block + dispatcher + entropy required): {features}")

    encrypted = payload[outer_offset:]
    attestation_candidates, seed, integrity_key = recover_attestation_binding(
        source, head, flags, encrypted, stored_integrity, layout
    )
    if seed == 0 or integrity_key == 0 or outer_integrity(encrypted, integrity_key, flags) != stored_integrity:
        raise ValueError("v5 outer authenticator rejected the independently derived integrity key")
    if head == seed:
        raise ValueError("strict EnvironmentLock unexpectedly exposed the serializer seed in the payload head")
    envelope = payload_stream_xor(encrypted, seed)
    if len(envelope) < 32:
        raise ValueError("entropy envelope is shorter than its fixed header")

    envelope_values = {
        field_name: read_uint(envelope, slot * 4, 4)
        for slot, field_name in enumerate(layout.envelope_order)
    }
    real_length = envelope_values["real_length"]
    entropy_length = envelope_values["entropy_length"]
    record_count = envelope_values["record_count"]
    data_count = envelope_values["data_count"]
    entropy_count = envelope_values["entropy_count"]
    nonce = envelope_values["nonce"]
    entropy_digest = envelope_values["entropy_digest"]
    envelope_tag = envelope_values["integrity"]
    record_header_width = 1 + layout.record_ordinal_width + layout.record_length_width
    expected = 32 + record_count * record_header_width + real_length + entropy_length
    if not ENTROPY_MIN <= entropy_length <= ENTROPY_MAX:
        raise ValueError(f"entropy contribution outside 64–96 KiB: {entropy_length}")
    if not (1 <= data_count <= 65535 and 8 <= entropy_count <= 64):
        raise ValueError("invalid entropy envelope record counts")
    if record_count != data_count + entropy_count or nonce == 0 or expected != len(envelope):
        raise ValueError("invalid entropy envelope framing")

    integrity_offset = layout.envelope_order.index("integrity") * 4
    authenticated = envelope[:integrity_offset] + envelope[integrity_offset + 4:]
    computed_tag = hash_bytes(((seed ^ ENVELOPE_INTEGRITY_DOMAIN) * 31) & MASK32, authenticated)
    if computed_tag != envelope_tag:
        raise ValueError("entropy envelope authentication mismatch")

    records: list[Record] = []
    offset = 32
    data_records: dict[int, bytes] = {}
    entropy_records: dict[int, bytes] = {}
    for _ in range(record_count):
        start = offset
        if offset + record_header_width > len(envelope):
            raise ValueError("truncated entropy record header")
        record_values: dict[str, int] = {}
        for field_name in layout.record_order:
            width = 1 if field_name == "kind" else layout.record_ordinal_width if field_name == "ordinal" else layout.record_length_width
            record_values[field_name] = read_uint(envelope, offset, width)
            offset += width
        kind = record_values["kind"]
        ordinal = record_values["ordinal"]
        length = record_values["length"]
        data_offset = offset
        end = offset + length
        if length < 1 or end > len(envelope):
            raise ValueError("invalid entropy record length")
        record_data = envelope[offset:end]
        offset = end
        destination = data_records if kind == DATA_KIND else entropy_records if kind == ENTROPY_KIND else None
        limit = data_count if kind == DATA_KIND else entropy_count
        if destination is None or not 1 <= ordinal <= limit or ordinal in destination:
            raise ValueError("invalid or duplicate entropy record ordinal")
        destination[ordinal] = record_data
        records.append(Record(start, end, kind, ordinal, record_data, data_offset))
    if offset != len(envelope):
        raise ValueError("trailing or missing bytes in entropy envelope")
    if set(data_records) != set(range(1, data_count + 1)) or set(entropy_records) != set(range(1, entropy_count + 1)):
        raise ValueError("missing data or entropy record")
    if sum(map(len, data_records.values())) != real_length or sum(map(len, entropy_records.values())) != entropy_length:
        raise ValueError("entropy envelope record total mismatch")
    transitions = sum(records[index - 1].kind != records[index].kind for index in range(1, len(records)))
    if transitions < 2:
        raise ValueError("data and entropy records are not interleaved")

    digest = ((seed ^ ENTROPY_DIGEST_DOMAIN) * 31 + nonce) & MASK32
    digest = hash_word(digest, entropy_length)
    digest = hash_word(digest, entropy_count)
    for ordinal in range(1, entropy_count + 1):
        record_data = entropy_records[ordinal]
        digest = hash_word(digest, ordinal)
        digest = hash_word(digest, len(record_data))
        digest = hash_bytes(digest, record_data)
    if digest != entropy_digest:
        raise ValueError("entropy digest mismatch")

    mask_state = (
        seed ^ nonce ^ entropy_digest ^ ENVELOPE_MASK_DOMAIN ^ PAYLOAD_FORMAT_DOMAIN ^ DECODE_PIPELINE_DOMAIN ^ real_length
    ) & MASK32
    protected_pages: list[bytes] = []
    plain_pages: list[bytes] = []
    page_lengths: list[int] = []
    for ordinal in range(1, data_count + 1):
        masked_page = data_records[ordinal]
        framed_page = payload_stream_xor(masked_page, mask_state)
        for _ in masked_page:
            mask_state = (mask_state * STREAM_MULTIPLIER + STREAM_INCREMENT) & MASK32
        if len(framed_page) < layout.page_length_width + 1 or len(framed_page) > 16384:
            raise ValueError("bounded payload page has invalid framed length")
        length_offset = len(framed_page) - layout.page_length_width if layout.page_length_suffix else 0
        raw_length = read_uint(framed_page, length_offset, layout.page_length_width)
        if not 1 <= raw_length <= 6144:
            raise ValueError("bounded payload page has invalid raw length")
        encoded_page = (
            framed_page[:length_offset]
            if layout.page_length_suffix
            else framed_page[layout.page_length_width:]
        )
        encoded_page = pipeline_inverse(encoded_page, layout, seed, nonce, entropy_digest, ordinal)
        try:
            plain_page = zlib.decompress(encoded_page, -15) if features & 1 else encoded_page
        except zlib.error as error:
            raise ValueError(f"payload page {ordinal} is not an independent raw DEFLATE stream: {error}") from error
        if len(plain_page) != raw_length:
            raise ValueError("bounded payload page raw-length mismatch")
        protected_pages.append(framed_page)
        plain_pages.append(plain_page)
        page_lengths.append(raw_length)
    protected_body = b"".join(protected_pages)
    body = b"".join(plain_pages)
    if not body:
        raise ValueError("restored serialized body is empty")

    # The 32-bit client-side binder can occasionally map another numeric literal
    # in the generated VM to the same outer keys. The attestation value also
    # participates in chunk/instruction state, so only the shipped value can
    # authenticate the complete prototype graph.
    roots: list[tuple[int, Prototype]] = []
    for candidate in attestation_candidates:
        PAYLOAD_ATTESTATION = binder_payload_binding(head, candidate)
        try:
            roots.append((candidate, parse_prototype(body, 0, len(body), seed)))
        except (ValueError, IndexError, struct.error):
            continue
    if len(roots) != 1:
        raise ValueError(
            f"could not uniquely authenticate attestation through prototype state: "
            f"{[candidate for candidate, _root in roots]}"
        )
    attestation_token, root = roots[0]
    PAYLOAD_ATTESTATION = binder_payload_binding(head, attestation_token)

    entropy = b"".join(entropy_records[index] for index in range(1, entropy_count + 1))
    entropy_score = shannon_entropy(entropy)
    if entropy_score < 7.95:
        raise ValueError(f"entropy records are not high entropy enough: {entropy_score:.4f} bits/byte")

    return PayloadInfo(
        path, source, domains, layout, literals, payload, head, seed, attestation_token, flags, envelope, records, entropy,
        protected_body, body, root, entropy_length, entropy_digest, nonce,
        data_count, entropy_count, page_lengths, entropy_score
    )


def build_outer_payload(info: PayloadInfo, envelope: bytes) -> bytes:
    encrypted = payload_stream_xor(envelope, info.seed)
    integrity_key = binder_integrity_key(info.head, info.attestation_token)
    integrity = outer_integrity(encrypted, integrity_key, info.flags)
    values = {"head": info.head, "integrity": integrity, "flags": info.flags}
    output = bytearray()
    for field_name in info.layout.outer_order:
        append_uint(output, values[field_name], 1 if field_name == "flags" else 4)
    output.extend(encrypted)
    return bytes(output)


def replace_payload_literals(info: PayloadInfo, payload: bytes) -> str:
    encoded = encode_base91(payload)
    original_total = sum(len(item.content) for item in info.literals)
    remaining = len(encoded)
    position = 0
    replacements: list[str] = []
    for index, literal in enumerate(info.literals):
        slots_left = len(info.literals) - index - 1
        if slots_left == 0:
            length = remaining
        else:
            proportional = round(len(encoded) * len(literal.content) / original_total)
            length = max(1, min(proportional, remaining - slots_left))
        replacements.append(encoded[position:position + length])
        position += length
        remaining -= length
    if position != len(encoded):
        raise AssertionError("failed to split replacement base91 payload")
    source = info.source
    for literal, replacement in reversed(list(zip(info.literals, replacements))):
        source = source[:literal.content_start] + replacement + source[literal.content_end:]
    return source


def split_evenly(data: bytes, count: int) -> dict[int, bytes]:
    if len(data) < count:
        raise ValueError("protected body is too short for existing data record count")
    base, extra = divmod(len(data), count)
    result: dict[int, bytes] = {}
    position = 0
    for ordinal in range(1, count + 1):
        length = base + (1 if ordinal <= extra else 0)
        result[ordinal] = data[position:position + length]
        position += length
    return result


def envelope_for_body(info: PayloadInfo, body: bytes) -> bytes:
    if sum(info.page_lengths) == len(body):
        raw_pages: list[bytes] = []
        position = 0
        for length in info.page_lengths:
            raw_pages.append(body[position:position + length])
            position += length
    else:
        raw_pages = list(split_evenly(body, info.data_count).values())

    framed_pages: list[bytes] = []
    for ordinal, raw_page in enumerate(raw_pages, 1):
        if info.flags & 1:
            compressor = zlib.compressobj(level=9, wbits=-15)
            encoded_page = compressor.compress(raw_page) + compressor.flush()
        else:
            encoded_page = raw_page
        transformed = pipeline_forward(encoded_page, info.layout, info.seed, info.nonce, info.entropy_digest, ordinal)
        frame = bytearray()
        if not info.layout.page_length_suffix:
            append_uint(frame, len(raw_page), info.layout.page_length_width)
        frame.extend(transformed)
        if info.layout.page_length_suffix:
            append_uint(frame, len(raw_page), info.layout.page_length_width)
        framed_pages.append(bytes(frame))
    real_length = sum(map(len, framed_pages))
    mask_state = (
        info.seed ^ info.nonce ^ info.entropy_digest ^ ENVELOPE_MASK_DOMAIN ^ PAYLOAD_FORMAT_DOMAIN ^ DECODE_PIPELINE_DOMAIN ^ real_length
    ) & MASK32
    masked_stream = payload_stream_xor(b"".join(framed_pages), mask_state)
    data_records: dict[int, bytes] = {}
    position = 0
    for ordinal, framed_page in enumerate(framed_pages, 1):
        data_records[ordinal] = masked_stream[position:position + len(framed_page)]
        position += len(framed_page)
    entropy_records = {record.ordinal: record.data for record in info.records if record.kind == ENTROPY_KIND}
    header_values = {
        "real_length": real_length,
        "entropy_length": info.entropy_length,
        "record_count": len(info.records),
        "data_count": len(framed_pages),
        "entropy_count": info.entropy_count,
        "nonce": info.nonce,
        "entropy_digest": info.entropy_digest,
        "integrity": 0,
    }
    envelope = bytearray()
    for field_name in info.layout.envelope_order:
        append_uint(envelope, header_values[field_name], 4)
    for record in info.records:
        record_data = data_records[record.ordinal] if record.kind == DATA_KIND else entropy_records[record.ordinal]
        record_values = {"kind": record.kind, "ordinal": record.ordinal, "length": len(record_data)}
        for field_name in info.layout.record_order:
            width = 1 if field_name == "kind" else info.layout.record_ordinal_width if field_name == "ordinal" else info.layout.record_length_width
            append_uint(envelope, record_values[field_name], width)
        envelope.extend(record_data)
    integrity_offset = info.layout.envelope_order.index("integrity") * 4
    tag = hash_bytes(
        ((info.seed ^ ENVELOPE_INTEGRITY_DOMAIN) * 31) & MASK32,
        envelope[:integrity_offset] + envelope[integrity_offset + 4:],
    )
    envelope[integrity_offset:integrity_offset + 4] = struct.pack("<I", tag)
    return bytes(envelope)


def write_body_variant(info: PayloadInfo, output_dir: Path, name: str, body: bytes | bytearray) -> None:
    envelope = envelope_for_body(info, bytes(body))
    payload = build_outer_payload(info, envelope)
    (output_dir / f"payload-{name}.lua").write_text(replace_payload_literals(info, payload), "latin1")


def patch_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & MASK32)


def write_tampered_variants(info: PayloadInfo, output_dir: Path) -> None:
    activate_domains(info.domains)
    entropy_records = [record for record in info.records if record.kind == ENTROPY_KIND]
    if len(entropy_records) < 2:
        raise ValueError("not enough entropy records for tamper variants")
    changed = bytearray(info.envelope)
    changed[entropy_records[0].data_offset] ^= 1
    removed = info.envelope[:entropy_records[0].start] + info.envelope[entropy_records[0].end:]
    first, second = info.records[0], info.records[1]
    reordered = (
        info.envelope[:first.start]
        + info.envelope[second.start:second.end]
        + info.envelope[first.start:first.end]
        + info.envelope[second.end:]
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    for name, envelope in {"modify": bytes(changed), "delete": removed, "reorder": reordered}.items():
        payload = build_outer_payload(info, envelope)
        (output_dir / f"entropy-{name}.lua").write_text(replace_payload_literals(info, payload), "latin1")

    # Prototype tag: alter only the independent root tag while rebuilding every
    # outer layer. The failure therefore occurs at prototype-slice authentication.
    prototype_variant = bytearray(info.body)
    prototype_variant[info.root.tag_offset] ^= 1
    write_body_variant(info, output_dir, "prototype-tag", prototype_variant)

    # Initial chunk state: repair the prototype tag after changing only the
    # attestation-bound wrapped state. Parsing/authentication passes, but the
    # first Fetch must reject the independently invalid chunk-state chain.
    initial_chunk_variant = bytearray(info.body)
    initial_chunk_variant[info.root.initial_wrapped_chunk_offset] ^= 1
    patch_u32(initial_chunk_variant, info.root.tag_offset, prototype_integrity(initial_chunk_variant, info.root))
    write_body_variant(info, output_dir, "initial-chunk-state", initial_chunk_variant)

    # Successor chunk state: alter one wrapped chain edge while repairing both
    # its block manifest and the root prototype tag. Flow wrapping remains valid,
    # leaving the attestation/VM-state chunk chain as the rejecting boundary.
    chain_block = next((block for block in info.root.blocks if block.start_pc == 1 and block.successors), None)
    if chain_block is None:
        raise ValueError("root prototype has no successor edge for chunk-chain tamper")
    successor_chain_variant = bytearray(info.body)
    original_successors = list(chain_block.successors)
    for successor_index, (destination, wrapped_state, wrapped_chunk_state) in enumerate(original_successors):
        patch_u32(
            successor_chain_variant,
            chain_block.successor_offsets[successor_index] + 8,
            wrapped_chunk_state ^ 1,
        )
        chain_block.successors[successor_index] = (destination, wrapped_state, wrapped_chunk_state ^ 1)
    patch_u32(
        successor_chain_variant,
        chain_block.tag_offset,
        block_integrity(successor_chain_variant, info.root, chain_block),
    )
    chain_block.successors[:] = original_successors
    patch_u32(successor_chain_variant, info.root.tag_offset, prototype_integrity(successor_chain_variant, info.root))
    write_body_variant(info, output_dir, "successor-chunk-state", successor_chain_variant)

    # Block manifest: alter the first block's opaque body, then repair the root
    # prototype tag. Outer/envelope/prototype checks pass; the complete block tag
    # must reject the body before any instruction from that block is decoded.
    entry_block = next((block for block in info.root.blocks if block.start_pc == 1 and block.body_end > block.body_start), None)
    if entry_block is None:
        raise ValueError("root prototype has no mutable entry block")
    block_variant = bytearray(info.body)
    block_variant[entry_block.body_start] ^= 1
    patch_u32(block_variant, info.root.tag_offset, prototype_integrity(block_variant, info.root))
    write_body_variant(info, output_dir, "block-manifest", block_variant)

    # Column framing: extend the first physical page into the following frame,
    # then repair both block and prototype tags. Authentication now passes, but
    # the block-local five-page parser must reject the shifted framing.
    column_framing_variant = bytearray(info.body)
    first_page_length = struct.unpack_from("<I", column_framing_variant, entry_block.body_start)[0]
    patch_u32(column_framing_variant, entry_block.body_start, first_page_length + 1)
    patch_u32(
        column_framing_variant,
        entry_block.tag_offset,
        block_integrity(column_framing_variant, info.root, entry_block),
    )
    patch_u32(
        column_framing_variant,
        info.root.tag_offset,
        prototype_integrity(column_framing_variant, info.root),
    )
    write_body_variant(info, output_dir, "column-framing", column_framing_variant)

    # Column consumption: turn one authenticated normal instruction into a data
    # word without removing its opcode/operand bytes. The role map and framing
    # remain valid, but exact per-column consumption must reject the leftovers.
    normal_offset = next(
        (offset for offset, descriptor in enumerate(entry_block.descriptors) if descriptor & 1 == 0 and descriptor < 64),
        None,
    )
    if normal_offset is None:
        raise ValueError("entry block has no normal instruction for column-consumption tamper")
    _, descriptor_offset, descriptor_end = entry_block.record_column_spans[normal_offset][0]
    if descriptor_end != descriptor_offset + 1:
        raise ValueError("normal instruction descriptor span is not scalar")
    descriptor_mask = block_field_mask(
        entry_block.entry_state, entry_block.start_pc + normal_offset, 7, info.root
    )
    column_consumption_variant = bytearray(info.body)
    encoded_descriptor = encode_prototype_column(
        bytes([(1 ^ descriptor_mask) & 0xFF]),
        info.root,
        entry_block,
        0,
        entry_block.start_pc + normal_offset,
    )
    column_consumption_variant[descriptor_offset] = encoded_descriptor[0]
    patch_u32(
        column_consumption_variant,
        entry_block.tag_offset,
        block_integrity(column_consumption_variant, info.root, entry_block),
    )
    patch_u32(
        column_consumption_variant,
        info.root.tag_offset,
        prototype_integrity(column_consumption_variant, info.root),
    )
    write_body_variant(info, output_dir, "column-consumption", column_consumption_variant)

    # Capsule integrity: alter a referenced capsule's stored tag, repair every
    # block manifest that embeds that capsule, and finally repair the prototype
    # tag. DecodeConstantCapsule must be the remaining rejecting layer.
    referenced = next((index for block in sorted(info.root.blocks, key=lambda item: item.start_pc)
                       for index in block.references), None)
    if referenced is None:
        raise ValueError("root prototype has no referenced constant capsule")
    capsule_variant = bytearray(info.body)
    target_capsule = next(
        capsule for capsule in info.root.capsules if capsule.index == referenced
    )
    capsule_variant[target_capsule.tag_offset] ^= 1
    owner = next(block for block in info.root.blocks if block.start_pc == target_capsule.block_start)
    patch_u32(capsule_variant, owner.tag_offset, block_integrity(capsule_variant, info.root, owner))
    patch_u32(capsule_variant, info.root.tag_offset, prototype_integrity(capsule_variant, info.root))
    write_body_variant(info, output_dir, "capsule-integrity", capsule_variant)


def count_prototypes(prototype: Prototype) -> int:
    return 1 + sum(count_prototypes(child) for child in prototype.children)


def count_blocks(prototype: Prototype) -> int:
    return len(prototype.blocks) + sum(count_blocks(child) for child in prototype.children)


def count_capsules(prototype: Prototype) -> int:
    return len(prototype.capsules) + sum(count_capsules(child) for child in prototype.children)


def collect_fragment_orders(prototype: Prototype) -> list[tuple[int, ...]]:
    return [tuple(block.fragment_order) for block in prototype.blocks] + [
        order for child in prototype.children for order in collect_fragment_orders(child)
    ]


def count_instruction_records(prototype: Prototype) -> int:
    return sum(len(block.record_column_orders) for block in prototype.blocks) + sum(
        count_instruction_records(child) for child in prototype.children
    )


def collect_fused_counts(prototype: Prototype) -> list[int]:
    return [count for block in prototype.blocks for count in block.fused_counts] + [
        count for child in prototype.children for count in collect_fused_counts(child)
    ]


def describe(info: PayloadInfo) -> str:
    fragment_orders = collect_fragment_orders(info.root)
    if len(fragment_orders) != count_blocks(info.root) or any(not order for order in fragment_orders):
        raise ValueError("code/data fragment validation did not cover every block")
    fused_counts = collect_fused_counts(info.root)
    physical_instructions = count_instruction_records(info.root)
    logical_instructions = physical_instructions + sum(fused_counts)
    return (
        f"PASS authenticated v5 payload: features={info.flags & 15}, "
        f"prototypes={count_prototypes(info.root)}, blocks={count_blocks(info.root)}, "
        f"fragment_layouts={len(set(fragment_orders))}, capsules={count_capsules(info.root)}, entropy={info.entropy_length} bytes, "
        f"instruction_records={physical_instructions}, logical_instructions={logical_instructions}, "
        f"fused_records={sum(count > 0 for count in fused_counts)}, pages={info.data_count}, max_page={max(info.page_lengths)}, "
        f"chunk_chain=attested, instruction_chain=sealed, "
        f"records={len(info.records)}, H={info.shannon_entropy:.4f} bits/byte, "
        f"entropy_sha256={hashlib.sha256(info.entropy).hexdigest()}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--compare", type=Path, help="verify a second generation has independent entropy")
    parser.add_argument("--tamper-dir", type=Path, help="write authenticated outer/envelope and v5 manifest tamper variants")
    args = parser.parse_args()
    try:
        info = parse_and_verify(args.generated)
        print(describe(info))
        if args.compare:
            other = parse_and_verify(args.compare)
            print(describe(other))
            if info.domains == other.domains:
                raise ValueError("independent generations reused the complete build-domain vector")
            print("PASS independent serializer/runtime domains across generations")
            if info.layout == other.layout:
                raise ValueError("independent generations reused the complete payload grammar and decode pipeline")
            print("PASS independent payload grammar/decode pipeline across generations")
            if info.entropy == other.entropy or info.entropy_digest == other.entropy_digest or info.nonce == other.nonce:
                raise ValueError("independent generations reused entropy state")
            print("PASS independent entropy across generations")
        if args.tamper_dir:
            write_tampered_variants(info, args.tamper_dir)
            print(f"PASS wrote entropy and v5 manifest tamper variants to {args.tamper_dir}")
    except (OSError, ValueError, struct.error, StopIteration) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
