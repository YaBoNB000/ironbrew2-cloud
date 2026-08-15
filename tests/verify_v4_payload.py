#!/usr/bin/env python3
"""Verify and tamper-test IronBrew2's authenticated v4 payload format."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import math
from pathlib import Path
import struct
import sys
import zlib

MASK32 = 0xFFFFFFFF
MOD32 = 1 << 32
INTEGRITY_DOMAIN = 0xA5C31F27
BLOCK_INTEGRITY_DOMAIN = 0x7F4A7C15
FLOW_DOMAIN = 0x6D2B79F5
ENVELOPE_INTEGRITY_DOMAIN = 0xC4D29A6B
ENTROPY_DIGEST_DOMAIN = 0x91E10DA5
ENVELOPE_MASK_DOMAIN = 0x3A75C9EF
CONSTANT_INTEGRITY_DOMAIN = 0xD13C5E79
CONSTANT_MASK_DOMAIN = 0x4B8F21A3
PROTOTYPE_INTEGRITY_DOMAIN = 0xE9274D6B
BLOCK_COLUMN_DOMAIN = 3253
ENTROPY_KIND = 0xA7
DATA_KIND = 0x5C
ENTROPY_MIN = 64 * 1024
ENTROPY_MAX = 96 * 1024
LCG_MULTIPLIER = 1664525
LCG_INCREMENT = 1013904223
LCG_INVERSE = pow(LCG_MULTIPLIER, -1, MOD32)


@dataclass(frozen=True)
class Literal:
    content_start: int
    content_end: int
    content: str


@dataclass(frozen=True)
class Record:
    start: int
    end: int
    kind: int
    ordinal: int
    data: bytes


@dataclass
class Capsule:
    index: int
    start: int
    end: int
    tag_offset: int
    encoded_start: int


@dataclass
class Block:
    start_pc: int
    count: int
    route_token: int
    references: list[int]
    verifier: int
    tag: int
    tag_offset: int
    successors: list[tuple[int, int]]
    body_start: int
    body_end: int
    entry_state: int
    column_order: list[int] = field(default_factory=list)
    column_spans: dict[int, tuple[int, int]] = field(default_factory=dict)
    descriptors: list[int] = field(default_factory=list)


@dataclass
class Prototype:
    start: int
    end: int
    k1: int
    k2: int
    k3: int
    tag_offset: int
    parameter_offset: int | None = None
    instruction_count: int = 0
    capsules: list[Capsule] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    children: list["Prototype"] = field(default_factory=list)


@dataclass
class PayloadInfo:
    path: Path
    source: str
    literals: list[Literal]
    payload: bytes
    seed: int
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
    candidates = [
        literal
        for literal in scan_string_literals(source)
        if len(literal.content) >= 1024 and is_base91_literal(literal.content)
    ]
    candidates.sort(key=lambda item: item.content_start)
    if not 2 <= len(candidates) <= 6:
        raise ValueError(f"expected 2–6 large base91 payload segments, found {len(candidates)}")
    payload = decode_base91("".join(item.content for item in candidates))
    if len(payload) < 9:
        raise ValueError("decoded payload is shorter than the fixed v4 header")
    return candidates, payload


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


def block_field_mask(entry_state: int, pc: int, slot: int, prototype: Prototype) -> int:
    low = entry_state & 0xFFFF
    high = entry_state >> 16
    return (
        low * ((pc + slot * 29) % 251 + 1)
        + high * 17
        + prototype.k1 * 13
        + prototype.k2 * 7
        + prototype.k3
        + slot * 911
    ) & 0xFFFF


def validate_columnar_block(data: bytes, prototype: Prototype, block: Block) -> None:
    """Validate framing, role derivation and exact logical-column consumption."""
    order = derive_block_permutation(
        5, block.entry_state, prototype.k1, prototype.k2, prototype.k3, BLOCK_COLUMN_DOMAIN
    )
    if sorted(order) != list(range(5)) or order == list(range(5)):
        raise ValueError("invalid or identity block column-role permutation")

    cursor = Cursor(data, block.body_start, block.body_end)
    columns: dict[int, bytes] = {}
    spans: dict[int, tuple[int, int]] = {}
    for role in order:
        frame_start = cursor.position
        length = cursor.u32()
        if role in columns:
            raise ValueError("duplicate logical block column role")
        columns[role] = cursor.take(length)
        spans[role] = (frame_start, cursor.position)
    if cursor.position != block.body_end or set(columns) != set(range(5)):
        raise ValueError("block column pages were not consumed exactly")

    descriptor_column = columns[0]
    if len(descriptor_column) != block.count:
        raise ValueError("descriptor column length does not match block instruction count")
    descriptors = [
        encoded ^ (block_field_mask(block.entry_state, block.start_pc + offset, 7, prototype) & 0xFF)
        for offset, encoded in enumerate(descriptor_column)
    ]

    non_data = 0
    expected_b = 0
    expected_c = 0
    for descriptor in descriptors:
        if descriptor & 1:
            if descriptor != 1:
                raise ValueError("invalid data-word descriptor in columnar block")
            continue
        if descriptor >= 64:
            raise ValueError("invalid high bits in instruction descriptor")
        instruction_type = (descriptor >> 1) & 3
        non_data += 1
        expected_b += 2 if instruction_type == 0 else 4
        if instruction_type in (0, 3):
            expected_c += 2

    expected_lengths = {
        0: block.count,
        1: non_data * 2,
        2: non_data * 2,
        3: expected_b,
        4: expected_c,
    }
    actual_lengths = {role: len(column) for role, column in columns.items()}
    if actual_lengths != expected_lengths:
        raise ValueError(
            f"logical block column lengths do not match descriptors: {actual_lengths} != {expected_lengths}"
        )
    block.column_order = order
    block.column_spans = spans
    block.descriptors = descriptors


def constant_mask_state(index: int, prototype: Prototype) -> int:
    value = (
        index * 65537
        + prototype.k1 * 257
        + prototype.k2 * 17
        + prototype.k3
        + CONSTANT_MASK_DOMAIN
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def constant_integrity(encoded: bytes, index: int, prototype: Prototype) -> int:
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    value = hash_word(keyed ^ CONSTANT_INTEGRITY_DOMAIN, index)
    value = hash_word(value, len(encoded))
    return hash_bytes(value, encoded)


def prototype_integrity(data: bytes | bytearray, prototype: Prototype) -> int:
    keyed = (prototype.k1 * 65537 + prototype.k2 * 257 + prototype.k3) & MASK32
    value = hash_word(keyed ^ PROTOTYPE_INTEGRITY_DOMAIN, prototype.end - prototype.start)
    for relative, byte in enumerate(data[prototype.start:prototype.end]):
        if not 6 <= relative < 10:
            value = hash_word(value, byte)
    return value


def flow_key(entry_state: int, from_pc: int, to_pc: int, prototype: Prototype) -> int:
    value = (
        entry_state * LCG_MULTIPLIER
        + from_pc * 257
        + to_pc * 65537
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + FLOW_DOMAIN
    ) & MASK32
    return (value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32


def recover_entry_state(verifier: int, block_start: int, prototype: Prototype) -> int:
    to_pc = block_start ^ 0x5A5A
    value = ((verifier - LCG_INCREMENT) * LCG_INVERSE) & MASK32
    constant = (
        block_start * 257
        + to_pc * 65537
        + prototype.k1 * 251
        + prototype.k2 * 17
        + prototype.k3
        + FLOW_DOMAIN
    ) & MASK32
    return ((value - constant) * LCG_INVERSE) & MASK32


def block_integrity(data: bytes | bytearray, prototype: Prototype, block: Block) -> int:
    value = hash_word(block.entry_state ^ BLOCK_INTEGRITY_DOMAIN, block.start_pc)
    for word in (block.count, prototype.k1, prototype.k2, prototype.k3, block.route_token, len(block.references)):
        value = hash_word(value, word)
    for index in block.references:
        capsule = prototype.capsules[index - 1]
        capsule_data = bytes(data[capsule.start:capsule.end])
        value = hash_word(value, index)
        value = hash_word(value, len(capsule_data))
        value = hash_bytes(value, capsule_data)
    value = hash_word(value, block.verifier)
    value = hash_word(value, len(block.successors))
    for destination, wrapped_state in block.successors:
        value = hash_word(value, destination)
        value = hash_word(value, wrapped_state)
    encoded_body = bytes(data[block.body_start:block.body_end])
    value = hash_word(value, len(encoded_body))
    return hash_bytes(value, encoded_body)


def validate_capsule(data: bytes, prototype: Prototype, capsule: Capsule) -> None:
    stored = struct.unpack_from("<I", data, capsule.tag_offset)[0]
    encoded = data[capsule.encoded_start:capsule.end]
    if constant_integrity(encoded, capsule.index, prototype) != stored:
        raise ValueError(f"constant capsule {capsule.index} authentication mismatch")
    raw = stream_xor(encoded, constant_mask_state(capsule.index, prototype))
    if not raw:
        raise ValueError("empty decoded constant capsule")
    tags = derive_permutation(4, prototype.k1, prototype.k2, prototype.k3, 911)
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
        if len(raw) < 5 or struct.unpack_from("<I", raw, 1)[0] != len(raw) - 5:
            raise ValueError("invalid decoded string constant framing")


def parse_prototype(data: bytes, start: int, length: int, preserve_line_info: bool = False) -> Prototype:
    end = start + length
    if length < 10 or start < 0 or end > len(data):
        raise ValueError("invalid prototype slice length")
    k1, k2, k3 = struct.unpack_from("<HHH", data, start)
    prototype = Prototype(start, end, k1, k2, k3, start + 6)
    stored_tag = struct.unpack_from("<I", data, prototype.tag_offset)[0]
    if prototype_integrity(data, prototype) != stored_tag:
        raise ValueError("prototype slice authentication mismatch")

    cursor = Cursor(data, start + 10, end)
    schema = derive_permutation(5, k1, k2, k3, 113)
    for step in schema:
        if step == 0:
            prototype.parameter_offset = cursor.position
            cursor.u8()
        elif step == 1:
            count = cursor.u32()
            if count > 1_000_000:
                raise ValueError("unreasonable constant capsule count")
            for index in range(1, count + 1):
                capsule_length = cursor.u32()
                if capsule_length < 5:
                    raise ValueError("constant capsule is shorter than tag plus value")
                capsule_start = cursor.position
                cursor.take(capsule_length)
                capsule = Capsule(index, capsule_start, cursor.position, capsule_start, capsule_start + 4)
                prototype.capsules.append(capsule)
                validate_capsule(data, prototype, capsule)
        elif step == 2:
            prototype.instruction_count = cursor.u32()
            block_count = cursor.u32()
            initial_wrapped_state = cursor.u32()
            initial_route = cursor.u32()
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
                successors = [(cursor.u32(), cursor.u32()) for _ in range(successor_count)]
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
                if flow_key(entry_state, start_pc, start_pc ^ 0x5A5A, prototype) != verifier:
                    raise ValueError("flow verifier inversion mismatch")
                prototype.blocks.append(
                    Block(start_pc, count, route, references, verifier, tag, tag_offset, successors,
                          body_start, cursor.position, entry_state)
                )
        elif step == 3:
            child_count = cursor.u32()
            if child_count > 1_000_000:
                raise ValueError("unreasonable child prototype count")
            for _ in range(child_count):
                child_length = cursor.u32()
                child_start = cursor.position
                cursor.take(child_length)
                prototype.children.append(parse_prototype(data, child_start, child_length, preserve_line_info))
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
        if any(not 1 <= item <= len(prototype.capsules) for item in block.references):
            raise ValueError("block references a missing constant capsule")
        for pc in range(block.start_pc, block.start_pc + block.count):
            if occupied[pc]:
                raise ValueError("overlapping instruction blocks")
            occupied[pc] = True
        if any(destination not in starts for destination, _ in block.successors):
            raise ValueError("successor does not name a block start")
        if block_integrity(data, prototype, block) != block.tag:
            raise ValueError("complete block manifest authentication mismatch")
        validate_columnar_block(data, prototype, block)
        for destination, wrapped_state in block.successors:
            expected_state = next(item.entry_state for item in prototype.blocks if item.start_pc == destination)
            recovered = wrapped_state ^ flow_key(
                block.entry_state, block.start_pc + block.count - 1, destination, prototype
            )
            if recovered != expected_state:
                raise ValueError("wrapped successor state mismatch")
    if not prototype.blocks or not all(occupied[1:]):
        raise ValueError("instruction blocks do not cover the prototype")
    entry = next((block for block in prototype.blocks if block.start_pc == 1), None)
    if entry is None:
        raise ValueError("prototype has no entry block")
    initial_key_value = (k1 * 65537 + k2 * 257 + k3 + FLOW_DOMAIN) & MASK32
    initial_key = (initial_key_value * LCG_MULTIPLIER + LCG_INCREMENT) & MASK32
    if initial_wrapped_state ^ initial_key != entry.entry_state:
        raise ValueError("initial block state mismatch")
    routed = [block for block in prototype.blocks if block.route_token != 0]
    if initial_route:
        if len(routed) != len(prototype.blocks) or entry.route_token != initial_route:
            raise ValueError("incomplete dispatcher route manifest")
        routes = [block.route_token for block in prototype.blocks]
        if len(routes) != len(set(routes)) or any(route <= prototype.instruction_count for route in routes):
            raise ValueError("invalid dispatcher route token")
    elif routed:
        raise ValueError("partial dispatcher route manifest")
    if cursor.position != end or prototype.parameter_offset is None:
        raise ValueError("prototype slice was not consumed exactly")
    return prototype


def parse_and_verify(path: Path) -> PayloadInfo:
    source = path.read_text("latin1")
    literals, payload = extract_payload(source)
    seed, stored_integrity = struct.unpack_from("<II", payload)
    flags = payload[8]
    version, features = flags >> 4, flags & 0x0F
    if version != 4:
        raise ValueError(f"expected payload version 4, found {version}")
    if features not in (14, 15):
        raise ValueError(f"unexpected v4 feature bits (block + dispatcher + entropy required): {features}")

    encrypted = payload[9:]
    integrity = hash_bytes(((seed ^ INTEGRITY_DOMAIN) * 31 + flags) & MASK32, encrypted)
    if integrity != stored_integrity:
        raise ValueError("outer encrypted-payload integrity mismatch (default unlocked output required)")
    envelope = stream_xor(encrypted, seed)
    if len(envelope) < 32:
        raise ValueError("entropy envelope is shorter than its fixed header")

    (
        real_length,
        entropy_length,
        record_count,
        data_count,
        entropy_count,
        nonce,
        entropy_digest,
        envelope_tag,
    ) = struct.unpack_from("<8I", envelope)
    expected = 32 + record_count * 7 + real_length + entropy_length
    if not ENTROPY_MIN <= entropy_length <= ENTROPY_MAX:
        raise ValueError(f"entropy contribution outside 64–96 KiB: {entropy_length}")
    if not (1 <= data_count <= 32 and 8 <= entropy_count <= 64):
        raise ValueError("invalid entropy envelope record counts")
    if record_count != data_count + entropy_count or nonce == 0 or expected != len(envelope):
        raise ValueError("invalid entropy envelope framing")

    authenticated = envelope[:28] + envelope[32:]
    computed_tag = hash_bytes(((seed ^ ENVELOPE_INTEGRITY_DOMAIN) * 31) & MASK32, authenticated)
    if computed_tag != envelope_tag:
        raise ValueError("entropy envelope authentication mismatch")

    records: list[Record] = []
    offset = 32
    data_records: dict[int, bytes] = {}
    entropy_records: dict[int, bytes] = {}
    for _ in range(record_count):
        start = offset
        if offset + 7 > len(envelope):
            raise ValueError("truncated entropy record header")
        kind = envelope[offset]
        ordinal, length = struct.unpack_from("<HI", envelope, offset + 1)
        offset += 7
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
        records.append(Record(start, end, kind, ordinal, record_data))
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

    masked_body = b"".join(data_records[index] for index in range(1, data_count + 1))
    mask_state = seed ^ nonce ^ entropy_digest ^ ENVELOPE_MASK_DOMAIN ^ real_length
    protected_body = stream_xor(masked_body, mask_state)
    try:
        body = zlib.decompress(protected_body, -15) if features & 1 else protected_body
    except zlib.error as error:
        raise ValueError(f"restored body is not a valid raw DEFLATE stream: {error}") from error
    if not body:
        raise ValueError("restored serialized body is empty")
    root = parse_prototype(body, 0, len(body))

    entropy = b"".join(entropy_records[index] for index in range(1, entropy_count + 1))
    entropy_score = shannon_entropy(entropy)
    if entropy_score < 7.95:
        raise ValueError(f"entropy records are not high entropy enough: {entropy_score:.4f} bits/byte")

    return PayloadInfo(
        path, source, literals, payload, seed, flags, envelope, records, entropy,
        protected_body, body, root, entropy_length, entropy_digest, nonce,
        data_count, entropy_count, entropy_score
    )


def build_outer_payload(info: PayloadInfo, envelope: bytes) -> bytes:
    encrypted = stream_xor(envelope, info.seed)
    integrity = hash_bytes(((info.seed ^ INTEGRITY_DOMAIN) * 31 + info.flags) & MASK32, encrypted)
    return struct.pack("<II", info.seed, integrity) + bytes([info.flags]) + encrypted


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
    if info.flags & 1:
        compressor = zlib.compressobj(level=9, wbits=-15)
        protected = compressor.compress(body) + compressor.flush()
    else:
        protected = body
    mask_state = info.seed ^ info.nonce ^ info.entropy_digest ^ ENVELOPE_MASK_DOMAIN ^ len(protected)
    data_records = split_evenly(stream_xor(protected, mask_state), info.data_count)
    entropy_records = {record.ordinal: record.data for record in info.records if record.kind == ENTROPY_KIND}
    envelope = bytearray(struct.pack(
        "<8I", len(protected), info.entropy_length, len(info.records), info.data_count,
        info.entropy_count, info.nonce, info.entropy_digest, 0
    ))
    for record in info.records:
        record_data = data_records[record.ordinal] if record.kind == DATA_KIND else entropy_records[record.ordinal]
        envelope.extend(struct.pack("<BHI", record.kind, record.ordinal, len(record_data)))
        envelope.extend(record_data)
    tag = hash_bytes(((info.seed ^ ENVELOPE_INTEGRITY_DOMAIN) * 31) & MASK32, envelope[:28] + envelope[32:])
    struct.pack_into("<I", envelope, 28, tag)
    return bytes(envelope)


def write_body_variant(info: PayloadInfo, output_dir: Path, name: str, body: bytes | bytearray) -> None:
    envelope = envelope_for_body(info, bytes(body))
    payload = build_outer_payload(info, envelope)
    (output_dir / f"payload-{name}.lua").write_text(replace_payload_literals(info, payload), "latin1")


def patch_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value & MASK32)


def write_tampered_variants(info: PayloadInfo, output_dir: Path) -> None:
    entropy_records = [record for record in info.records if record.kind == ENTROPY_KIND]
    if len(entropy_records) < 2:
        raise ValueError("not enough entropy records for tamper variants")
    changed = bytearray(info.envelope)
    changed[entropy_records[0].start + 7] ^= 1
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
        (offset for offset, descriptor in enumerate(entry_block.descriptors) if descriptor & 1 == 0),
        None,
    )
    if normal_offset is None:
        raise ValueError("entry block has no normal instruction for column-consumption tamper")
    descriptor_frame_start, _ = entry_block.column_spans[0]
    descriptor_offset = descriptor_frame_start + 4 + normal_offset
    descriptor_mask = block_field_mask(
        entry_block.entry_state, entry_block.start_pc + normal_offset, 7, info.root
    )
    column_consumption_variant = bytearray(info.body)
    column_consumption_variant[descriptor_offset] = (1 ^ descriptor_mask) & 0xFF
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
    target_capsule = info.root.capsules[referenced - 1]
    capsule_variant[target_capsule.tag_offset] ^= 1
    for block in info.root.blocks:
        if referenced in block.references:
            patch_u32(capsule_variant, block.tag_offset, block_integrity(capsule_variant, info.root, block))
    patch_u32(capsule_variant, info.root.tag_offset, prototype_integrity(capsule_variant, info.root))
    write_body_variant(info, output_dir, "capsule-integrity", capsule_variant)


def count_prototypes(prototype: Prototype) -> int:
    return 1 + sum(count_prototypes(child) for child in prototype.children)


def count_blocks(prototype: Prototype) -> int:
    return len(prototype.blocks) + sum(count_blocks(child) for child in prototype.children)


def count_capsules(prototype: Prototype) -> int:
    return len(prototype.capsules) + sum(count_capsules(child) for child in prototype.children)


def collect_column_orders(prototype: Prototype) -> list[tuple[int, ...]]:
    return [tuple(block.column_order) for block in prototype.blocks] + [
        order for child in prototype.children for order in collect_column_orders(child)
    ]


def describe(info: PayloadInfo) -> str:
    column_orders = collect_column_orders(info.root)
    if len(column_orders) != count_blocks(info.root) or any(not order for order in column_orders):
        raise ValueError("column-role validation did not cover every block")
    return (
        f"PASS authenticated v4 payload: features={info.flags & 15}, "
        f"prototypes={count_prototypes(info.root)}, blocks={count_blocks(info.root)}, "
        f"column_layouts={len(set(column_orders))}, capsules={count_capsules(info.root)}, entropy={info.entropy_length} bytes, "
        f"records={len(info.records)}, H={info.shannon_entropy:.4f} bits/byte, "
        f"entropy_sha256={hashlib.sha256(info.entropy).hexdigest()}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--compare", type=Path, help="verify a second generation has independent entropy")
    parser.add_argument("--tamper-dir", type=Path, help="write authenticated outer/envelope and v4 manifest tamper variants")
    args = parser.parse_args()
    try:
        info = parse_and_verify(args.generated)
        print(describe(info))
        if args.compare:
            other = parse_and_verify(args.compare)
            print(describe(other))
            if info.entropy == other.entropy or info.entropy_digest == other.entropy_digest or info.nonce == other.nonce:
                raise ValueError("independent generations reused entropy state")
            print("PASS independent entropy across generations")
        if args.tamper_dir:
            write_tampered_variants(info, args.tamper_dir)
            print(f"PASS wrote entropy and v4 manifest tamper variants to {args.tamper_dir}")
    except (OSError, ValueError, struct.error, StopIteration) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
