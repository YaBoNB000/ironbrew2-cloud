#!/usr/bin/env python3
"""Verify and test IronBrew2's authenticated v3 entropy envelope."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import struct
import sys
import zlib

MASK32 = 0xFFFFFFFF
INTEGRITY_DOMAIN = 0xA5C31F27
ENVELOPE_INTEGRITY_DOMAIN = 0xC4D29A6B
ENTROPY_DIGEST_DOMAIN = 0x91E10DA5
ENVELOPE_MASK_DOMAIN = 0x3A75C9EF
ENTROPY_KIND = 0xA7
DATA_KIND = 0x5C
ENTROPY_MIN = 64 * 1024
ENTROPY_MAX = 96 * 1024


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
    body: bytes
    entropy_length: int
    entropy_digest: int
    nonce: int
    shannon_entropy: float


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
    # The protected stream is split into 2–6 local literals. With the mandatory
    # entropy envelope every segment is much larger than any ordinary VM string.
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
        raise ValueError("decoded payload is shorter than the fixed v3 header")
    return candidates, payload


def hash_bytes(initial: int, data: bytes) -> int:
    value = initial & MASK32
    for item in data:
        value = (value * 31 + item) & MASK32
    return value


def stream_xor(data: bytes, seed: int) -> bytes:
    output = bytearray(len(data))
    state = seed
    for index, value in enumerate(data):
        output[index] = value ^ (state >> 24)
        state = (state * 1664525 + 1013904223) & MASK32
    return bytes(output)


def shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def parse_and_verify(path: Path) -> PayloadInfo:
    source = path.read_text("latin1")
    literals, payload = extract_payload(source)
    seed, stored_integrity = struct.unpack_from("<II", payload)
    flags = payload[8]
    version, features = flags >> 4, flags & 0x0F
    if version != 3:
        raise ValueError(f"expected payload version 3, found {version}")
    if features not in (14, 15):
        raise ValueError(f"unexpected v3 feature bits (block + dispatcher + entropy required): {features}")

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
        data = envelope[offset:end]
        offset = end
        destination = data_records if kind == DATA_KIND else entropy_records if kind == ENTROPY_KIND else None
        limit = data_count if kind == DATA_KIND else entropy_count
        if destination is None or not 1 <= ordinal <= limit or ordinal in destination:
            raise ValueError("invalid or duplicate entropy record ordinal")
        destination[ordinal] = data
        records.append(Record(start, end, kind, ordinal, data))
    if offset != len(envelope):
        raise ValueError("trailing or missing bytes in entropy envelope")
    if set(data_records) != set(range(1, data_count + 1)):
        raise ValueError("missing real-data record")
    if set(entropy_records) != set(range(1, entropy_count + 1)):
        raise ValueError("missing entropy record")
    if sum(map(len, data_records.values())) != real_length:
        raise ValueError("real-data record total mismatch")
    if sum(map(len, entropy_records.values())) != entropy_length:
        raise ValueError("entropy record total mismatch")

    transitions = sum(records[index - 1].kind != records[index].kind for index in range(1, len(records)))
    if transitions < 2:
        raise ValueError("data and entropy records are not interleaved")

    digest = ((seed ^ ENTROPY_DIGEST_DOMAIN) * 31 + nonce) & MASK32
    digest = (digest * 31 + entropy_length) & MASK32
    digest = (digest * 31 + entropy_count) & MASK32
    for ordinal in range(1, entropy_count + 1):
        record = entropy_records[ordinal]
        digest = (digest * 31 + ordinal) & MASK32
        digest = (digest * 31 + len(record)) & MASK32
        digest = hash_bytes(digest, record)
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

    entropy = b"".join(entropy_records[index] for index in range(1, entropy_count + 1))
    entropy_score = shannon_entropy(entropy)
    if entropy_score < 7.95:
        raise ValueError(f"entropy records are not high entropy enough: {entropy_score:.4f} bits/byte")

    return PayloadInfo(
        path=path,
        source=source,
        literals=literals,
        payload=payload,
        seed=seed,
        flags=flags,
        envelope=envelope,
        records=records,
        entropy=entropy,
        body=body,
        entropy_length=entropy_length,
        entropy_digest=entropy_digest,
        nonce=nonce,
        shannon_entropy=entropy_score,
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
        replacements.append(encoded[position : position + length])
        position += length
        remaining -= length
    if position != len(encoded):
        raise AssertionError("failed to split replacement base91 payload")

    source = info.source
    for literal, replacement in reversed(list(zip(info.literals, replacements))):
        source = source[: literal.content_start] + replacement + source[literal.content_end :]
    return source


def write_tampered_variants(info: PayloadInfo, output_dir: Path) -> None:
    entropy_records = [record for record in info.records if record.kind == ENTROPY_KIND]
    if len(entropy_records) < 2:
        raise ValueError("not enough entropy records for tamper variants")

    changed = bytearray(info.envelope)
    changed[entropy_records[0].start + 7] ^= 1

    removed = info.envelope[: entropy_records[0].start] + info.envelope[entropy_records[0].end :]

    first, second = info.records[0], info.records[1]
    reordered = (
        info.envelope[: first.start]
        + info.envelope[second.start : second.end]
        + info.envelope[first.start : first.end]
        + info.envelope[second.end :]
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    variants = {"modify": bytes(changed), "delete": removed, "reorder": reordered}
    for name, envelope in variants.items():
        payload = build_outer_payload(info, envelope)
        (output_dir / f"entropy-{name}.lua").write_text(replace_payload_literals(info, payload), "latin1")


def describe(info: PayloadInfo) -> str:
    return (
        f"PASS authenticated v3 entropy envelope: features={info.flags & 15}, "
        f"entropy={info.entropy_length} bytes, records={len(info.records)}, "
        f"H={info.shannon_entropy:.4f} bits/byte, "
        f"entropy_sha256={hashlib.sha256(info.entropy).hexdigest()}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--compare", type=Path, help="verify a second generation has independent entropy")
    parser.add_argument("--tamper-dir", type=Path, help="write outer-integrity-valid entropy tamper variants")
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
            print(f"PASS wrote authenticated-envelope tamper variants to {args.tamper_dir}")
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
