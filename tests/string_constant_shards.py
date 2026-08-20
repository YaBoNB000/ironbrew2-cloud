#!/usr/bin/env python3
"""Verify string capsules contain shuffled inner-masked shards, not plaintext."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v4_payload as payload
from runtime_layout import _code_only
from static_attack_baseline import decode_constant, prototypes


def verify(generated: Path, generated_vm: Path | None, require_chain: bool = False) -> None:
    info = payload.parse_and_verify(generated)
    strings = 0
    multi_shard = 0
    shard_counts: set[int] = set()
    chained_strings = 0
    for _, proto in prototypes(info.root):
        tags = payload.derive_permutation(
            4, proto.k1, proto.k2, proto.k3, payload.CONSTANT_TAG_DOMAIN
        )
        for capsule in proto.capsules:
            encoded = info.body[capsule.encoded_start:capsule.end]
            raw = payload.stream_xor(
                encoded, payload.constant_mask_state(capsule.index, proto, capsule)
            )
            if tags.index(raw[0]) != 3:
                continue
            strings += 1
            decoded, shard_count = payload.decode_string_shards(raw, capsule.index, proto, capsule)
            owner = next(
                block for block in proto.blocks
                if block.start_pc == capsule.block_start and block.entry_state == capsule.entry_state
            )
            initial_chain = payload.begin_constant_chain(proto, owner)
            if capsule.chain_state != initial_chain:
                independent_capsule = replace(capsule, chain_state=initial_chain)
                independent, _ = payload.decode_string_shards(raw, capsule.index, proto, independent_capsule)
                if independent == decoded:
                    raise ValueError("a chained string still decodes from its capsule independently")
                chained_strings += 1
            shard_counts.add(shard_count)
            if len(decoded) > 1:
                multi_shard += 1
                if shard_count < 2:
                    raise ValueError("a multi-byte string was not split into shards")

            length = struct.unpack_from("<I", raw, 1)[0]
            order = payload.derive_permutation(
                shard_count, proto.k1, proto.k2, proto.k3,
                (payload.CONSTANT_MASK_DOMAIN + 0x9E3779B9) & payload.MASK32,
            )
            cursor = 6
            inner_encoded = bytearray()
            for logical_shard in order:
                shard_length = struct.unpack_from("<I", raw, cursor)[0]
                cursor += 4
                expected = len(range(logical_shard, length, shard_count))
                if shard_length != expected:
                    raise ValueError("string shard framing is inconsistent")
                inner_encoded.extend(raw[cursor:cursor + shard_length])
                cursor += shard_length
            if cursor != len(raw):
                raise ValueError("string shard payload was not consumed exactly")
            if len(decoded) >= 4 and decoded in bytes(inner_encoded):
                raise ValueError("a complete plaintext string survived inside its capsule shards")

            kind, recovered = decode_constant(info, proto, capsule)
            expected_kind = "string"
            try:
                expected_value = decoded.decode("utf-8")
            except UnicodeDecodeError:
                expected_kind, expected_value = "binary-string", decoded.hex()
            if (kind, recovered) != (expected_kind, expected_value):
                raise ValueError("adapted final-file attacker did not reconstruct sharded string")

    if strings == 0 or multi_shard == 0:
        raise ValueError("fixture did not exercise multi-shard string constants")
    if require_chain and chained_strings == 0:
        raise ValueError("fixture did not exercise cross-capsule chained strings")

    if generated_vm:
        code = _code_only(generated_vm.read_text("latin1"))
        final_code = _code_only(generated.read_text("latin1"))
        leaked = re.search(
            r"\b(?:StringShardState|BeginConstantChain|AdvanceConstantChain|ConstantChainState|StringParts|Shard(?:Count|Order|Index|Offset|Length|Position|Byte)|ExpectedShardLength)\b",
            code + "\n" + final_code,
        )
        if leaked:
            raise ValueError(f"stable string-shard identifier leaked: {leaked.group(0)}")

    print(
        "PASS sharded string capsules: "
        f"strings={strings}, multi-shard={multi_shard}, chained={chained_strings}, "
        f"shard-counts={sorted(shard_counts)}, outer-unmask=inner-ciphertext"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("generated_vm", type=Path, nargs="?")
    parser.add_argument("--require-chain", action="store_true")
    args = parser.parse_args()
    try:
        verify(args.generated, args.generated_vm, args.require_chain)
    except (OSError, ValueError, IndexError, struct.error) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
