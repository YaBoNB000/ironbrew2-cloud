#!/usr/bin/env python3
"""Reject stable/plaintext runtime-primitive bootstrap signatures.

The generated, pre-minified VM is inspected because it preserves enough syntax to
separate the primitive descriptor vault from the later anti-dump vault. Resolver
profiles are read from the corresponding build logs so multi-build topology and
first-resolution-order diversity are checked alongside emitted source.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path


DIRECT_MEMBER = re.compile(
    r"\b(?:string|table|math)\s*\.\s*"
    r"(?:byte|char|sub|concat|insert|ldexp|unpack)\b"
)
PLAIN_KEY = re.compile(
    r"([\"'])(?:byte|char|sub|concat|insert|ldexp|getfenv|setmetatable|"
    r"getmetatable|rawget|rawset|rawequal|unpack)\1"
)
PROFILE = re.compile(
    r"Primitive resolver: bootstrap=(\d+); vault=(\d+); topology=(\d+); "
    r"keys=(\d+); order=([0-9a-f]{8})\."
)
DESCRIPTOR = re.compile(
    r"\b([A-Za-z_]\w*)\[(\d+)\]=\{(\d+),(\d+),(\d+)\};"
)
BARE_FORBIDDEN = (
    "string", "table", "math", "debug", "unpack", "rawget", "rawset",
    "rawequal", "setmetatable", "getmetatable", "pcall", "tostring",
    "tonumber", "select",
)


def strip_short_strings(source: str) -> str:
    """Blank Lua short strings while retaining source offsets and newlines."""
    chars = list(source)
    index = 0
    while index < len(chars):
        quote = chars[index]
        if quote not in ("'", '"'):
            index += 1
            continue
        chars[index] = " "
        index += 1
        while index < len(chars):
            current = chars[index]
            if current == "\\":
                chars[index] = " "
                if index + 1 < len(chars) and chars[index + 1] != "\n":
                    chars[index + 1] = " "
                index += 2
                continue
            chars[index] = "\n" if current == "\n" else " "
            index += 1
            if current == quote:
                break
    return "".join(chars)


def inspect_source(path: Path, expected_keys: int) -> str:
    source = path.read_text("latin1")
    if DIRECT_MEMBER.search(source):
        raise SystemExit(f"{path}: direct string/table/math primitive member remains")
    if PLAIN_KEY.search(source):
        raise SystemExit(f"{path}: plaintext primitive lookup key remains")

    # All large payload literals occur later. The first 20 KiB contains the
    # layered bootstrap and the beginning of the anti-dump guard on all audited
    # layouts, so bare identifiers here expose a real resolver path, not data.
    prefix = strip_short_strings(source[:20000])
    for name in BARE_FORBIDDEN:
        if re.search(rf"(?<![A-Za-z0-9_]){name}(?![A-Za-z0-9_])", prefix):
            raise SystemExit(f"{path}: bare primitive root {name!r} remains in prefix")
    getfenv_count = len(re.findall(r"(?<![A-Za-z0-9_])getfenv(?![A-Za-z0-9_])", prefix))
    if getfenv_count != 1:
        raise SystemExit(
            f"{path}: expected exactly one minimal getfenv anchor, found {getfenv_count}"
        )

    descriptors = DESCRIPTOR.findall(source[:20000])
    if len(descriptors) < expected_keys:
        raise SystemExit(
            f"{path}: primitive vault has only {len(descriptors)} visible descriptors; "
            f"expected {expected_keys}"
        )
    # The primitive vault is first. Include token and physical layout so both
    # descriptor emission order and byte placement contribute to the profile.
    primitive_descriptors = descriptors[:expected_keys]
    return hashlib.sha256(repr(primitive_descriptors).encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "build",
        nargs="+",
        help="pre-minified-vm.lua:obfuscator.log",
    )
    args = parser.parse_args()

    profiles: list[tuple[int, int, int, int, str]] = []
    descriptor_profiles: list[str] = []
    for item in args.build:
        try:
            vm_name, log_name = item.rsplit(":", 1)
        except ValueError as error:
            raise SystemExit(f"invalid build pair: {item}") from error
        vm_path = Path(vm_name)
        log_path = Path(log_name)
        match = PROFILE.search(log_path.read_text("utf-8", errors="replace"))
        if not match:
            raise SystemExit(f"{log_path}: missing primitive resolver profile")
        profile = (
            int(match.group(1)), int(match.group(2)), int(match.group(3)),
            int(match.group(4)), match.group(5),
        )
        profiles.append(profile)
        descriptor_profiles.append(inspect_source(vm_path, profile[3]))

    if len(set(descriptor_profiles)) != len(descriptor_profiles):
        raise SystemExit("primitive descriptor order/layout repeated across builds")
    orders = [profile[4] for profile in profiles]
    if len(set(orders)) != len(orders):
        raise SystemExit("primitive first-resolution-order signature repeated across builds")
    combined = {(profile[0], profile[1], profile[2]) for profile in profiles}
    if len(profiles) >= 2 and len(combined) < 2:
        raise SystemExit("primitive bootstrap/resolver topology did not vary")
    if len(profiles) >= 10:
        labels = ("bootstrap", "vault", "resolver")
        for offset, label in enumerate(labels):
            if len({profile[offset] for profile in profiles}) < 2:
                raise SystemExit(f"primitive {label} topology did not vary")

    print(
        "PASS primitive bootstrap "
        f"builds={len(profiles)} descriptor_profiles={len(set(descriptor_profiles))} "
        f"orders={len(set(orders))} topologies={len(combined)}"
    )


if __name__ == "__main__":
    main()
