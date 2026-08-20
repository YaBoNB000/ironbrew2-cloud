#!/usr/bin/env python3
"""Verify permanent global print/error/warn no-op installation wiring."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only

IDENT = r"[A-Za-z_]\w*"


def verify(vm_path: Path, final_path: Path | None) -> None:
    source = vm_path.read_text("latin1")
    code = _code_only(source)

    noops = list(re.finditer(
        rf"local\s+({IDENT})\s*=\s*function\s*\(\s*\.\.\.\s*\)\s*return\s+nil\s*;?\s*end\s*;",
        code,
    ))
    candidates: list[tuple[str, str, str, tuple[str, str, str]]] = []
    for noop in noops:
        name = noop.group(1)
        pattern = re.compile(
            rf"({IDENT})\s*\(\s*({IDENT})\s*,\s*({IDENT})\s*,\s*{re.escape(name)}\s*\)\s*;\s*"
            rf"\1\s*\(\s*\2\s*,\s*({IDENT})\s*,\s*{re.escape(name)}\s*\)\s*;\s*"
            rf"\1\s*\(\s*\2\s*,\s*({IDENT})\s*,\s*{re.escape(name)}\s*\)\s*;",
            re.S,
        )
        match = pattern.search(code[noop.end():])
        if match:
            candidates.append((name, match.group(1), match.group(2), (match.group(3), match.group(4), match.group(5))))
    if len(candidates) != 1:
        raise ValueError(f"expected one three-key global no-op installer, found {len(candidates)}")
    noop, raw_setter, target, keys = candidates[0]
    if len(set(keys)) != 3:
        raise ValueError("print/error/warn keys do not use three independent derived strings")

    # Installation must cover a getgenv result and the thread/_G environment,
    # while deduplicating aliases by identity before mutation.
    installer = re.search(
        rf"local\s+function\s+({IDENT})\s*\(\s*{re.escape(target)}\s*\)"
        rf"(?P<body>.*?{re.escape(raw_setter)}\s*\(\s*{re.escape(target)}\s*,\s*{re.escape(keys[2])}\s*,\s*{re.escape(noop)}\s*\)\s*;\s*end\s*;)",
        code,
        re.S,
    )
    if not installer:
        raise ValueError("global no-op target installer was not found")
    installer_name = installer.group(1)
    body = installer.group("body")
    if not re.search(rf"for\s+{IDENT}\s*=\s*1\s*,\s*#{IDENT}\s+do", body):
        raise ValueError("global environment aliases are not deduplicated")
    if not re.search(rf"if\s+{IDENT}\s*\(.*?{re.escape(target)}.*?\)\s*then\s+return", body, re.S):
        raise ValueError("global environment deduplication does not use identity comparison")
    tail = code[installer.end():]
    if len(re.findall(rf"\b{re.escape(installer_name)}\s*\(", tail)) < 3:
        raise ValueError("getgenv, _G and thread environments are not all installed")
    if not re.search(rf"{IDENT}\s*\(\s*{IDENT}\s*\)\s*;.*?{re.escape(installer_name)}", tail, re.S):
        raise ValueError("getgenv target is not protected by a captured call boundary")

    combined_raw = source + "\n" + (final_path.read_text("latin1") if final_path else "")
    if re.search(r"['\"](?:print|error|warn)['\"]", combined_raw):
        raise ValueError("a plaintext disabled-global key leaked")
    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\bDisabled(?:Global(?:Function|Environment|Targets|Index|Candidate)|PrintKey|ErrorKey|WarnKey|GetGenV(?:Key|OK)?|RootKey)|DisableGlobalTarget\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable disabled-global identifier leaked: {leaked.group(0)}")

    print("PASS global no-op wiring: targets=getgenv/_G/thread, keys=char-derived, aliases=deduplicated")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
