#!/usr/bin/env python3
"""Verify a high-value loader chain becomes one two-phase fused VM program."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from static_decompiler import analyze_decompiler
from verify_v4_payload import collect_fused_counts, count_instruction_records, parse_and_verify


def verify(generated: Path, build_log: Path) -> None:
    info = parse_and_verify(generated)
    fused = [count for count in collect_fused_counts(info.root) if count]
    physical = count_instruction_records(info.root)
    logical = physical + sum(fused)
    if physical != 2 or logical != 11 or fused != [9]:
        raise ValueError(
            f"loader chain did not lower to one 10-member record plus RETURN: "
            f"physical/logical={physical}/{logical}, fused={fused}"
        )

    profile = re.search(
        r"Call-inclusive fusion: templates=(\d+); folded=(\d+); max-width=(\d+)\.",
        build_log.read_text("utf-8", errors="replace"),
    )
    if not profile or tuple(map(int, profile.groups())) != (1, 1, 10):
        raise ValueError(f"unexpected call-inclusive build profile: {profile.group(0) if profile else None}")
    phases = re.search(
        r"Fused member tokens: operators=(\d+); members=(\d+); phases=(\d+); signature=([0-9a-f]{8})\.",
        build_log.read_text("utf-8", errors="replace"),
    )
    if (not phases or int(phases.group(1)) < 1 or int(phases.group(2)) < 10
            or int(phases.group(3)) != int(phases.group(2)) * 2):
        raise ValueError("loader chain is not backed by complete select/execute phase pairs")

    # Keep the adapted attacker current: success here demonstrates that the new
    # VM raises analysis cost rather than being mistaken for client-side secrecy.
    report = analyze_decompiler(generated)
    rendered = "\n".join(report.rendered)
    markers = (
        '_ENV.getgenv()["SCRIPT_KEY"]="fixture-key"',
        ':HttpGet("https://example.invalid/vm-chain")',
        "_ENV.loadstring(",
        "results=discard",
    )
    missing = [marker for marker in markers if marker not in rendered]
    if missing:
        raise ValueError(f"adapted final-output attacker missed fused loader data flow: {missing}")
    if (report.calls, report.self_calls, report.table_writes,
            report.discarded_calls, report.returns) != (4, 1, 1, 1, 1):
        raise ValueError("fused loader semantic counts are incomplete")

    print(
        "PASS call-inclusive two-phase fusion: "
        f"physical/logical={physical}/{logical}, members=10, phases=20, "
        f"operand-slots=shuffled, attacker-classified={report.classified_instructions}/{report.logical_instructions}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--build-log", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.generated, args.build_log)
    except (OSError, ValueError, IndexError, KeyError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
