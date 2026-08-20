#!/usr/bin/env python3
"""Measure Phase 4 generation/execution while enforcing semantics and timeouts."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import statistics
import subprocess
import time


def timed(command: list[str], cwd: Path, timeout: float, expected: bytes | None = None) -> tuple[float, bytes]:
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            + completed.stderr.decode("utf-8", "replace")[-2000:]
        )
    if expected is not None and completed.stdout != expected:
        raise RuntimeError(f"output mismatch from {' '.join(command)}")
    return elapsed, completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--lua", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--payload-output", type=Path, required=True)
    parser.add_argument("--vm-output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    fixture = args.fixture.resolve()
    executor = root / "tests" / "executor_runner.lua"
    args.work.mkdir(parents=True, exist_ok=True)

    try:
        _duration, baseline_output = timed([args.lua, str(executor), "trusted", str(fixture)], root, 20)
        generation: list[float] = []
        for index in range(3):
            shutil.rmtree(root / "temp", ignore_errors=True)
            (root / "out.lua").unlink(missing_ok=True)
            duration, log = timed([args.dotnet, str(args.cli), str(fixture)], root, 30)
            generation.append(duration)
            (args.work / f"phase4-generation-{index + 1}.log").write_bytes(log)
            if not (root / "out.lua").is_file() or not (root / "temp" / "t2.lua").is_file():
                raise RuntimeError("obfuscator did not emit out.lua and temp/t2.lua")
        shutil.copy2(root / "out.lua", args.payload_output)
        shutil.copy2(root / "temp" / "t2.lua", args.vm_output)

        baseline: list[float] = []
        protected: list[float] = []
        # One untimed warm-up amortizes filesystem cache and process-loader noise.
        timed([args.lua, str(executor), "trusted", str(fixture)], root, 20, baseline_output)
        timed([args.lua, str(executor), "trusted", str(args.payload_output)], root, 20, baseline_output)
        for _ in range(5):
            baseline.append(timed([args.lua, str(executor), "trusted", str(fixture)], root, 20, baseline_output)[0])
        for _ in range(3):
            protected.append(timed([args.lua, str(executor), "trusted", str(args.payload_output)], root, 20, baseline_output)[0])

        generation_median = statistics.median(generation)
        baseline_median = statistics.median(baseline)
        protected_median = statistics.median(protected)
        ratio = protected_median / baseline_median
        stabilized_ratio = protected_median / max(baseline_median, 0.010)

        # Performance/size optimization is outside the current requirements.
        # Keep measurements for visibility, while subprocess timeouts and exact
        # output comparisons continue to catch hangs and semantic regressions.
        print(
            "PASS Phase 4 measured execution: "
            f"generation median={generation_median:.3f}s max={max(generation):.3f}s; "
            f"execution baseline={baseline_median:.4f}s protected={protected_median:.3f}s "
            f"ratio={ratio:.1f}x stabilized={stabilized_ratio:.1f}x"
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
