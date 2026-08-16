#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOTNET=${DOTNET:-$(command -v dotnet || true)}
LUA=${LUA:-$(command -v lua5.1 || command -v lua || true)}
LUAC=${LUAC:-$(command -v luac5.1 || command -v luac || true)}
RANDOM_RUNS=${IB2_RANDOM_RUNS:-20}

if [[ -z "$DOTNET" || -z "$LUA" || -z "$LUAC" ]]; then
    echo "This suite requires .NET 8, lua 5.1 and luac 5.1." >&2
    echo "Override discovery with DOTNET=..., LUA=... and LUAC=...." >&2
    exit 2
fi

if ! "$LUA" -e 'assert(_VERSION == "Lua 5.1", _VERSION)' >/dev/null; then
    echo "LUA must point to Lua 5.1." >&2
    exit 2
fi

export PATH="$(dirname "$DOTNET"):$(dirname "$LUA"):$(dirname "$LUAC"):$PATH"
export DOTNET_CLI_HOME=${DOTNET_CLI_HOME:-/tmp/ib2-dotnet-home}
export NUGET_PACKAGES=${NUGET_PACKAGES:-/tmp/ib2-nuget}
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1

WORK=$(mktemp -d /tmp/ib2-tests.XXXXXX)
cleanup() {
    rm -rf "$WORK" "$ROOT/temp" "$ROOT/out.lua" "$ROOT/luac.out"
}
trap cleanup EXIT

cd "$ROOT"
"$DOTNET" build "IronBrew2 CLI/IronBrew2 CLI.csproj" -c Release --nologo >/dev/null
CLI="$ROOT/IronBrew2 CLI/bin/Release/net8.0/IronBrew2 CLI.dll"
"$DOTNET" run --project tests/cfg_regression/cfg_regression.csproj --configuration Debug --nologo
"$LUA" tests/semantic.lua > "$WORK/baseline.out"

obfuscate() {
    local output=$1
    rm -rf temp out.lua
    "$DOTNET" "$CLI" tests/semantic.lua > "$WORK/obfuscator.log"
    mv out.lua "$output"
    "$LUAC" -p "$output"
}

run_executor() {
    "$LUA" tests/executor_runner.lua trusted "$1"
}

run_executor_mode() {
    local mode=$1
    local script=$2
    "$LUA" tests/executor_runner.lua "$mode" "$script"
}

obfuscate "$WORK/fixed.lua"
cp "$ROOT/temp/t2.lua" "$WORK/fixed-vm.lua"
python3 tests/verify_v4_payload.py "$WORK/fixed.lua"
python3 tests/runtime_layout.py "$WORK/fixed-vm.lua"
run_executor "$WORK/fixed.lua" > "$WORK/fixed.out"
cmp "$WORK/baseline.out" "$WORK/fixed.out"
echo "PASS single fixed configuration"

# Every generation must carry 64–96 KiB of independently generated high-entropy
# records. The verifier authenticates the envelope, restores its real body and
# checks record interleaving, entropy and state-derived inner masking.
obfuscate "$WORK/entropy-second.lua"
python3 tests/verify_v4_payload.py "$WORK/fixed.lua" --compare "$WORK/entropy-second.lua" --tamper-dir "$WORK"
python3 tests/runtime_layout.py "$WORK/fixed-vm.lua" --compare "$ROOT/temp/t2.lua"
run_executor "$WORK/entropy-second.lua" > "$WORK/entropy-second.out"
cmp "$WORK/baseline.out" "$WORK/entropy-second.out"
for entropy_case in modify delete reorder; do
    entropy_file="$WORK/entropy-$entropy_case.lua"
    "$LUAC" -p "$entropy_file"
    set +e
    run_executor "$entropy_file" > "$WORK/entropy-$entropy_case.stdout" 2> "$WORK/entropy-$entropy_case.stderr"
    entropy_code=$?
    set -e
    [[ $entropy_code -ne 0 ]]
    grep -Fq 'invalid protected payload' "$WORK/entropy-$entropy_case.stderr"
done
echo "PASS entropy record modification, deletion and reordering rejection after outer-tag recomputation"

# Rebuild every outer/envelope layer around deliberately damaged v4 internals.
# Each case leaves exactly the named prototype, complete block-manifest,
# authenticated column parser/consumption, or capsule-integrity layer as the
# first rejecting boundary.
for payload_case in prototype-tag block-manifest column-framing column-consumption capsule-integrity; do
    payload_file="$WORK/payload-$payload_case.lua"
    "$LUAC" -p "$payload_file"
    set +e
    run_executor "$payload_file" > "$WORK/payload-$payload_case.stdout" 2> "$WORK/payload-$payload_case.stderr"
    payload_code=$?
    set -e
    [[ $payload_code -ne 0 ]]
    grep -Fq 'invalid protected payload' "$WORK/payload-$payload_case.stderr"
done
echo "PASS v4 prototype, block-manifest, column framing/consumption and constant-capsule tamper rejection"

# The trusted test executor must pass every retained hard-AND behavior contract.
# Compatibility paths model proxy-backed globals, empty C-upvalue results and
# alternate inactive-proto representations. The removed-root-contracts mode
# reproduces all six real-executor compatibility failures removed from the gate:
# hidden random constants/upvalues, no observable interim setupvalue mutation,
# wrong callable inactive results and a wrong activated-proto result.
for mode in trusted no-alias compat-representations callable-proto wrong-callable-proto removed-root-contracts; do
    run_executor_mode "$mode" "$WORK/fixed.lua" > "$WORK/executor-$mode.out"
    cmp "$WORK/baseline.out" "$WORK/executor-$mode.out"
done

# The standalone sink checker evaluates every retained production condition
# without entering the sink itself, prints only triggering conditions and keeps
# a dynamic summary. All six removed root contracts must be absent from its
# record set and from transcript/token/seal evidence.
removed_sink_checks=(
    constants.contains-random-value
    upvalues.contains-random-value
    upvalues.changed-value
    proto.getproto-inactive-contract
    proto.getproto-active-result
    proto.getprotos-inactive-contract
)
for check in "${removed_sink_checks[@]}"; do
    ! grep -Fq "$check" tools/executor_sink_trigger_check.lua
done
for mode in trusted callable-proto compat-representations wrong-callable-proto removed-root-contracts; do
    "$LUA" tests/executor_runner.lua "$mode" tools/executor_sink_trigger_check.lua \
        > "$WORK/sink-check-$mode.out"
    ! grep -q '^\[会触发静默 sink\]' "$WORK/sink-check-$mode.out"
    ! grep -q '^\[不会触发静默 sink\]' "$WORK/sink-check-$mode.out"
    grep -q '^逐项汇总: 不会触发静默 sink: 162 会触发静默 sink: 0$' \
        "$WORK/sink-check-$mode.out"
    grep -q '^综合结论: 当前环境不会因上述 executor gate 条件进入静默 sink$' \
        "$WORK/sink-check-$mode.out"
done
echo "PASS standalone sink-trigger checker and six removed root contracts"

set +e
timeout 1s "$LUA" "$WORK/fixed.lua" > "$WORK/executor-plain.stdout" 2> "$WORK/executor-plain.stderr"
plain_code=$?
set -e
[[ $plain_code -eq 124 ]]
[[ ! -s "$WORK/executor-plain.stdout" && ! -s "$WORK/executor-plain.stderr" ]]

# With the temporary bypass disabled, ordinary Lua and every retained
# executor-contract failure must remain in the silent non-yielding sink until
# the external timeout kills the process. The sink itself emits no output.
for mode in primitive-hook raw-hook debug-api-hook classifier-spoof identity-spoof version-number missing-debug polluted-genv invalid-load c-debug-leak c-upvalue-leak; do
    set +e
    timeout 1s "$LUA" tests/executor_runner.lua "$mode" "$WORK/fixed.lua" \
        > "$WORK/executor-$mode.stdout" 2> "$WORK/executor-$mode.stderr"
    sink_code=$?
    set -e
    [[ $sink_code -eq 124 ]]
    [[ ! -s "$WORK/executor-$mode.stdout" && ! -s "$WORK/executor-$mode.stderr" ]]
done
set +e
timeout 5s "$LUA" tests/executor_runner.lua canary-error "$WORK/fixed.lua" \
    > "$WORK/executor-canary-error.stdout" 2> "$WORK/executor-canary-error.stderr"
canary_code=$?
set -e
[[ $canary_code -eq 42 ]]
[[ ! -s "$WORK/executor-canary-error.stdout" && ! -s "$WORK/executor-canary-error.stderr" ]]
echo "PASS strict executor detection, silent sink enforcement and challenge cleanup"

# Verify the unminified generated VM contains all three guard checkpoints and
# that stable implementation identifiers do not survive name randomization.
python3 - "$ROOT/temp/t2.lua" "$WORK/fixed.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
final_source = Path(sys.argv[2]).read_text("latin1")
root = re.search(
    r"local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*"
    r"if\s+([A-Za-z_]\w*)\(true\)\s+then\s+[^\n]*return\s+([A-Za-z_]\w*)\(\);\s*end;",
    source,
)
if not root:
    raise SystemExit("post-deserialize forced guard/sink call not found")
probe = root.group(2)
if not re.search(r"local\s+function\s+" + re.escape(probe) + r"\s*\(", source):
    raise SystemExit("guard definition not found")
if len(re.findall(r"\b" + re.escape(probe) + r"\s*\(true\)", source)) < 3:
    raise SystemExit("startup, post-deserialize and first-block forced guards are not all present")
if not re.search(r"\b" + re.escape(probe) + r"\s*\(false\)", source):
    raise SystemExit("periodic dispatch guard not found")
leaked = re.search(r"\bGuard[A-Za-z0-9_]*", source + "\n" + final_source)
if leaked:
    raise SystemExit("stable guard identifier leaked: " + leaked.group(0))
envelope_leak = re.search(r"\b(?:Payload|Envelope)[A-Z][A-Za-z0-9_]*", source + "\n" + final_source)
if envelope_leak:
    raise SystemExit("stable entropy-envelope identifier leaked: " + envelope_leak.group(0))
column_leak = re.search(r"\b(?:DeriveBlockPermutation|Column(?:Order|Positions|Read8|Read16|Read32|Data|Position))\b", source + "\n" + final_source)
if column_leak:
    raise SystemExit("stable columnar-IR identifier leaked: " + column_leak.group(0))
PY
echo "PASS guard, entropy-envelope and columnar-IR runtime identifiers are randomized"

# semantic.lua contains no IB_MAX_CFLOW markers. Assert that its root prototype
# was nevertheless selected and received a complete random route-state map.
python3 - "$ROOT/temp/t2.lua" "$WORK/automatic-dispatch.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
sys.path.insert(0, str(Path.cwd() / "tests"))
from runtime_layout import derive_runtime_layout
chunk_slots = derive_runtime_layout(source)["chunk"]
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"(?:if\s+[A-Za-z_]\w*\(true\)\s+then\s+[^\n]*?end;\s*)?"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = (
    "do local d=" + root + f"[{chunk_slots[13]}];local s=" + root + f"[{chunk_slots[14]}];"
    "assert(type(d)=='table' and type(s)=='number' and d[s]==1);"
    "local n=0;for _ in pairs(d) do n=n+1;end;assert(n>=2);end;\n"
)
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/automatic-dispatch.lua"
run_executor "$WORK/automatic-dispatch.lua" > "$WORK/automatic-dispatch.out"
cmp "$WORK/baseline.out" "$WORK/automatic-dispatch.out"
echo "PASS automatic dispatcher selection without source markers"

# A tiny straight-line prototype has no useful block transition to flatten. It
# must retain the ordinary PC path and contain no partial dispatcher metadata.
printf '%s\n' 'print(1 + 2)' > "$WORK/dispatcher-fallback.lua"
"$LUA" "$WORK/dispatcher-fallback.lua" > "$WORK/dispatcher-fallback-baseline.out"
rm -rf temp out.lua
"$DOTNET" "$CLI" "$WORK/dispatcher-fallback.lua" > "$WORK/dispatcher-fallback-build.log"
mv out.lua "$WORK/dispatcher-fallback-obfuscated.lua"
python3 - "$ROOT/temp/t2.lua" "$WORK/dispatcher-fallback-instrumented.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
sys.path.insert(0, str(Path.cwd() / "tests"))
from runtime_layout import derive_runtime_layout
chunk_slots = derive_runtime_layout(source)["chunk"]
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"(?:if\s+[A-Za-z_]\w*\(true\)\s+then\s+[^\n]*?end;\s*)?"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = "assert(" + root + f"[{chunk_slots[13]}]==nil and " + root + f"[{chunk_slots[14]}]==nil);\n"
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/dispatcher-fallback-obfuscated.lua"
"$LUAC" -p "$WORK/dispatcher-fallback-instrumented.lua"
run_executor "$WORK/dispatcher-fallback-instrumented.lua" > "$WORK/dispatcher-fallback.out"
cmp "$WORK/dispatcher-fallback-baseline.out" "$WORK/dispatcher-fallback.out"
echo "PASS unsupported dispatcher shape falls back without partial metadata"

# Repeat randomized prototype keys, opcode maps and schema orders.
for ((i = 1; i <= RANDOM_RUNS; i++)); do
    obfuscate "$WORK/random.lua"
    python3 tests/runtime_layout.py "$ROOT/temp/t2.lua" > "$WORK/runtime-layout-$i.out"
    run_executor "$WORK/random.lua" > "$WORK/random.out"
    cmp -s "$WORK/baseline.out" "$WORK/random.out"
done
echo "PASS randomized opcode handlers and non-identity runtime layouts: $RANDOM_RUNS/$RANDOM_RUNS"

# Tamper with v4's invocation-local flow metadata only after the outer payload
# has been authenticated and deserialized. These probes target the unminified
# generated VM so each rejection is attributable to block/flow validation, not
# to the top-level encrypted-payload checksum.
python3 - "$ROOT/temp/t2.lua" "$WORK" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
out_dir = Path(sys.argv[2])
sys.path.insert(0, str(Path.cwd() / "tests"))
from runtime_layout import derive_runtime_layout
layout = derive_runtime_layout(source)
chunk_slots = layout["chunk"]
block_slots = layout["block"]
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"(?:if\s+[A-Za-z_]\w*\(true\)\s+then\s+[^\n]*?end;\s*)?"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)

blocks_slot = chunk_slots[9]
initial_state_slot = chunk_slots[12]
initial_route_slot = chunk_slots[14]
block_start_slot = block_slots[1]
block_body_slot = block_slots[3]
block_successors_slot = block_slots[5]
find_entry = (
    "do local b;for _,v in pairs(" + root + f"[{blocks_slot}]) do "
    f"if v[{block_start_slot}]==1 then b=v;break;end;end;"
)
probes = {
    "block-body": (
        find_entry
        + f"assert(b and type(b[{block_body_slot}])=='string' and #b[{block_body_slot}]>0);"
        + f"b[{block_body_slot}]=string.char((string.byte(b[{block_body_slot}],1)+1)%256).."
          f"string.sub(b[{block_body_slot}],2);end;\n"
    ),
    "initial-state": root + f"[{initial_state_slot}]=(" + root + f"[{initial_state_slot}]+1)%4294967296;\n",
    "dispatcher-state": root + f"[{initial_route_slot}]=1;\n",
    "missing-edge": (
        find_entry
        + f"assert(b and next(b[{block_successors_slot}]));b[{block_successors_slot}]={{}};end;\n"
    ),
    "wrapped-edge-state": (
        find_entry
        + f"assert(b);local changed=false;for k,v in pairs(b[{block_successors_slot}]) do "
          f"b[{block_successors_slot}][k]=(v+1)%4294967296;changed=true;break;end;"
          "assert(changed);end;\n"
    ),
}
for name, probe in probes.items():
    modified = source[:match.end(1)] + probe + source[match.end(1):]
    (out_dir / ("flow-" + name + ".lua")).write_text(modified, "latin1")
PY
for flow_case in block-body initial-state dispatcher-state missing-edge wrapped-edge-state; do
    flow_file="$WORK/flow-$flow_case.lua"
    "$LUAC" -p "$flow_file"
    set +e
    run_executor "$flow_file" > "$WORK/flow-$flow_case.stdout" 2> "$WORK/flow-$flow_case.stderr"
    flow_code=$?
    set -e
    [[ $flow_code -ne 0 ]]
    grep -Fq 'invalid protected payload' "$WORK/flow-$flow_case.stderr"
done
echo "PASS block body and flow edge/state tamper rejection"

# Force a CLOSURE and its 30 pseudo upvalue-binding instructions across the
# 24-instruction page boundary. OpClosure must carry the same Flow state while
# fetching pseudo instructions in the next block.
"$LUA" tests/closure_boundary.lua > "$WORK/closure-boundary-baseline.out"
rm -rf temp out.lua
"$DOTNET" "$CLI" tests/closure_boundary.lua > "$WORK/closure-boundary-build.log"
mv out.lua "$WORK/closure-boundary.lua"
"$LUAC" -p "$WORK/closure-boundary.lua"
run_executor "$WORK/closure-boundary.lua" > "$WORK/closure-boundary.out"
cmp "$WORK/closure-boundary-baseline.out" "$WORK/closure-boundary.out"
echo "PASS Closure pseudo instructions across flow blocks"

# Verify AntiDump keeps block bodies opaque and materializes plaintext instructions
# only in the invocation-local Flow cache. The root prototype's shared instruction
# table must remain empty even while the first protected block is executing.
"$LUA" tests/lazy_blocks.lua > "$WORK/lazy-baseline.out"
rm -rf temp out.lua
"$DOTNET" "$CLI" tests/lazy_blocks.lua > "$WORK/lazy-build.log"
mv out.lua "$WORK/lazy.lua"
"$LUAC" -p "$WORK/lazy.lua"
run_executor "$WORK/lazy.lua" > "$WORK/lazy.out"
cmp "$WORK/lazy-baseline.out" "$WORK/lazy.out"
python3 - "$ROOT/temp/t2.lua" "$WORK/lazy-instrumented.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
sys.path.insert(0, str(Path.cwd() / "tests"))
from runtime_layout import derive_runtime_layout
layout = derive_runtime_layout(source)
chunk_slots = layout["chunk"]
block_slots = layout["block"]
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"(?:if\s+[A-Za-z_]\w*\(true\)\s+then\s+[^\n]*?end;\s*)?"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = (
    "_G.__ib2_lazy_opaque=function() "
    "assert(next(" + root + f"[{chunk_slots[1]}])==nil,'decoded instructions escaped invocation-local cache');"
    "local capsules=" + root + f"[{chunk_slots[15]}];assert(type(capsules)=='table');"
    "for _,capsule in pairs(capsules) do assert(type(capsule)=='string','plaintext constant escaped block-local cache');end;"
    "local n=0;local blocks=" + root + f"[{chunk_slots[9]}];"
    "if blocks then for _,block in pairs(blocks) do "
    f"if type(block[{block_slots[3]}])=='string' then n=n+1;end;end;end;"
    "return n;end;\n"
)
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/lazy-instrumented.lua"
run_executor "$WORK/lazy-instrumented.lua" > "$WORK/lazy-instrumented.out"
grep -Eq '^lazy-blocks:[1-9][0-9]*:executed-constant:37$' "$WORK/lazy-instrumented.out"
echo "PASS ephemeral instruction/constant cache and opaque block retention"

# Exercise Lua 5.1's SETLIST C == 0 data word without checking in a huge table
# constructor. A test-only luac wrapper patches the one-element fixture after
# source preprocessing and before IronBrew2 deserializes it.
mkdir -p "$WORK/setlist-bin"
cp "$ROOT/tests/luac_setlist_c0_wrapper.py" "$WORK/setlist-bin/luac"
chmod +x "$WORK/setlist-bin/luac"
printf '%s\n' 'local t={123}; print("setlist-c0:" .. t[1])' > "$WORK/setlist-c0.lua"
"$LUA" "$WORK/setlist-c0.lua" > "$WORK/setlist-c0-baseline.out"
rm -rf temp out.lua
IB2_REAL_LUAC="$LUAC" PATH="$WORK/setlist-bin:$PATH" \
    "$DOTNET" "$CLI" "$WORK/setlist-c0.lua" > "$WORK/setlist-c0-build.log"
mv out.lua "$WORK/setlist-c0-obfuscated.lua"
"$LUAC" -p "$WORK/setlist-c0-obfuscated.lua"
run_executor "$WORK/setlist-c0-obfuscated.lua" > "$WORK/setlist-c0-obfuscated.out"
cmp "$WORK/setlist-c0-baseline.out" "$WORK/setlist-c0-obfuscated.out"
echo "PASS SETLIST C=0 data-word semantics"

# The old tier selector must no longer be accepted.
rm -rf temp out.lua
set +e
"$DOTNET" "$CLI" tests/semantic.lua --strength mid > "$WORK/removed-tier.stdout" 2> "$WORK/removed-tier.stderr"
tier_code=$?
set -e
[[ $tier_code -eq 2 ]]
grep -Fq 'unknown option: --strength' "$WORK/removed-tier.stdout"
echo "PASS low/mid/high selector removed"

# PreserveLineInfo should report the original nested source line.
rm -rf temp out.lua
"$DOTNET" "$CLI" tests/line_error.lua --line-info > "$WORK/line-build.log"
mv out.lua "$WORK/line.lua"
"$LUAC" -p "$WORK/line.lua"
set +e
run_executor "$WORK/line.lua" > "$WORK/line.stdout" 2> "$WORK/line.stderr"
line_code=$?
set -e
[[ $line_code -ne 0 ]]
grep -q 'ERROR IN IRONBREW SCRIPT \[LINE 4\]' "$WORK/line.stderr"
echo "PASS nested line-info reporting"

# Simulate LuaJIT's signed 32-bit bit.bxor result.
run_executor_mode signed-bit "$WORK/fixed.lua" > "$WORK/signed-bit.out"
cmp "$WORK/baseline.out" "$WORK/signed-bit.out"
echo "PASS signed bit.bxor compatibility"

# Mutate one Base91 payload character while leaving valid Lua syntax.
python3 - "$WORK/fixed.lua" "$WORK/tampered.lua" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text("latin1")
literals = []
i = 0
while i < len(source):
    if source[i] in "'\"":
        quote = source[i]
        start = i
        i += 1
        while i < len(source):
            if source[i] == "\\":
                i += 2
                continue
            if source[i] == quote:
                literals.append((i - start + 1, start, i))
                i += 1
                break
            i += 1
    else:
        i += 1
_, start, end = max(literals)
for position in range(start + 20, end - 20):
    if source[position].isalnum() and source[position - 1] != "\\":
        replacement = "A" if source[position] != "A" else "B"
        source = source[:position] + replacement + source[position + 1:]
        break
else:
    raise SystemExit("could not find a safe payload mutation position")
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/tampered.lua"
set +e
run_executor "$WORK/tampered.lua" > "$WORK/tamper.stdout" 2> "$WORK/tamper.stderr"
tamper_code=$?
set -e
[[ $tamper_code -ne 0 ]]
grep -Fq 'invalid protected payload' "$WORK/tamper.stderr"
echo "PASS tamper detection"

if grep -aEq "[\"'](constants|nested|closure)[\"']|A\\\\000B" "$WORK/fixed.lua"; then
    echo "A semantic string literal leaked into generated output." >&2
    exit 1
fi
echo "PASS no test string literals visible in generated source"

echo "All IronBrew2 Linux tests passed."
