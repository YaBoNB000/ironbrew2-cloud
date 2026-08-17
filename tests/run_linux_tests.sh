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
python3 tests/build_seed_wiring.py
"$LUA" tests/semantic.lua > "$WORK/baseline.out"

obfuscate() {
    local output=$1
    rm -rf temp out.lua
    "$DOTNET" "$CLI" tests/semantic.lua > "$WORK/obfuscator.log"
    mv out.lua "$output"
    "$LUAC" -p "$output"
    if LC_ALL=C grep -aFq 'invalid protected payload' "$output"; then
        echo "Stable protected-payload diagnostic leaked into $output." >&2
        exit 1
    fi
}

run_executor() {
    "$LUA" tests/executor_runner.lua trusted "$1"
}

run_executor_mode() {
    local mode=$1
    local script=$2
    "$LUA" tests/executor_runner.lua "$mode" "$script"
}

assert_payload_rejected() {
    local exit_code=$1
    local stdout_file=$2
    local stderr_file=$3
    local label=$4
    if [[ $exit_code -eq 0 ]]; then
        echo "$label unexpectedly executed successfully." >&2
        exit 1
    fi
    if cmp -s "$WORK/baseline.out" "$stdout_file"; then
        echo "$label emitted the complete protected payload output before rejection." >&2
        exit 1
    fi
    if LC_ALL=C grep -aFq 'invalid protected payload' "$stderr_file"; then
        echo "$label leaked the stable protected-payload diagnostic." >&2
        exit 1
    fi
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
    assert_payload_rejected "$entropy_code" "$WORK/entropy-$entropy_case.stdout" \
        "$WORK/entropy-$entropy_case.stderr" "entropy $entropy_case tamper"
done
echo "PASS entropy record modification, deletion and reordering rejection after outer-tag recomputation"

# Rebuild every outer/envelope layer around deliberately damaged v4 internals.
# Each case leaves exactly the named prototype, complete block-manifest,
# authenticated instruction-record parser/consumption, or block-local
# capsule-integrity layer as the first rejecting boundary.
for payload_case in prototype-tag initial-chunk-state successor-chunk-state block-manifest column-framing column-consumption capsule-integrity; do
    payload_file="$WORK/payload-$payload_case.lua"
    "$LUAC" -p "$payload_file"
    set +e
    run_executor "$payload_file" > "$WORK/payload-$payload_case.stdout" 2> "$WORK/payload-$payload_case.stderr"
    payload_code=$?
    set -e
    assert_payload_rejected "$payload_code" "$WORK/payload-$payload_case.stdout" \
        "$WORK/payload-$payload_case.stderr" "v4 $payload_case tamper"
done
echo "PASS v4 prototype, attested chunk-chain, block-manifest, record framing/consumption and block-local capsule tamper rejection"

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
stream_leak = re.search(
    r"\b(?:DeriveBlockPermutation|DeriveCodeDataPermutation|Column(?:Order|Positions|Read8|Read16|Read32|Data|Position)|"
    r"Fragment(?:Order|Spans|Count|State)|Instruction(?:Digest|State|Seal)|BeginInstructionState|AdvanceInstructionState|"
    r"OpcodeState(?:Key|Seal)?|BeginOpcodeState|AdvanceOpcodeState|PreviousOpcodeState|CurrentOpcode(?:State|Seal)|"
    r"CipherByte|KeyByte|LengthOffset|EncodedIndex|Pipeline(?:State|Index)|TransformedByte|InstrPoint|Inst|GetInstruction)\b",
    source + "\n" + final_source,
)
if stream_leak:
    raise SystemExit("stable streaming/opcode/pipeline identifier leaked: " + stream_leak.group(0))
PY
echo "PASS guard, entropy-envelope and streaming-record runtime identifiers are randomized"

# Mutate the private payload-chain state immediately after its first successful
# instruction bind. The next GuardProbe must notice the broken payload seal and
# enter the configured non-yielding sticky sink before any protected output.
python3 - "$WORK/fixed-vm.lua" "$WORK/guard-payload-state-tamper.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
ident = r"[A-Za-z_]\w*"
calls = list(re.finditer(
    rf"if\s+({ident})\(\s*({ident})\s*,\s*({ident})\s*,\s*({ident})\s*,\s*({ident})\s*,\s*"
    rf"({ident})\s*,\s*({ident})\s*\)\s+then\s+return\s+({ident})\(\);\s*end;\s*return\s+({ident})\s*;",
    source,
))
if len(calls) != 1:
    raise SystemExit(f"expected one six-state Guard/payload bind call, found {len(calls)}")
bind_name = calls[0].group(1)
declaration = re.search(
    rf"local\s+function\s+{re.escape(bind_name)}\s*\([^)]*\)(.*?)\nend;",
    source,
    re.S,
)
if not declaration:
    raise SystemExit("Guard/payload bind declaration not found")
body = declaration.group(1)
state = re.search(rf"\b({ident})\s*=\s*\(\s*\1\s*\*\s*4093\s*\+", body)
if not state:
    raise SystemExit("Guard/payload state absorption is missing")
state_name = state.group(1)
if not re.search(rf"\b{ident}\s*=\s*{ident}\(\s*\)\s*;\s*return\s+false;", body):
    raise SystemExit("Guard/payload bind does not reseal before returning")
return_offset = body.rfind("return false;")
if return_offset < 0:
    raise SystemExit("Guard/payload bind has no successful return")
injection = (
    "if not _G.__ib2_payload_state_tamper then "
    f"_G.__ib2_payload_state_tamper=true;{state_name}=({state_name}+1)%2147483647;end;"
)
patched = body[:return_offset] + injection + body[return_offset:]
source = source[:declaration.start(1)] + patched + source[declaration.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/guard-payload-state-tamper.lua"
set +e
timeout 3s "$LUA" tests/executor_runner.lua trusted "$WORK/guard-payload-state-tamper.lua" \
    > "$WORK/guard-payload-state-tamper.stdout" 2> "$WORK/guard-payload-state-tamper.stderr"
guard_payload_code=$?
set -e
if [[ $guard_payload_code -ne 124 ]]; then
    echo "Guard/payload state tamper did not enter the non-yielding sticky sink (exit $guard_payload_code)." >&2
    exit 1
fi
if [[ -s "$WORK/guard-payload-state-tamper.stdout" ]]; then
    echo "Guard/payload state tamper emitted protected output before the sticky sink." >&2
    exit 1
fi
if LC_ALL=C grep -aFq 'invalid protected payload' "$WORK/guard-payload-state-tamper.stderr"; then
    echo "Guard/payload state tamper leaked the stable protected-payload diagnostic." >&2
    exit 1
fi
echo "PASS bidirectional Guard/payload seal rejects instruction-state mutation through sticky sink"

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
    r"(?:[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*nil(?:\s*,\s*nil)*;\s*)?"
    r"(return\s+[A-Za-z_]\w*\(\2\b)"
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
    r"(?:[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*nil(?:\s*,\s*nil)*;\s*)?"
    r"(return\s+[A-Za-z_]\w*\(\2\b)"
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

# Repeat randomized prototype keys, opcode maps, schema orders and dispatcher
# control-flow templates. Each generated VM is parsed structurally before it is
# executed, so template diversity never replaces semantic validation.
for ((i = 1; i <= RANDOM_RUNS; i++)); do
    obfuscate "$WORK/random.lua"
    cp "$WORK/obfuscator.log" "$WORK/obfuscator-$i.log"
    python3 tests/runtime_layout.py "$ROOT/temp/t2.lua" --include-shape > "$WORK/runtime-layout-$i.out"
    run_executor "$WORK/random.lua" > "$WORK/random.out"
    cmp -s "$WORK/baseline.out" "$WORK/random.out"
done
python3 - "$WORK" "$RANDOM_RUNS" <<'PY'
from itertools import combinations
from pathlib import Path
import json
import re
import sys

work = Path(sys.argv[1])
runs = int(sys.argv[2])
if runs < 5:
    raise SystemExit("opcode polymorphism comparison requires at least five builds")
layouts = []
for index in range(1, runs + 1):
    line = (work / f"runtime-layout-{index}.out").read_text().strip().splitlines()[-1]
    marker = "PASS runtime slot ABI "
    if not line.startswith(marker):
        raise SystemExit(f"missing runtime layout result for build {index}")
    layouts.append(json.loads(line[len(marker):]))

continuations = [layout["continuation"] for layout in layouts]
vm_layouts = [layout["vm_layout"] for layout in layouts]
counts = [continuation["opcodes"] for continuation in continuations]
fingerprints = [continuation["fingerprint"] for continuation in continuations]
structure_fingerprints = [continuation["structure_fingerprint"] for continuation in continuations]
templates = [continuation["template"] for continuation in continuations]
update_orders = [continuation["state_update_order"] for continuation in continuations]
vm_layout_fingerprints = [layout["fingerprint"] for layout in vm_layouts]
vm_layout_templates = [layout["template"] for layout in vm_layouts]
domain_vectors = [json.dumps(layout["domains"], sort_keys=True) for layout in layouts]

def permute(values, seed, salt):
    result = list(values)
    state = (seed ^ salt) & 0xFFFFFFFF
    for size in range(len(result), 1, -1):
        state = (state * 1664525 + 1013904223 + size * salt) & 0xFFFFFFFF
        swap = state % size
        result[size - 1], result[swap] = result[swap], result[size - 1]
    return result

def payload_layout(domains):
    domain = domains["payload_format"]
    return {
        "outer": permute(["head", "integrity", "flags"], domain, 0x13579BDF),
        "envelope": permute(
            ["real_length", "entropy_length", "record_count", "data_count", "entropy_count", "nonce", "entropy_digest", "integrity"],
            domain, 0x2468ACE1,
        ),
        "record": permute(["kind", "ordinal", "length"], domain, 0x9E3779B9),
        "ordinal_width": 2 if ((domain >> 3) & 1) == 0 else 4,
        "record_length_width": 3 if ((domain >> 7) & 1) == 0 else 4,
        "page_length_width": 2 if ((domain >> 11) & 1) == 0 else 4,
        "page_length_suffix": ((domain >> 15) & 1) != 0,
        "pipeline": domains["decode_pipeline"] % 3,
    }

payload_layouts = [payload_layout(layout["domains"]) for layout in layouts]
payload_layout_vectors = [json.dumps(layout, sort_keys=True) for layout in payload_layouts]
super_records = []
for index in range(1, runs + 1):
    log = (work / f"obfuscator-{index}.log").read_text()
    match = re.search(
        r"Created (\d+) short super operators; folded (\d+) sequences; lengths ([0-9:,]+); structure ([0-9a-f]{8})\.",
        log,
    )
    if not match:
        raise SystemExit(f"missing structural short-super-operator record for build {index}")
    lengths = {int(size): int(count) for size, count in
               (entry.split(":") for entry in match.group(3).split(","))}
    super_records.append((int(match.group(1)), int(match.group(2)), lengths, match.group(4)))
slot_abis = [json.dumps({key: layout[key] for key in ("chunk", "block", "flow", "flow_cache")}, sort_keys=True)
             for layout in layouts]
if min(counts) <= 44:
    raise SystemExit(f"semantic opcode aliases were not emitted in every build: {counts}")
if len(set(counts)) < 2:
    raise SystemExit(f"opcode cardinality did not vary across builds: {counts}")
if len(set(fingerprints)) != runs:
    raise SystemExit("a continuation/opcode execution graph was reused across builds")
if len(set(structure_fingerprints)) != runs:
    raise SystemExit("a normalized dispatcher structure was reused across builds")
expected_templates = {"lane-partitioned", "token-threaded", "depth-layered"}
if set(templates) != expected_templates:
    raise SystemExit(f"not all dispatcher templates were emitted: {sorted(set(templates))}")
expected_vm_layouts = {"dual-partitioned", "tiered-partitioned", "hybrid-locals"}
if set(vm_layout_templates) != expected_vm_layouts:
    raise SystemExit(f"not all VM layout templates were emitted: {sorted(set(vm_layout_templates))}")
if len(set(vm_layout_fingerprints)) != runs:
    raise SystemExit("a VM state carrier layout was reused across builds")
if len(set(update_orders)) < 2:
    raise SystemExit(f"dispatcher transition ordering did not vary: {update_orders}")
if len(set(domain_vectors)) != runs:
    raise SystemExit("a serializer/runtime domain vector was reused across builds")
if len(set(payload_layout_vectors)) != runs:
    raise SystemExit("a complete payload grammar/pipeline layout was reused across builds")
if {layout["pipeline"] for layout in payload_layouts} != {0, 1, 2}:
    raise SystemExit("not all three decode pipelines were emitted")
if len({tuple(layout["outer"]) for layout in payload_layouts}) < 4:
    raise SystemExit("payload outer-field ordering did not vary sufficiently")
if len({tuple(layout["envelope"]) for layout in payload_layouts}) < runs // 2:
    raise SystemExit("payload envelope ordering did not vary sufficiently")
if len({tuple(layout["record"]) for layout in payload_layouts}) < 4:
    raise SystemExit("payload record-field ordering did not vary sufficiently")
for field, expected in (
    ("ordinal_width", {2, 4}),
    ("record_length_width", {3, 4}),
    ("page_length_width", {2, 4}),
    ("page_length_suffix", {False, True}),
):
    observed = {layout[field] for layout in payload_layouts}
    if observed != expected:
        raise SystemExit(f"payload grammar dimension {field} did not emit both forms: {sorted(observed)}")
if min(record[0] for record in super_records) < 12 or min(record[1] for record in super_records) < 8:
    raise SystemExit(f"short super operators were not materially emitted/folded: {super_records}")
if any(len(record[2]) < 2 or sum(record[2].values()) != record[0] for record in super_records):
    raise SystemExit(f"short super-operator length structure is degenerate: {super_records}")
if len({record[3] for record in super_records}) != runs:
    raise SystemExit("a short super-operator semantic structure was reused across builds")
if len(set(slot_abis)) != runs:
    raise SystemExit("a runtime slot ABI was reused across builds")

# Compare normalized structural token bigrams, not randomized names, arithmetic
# spellings or token values. A high score therefore indicates actual CFG/layout
# reuse instead of superficial lexical similarity.
def bigrams(sequence):
    return set(zip(sequence, sequence[1:]))

def jaccard(left, right):
    union = left | right
    return len(left & right) / len(union) if union else 1.0

shape_bigrams = [bigrams(continuation["shape_sequence"]) for continuation in continuations]
similarities = [jaccard(left, right) for left, right in combinations(shape_bigrams, 2)]
max_similarity = max(similarities)
mean_similarity = sum(similarities) / len(similarities)
if max_similarity > 0.35 or mean_similarity > 0.08:
    raise SystemExit(
        f"normalized dispatcher structures remain too similar: max={max_similarity:.3f}, mean={mean_similarity:.3f}"
    )
layout_bigrams = [bigrams(layout["shape_sequence"]) for layout in vm_layouts]
layout_similarities = [jaccard(left, right) for left, right in combinations(layout_bigrams, 2)]
max_layout_similarity = max(layout_similarities)
mean_layout_similarity = sum(layout_similarities) / len(layout_similarities)
if max_layout_similarity > 0.45 or mean_layout_similarity > 0.10:
    raise SystemExit(
        f"normalized VM layouts remain too similar: max={max_layout_similarity:.3f}, "
        f"mean={mean_layout_similarity:.3f}"
    )
print(
    f"PASS {runs}-build execution-model barrier: counts={sorted(set(counts))}, "
    f"dispatcher templates={sorted(set(templates))}, VM layouts={sorted(set(vm_layout_templates))}, "
    f"unique graphs/structures/layouts/domains/ABIs/payload-grammars/super-structures={runs}, "
    f"pipelines={sorted({layout['pipeline'] for layout in payload_layouts})}, "
    f"super folded={min(record[1] for record in super_records)}..{max(record[1] for record in super_records)}, "
    f"dispatcher similarity max={max_similarity:.3f} mean={mean_similarity:.3f}, "
    f"VM-layout similarity max={max_layout_similarity:.3f} mean={mean_layout_similarity:.3f}"
)
PY
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
    r"(?:[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*nil(?:\s*,\s*nil)*;\s*)?"
    r"(return\s+[A-Za-z_]\w*\(\2\b)"
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
block_chunk_successors_slot = block_slots[10]
initial_chunk_state_slot = chunk_slots[16]
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
    "initial-chunk-state": root + f"[{initial_chunk_state_slot}]=(" + root + f"[{initial_chunk_state_slot}]+1)%4294967296;\n",
    "dispatcher-state": root + f"[{initial_route_slot}]=1;\n",
    "missing-edge": (
        find_entry
        + f"assert(b and next(b[{block_successors_slot}]));b[{block_successors_slot}]={{}};end;\n"
    ),
    "wrapped-edge-state": (
        find_entry
        + f"assert(b);local changed=false;for k,v in pairs(b[{block_successors_slot}]) do "
          f"b[{block_successors_slot}][k]=(v+1)%4294967296;changed=true;end;"
          "assert(changed);end;\n"
    ),
    "wrapped-edge-chunk-state": (
        find_entry
        + f"assert(b);local changed=false;for k,v in pairs(b[{block_chunk_successors_slot}]) do "
          f"b[{block_chunk_successors_slot}][k]=(v+1)%4294967296;changed=true;end;"
          "assert(changed);end;\n"
    ),
}
for name, probe in probes.items():
    modified = source[:match.end(1)] + probe + source[match.end(1):]
    (out_dir / ("flow-" + name + ".lua")).write_text(modified, "latin1")
PY
for flow_case in block-body initial-state initial-chunk-state dispatcher-state missing-edge wrapped-edge-state wrapped-edge-chunk-state; do
    flow_file="$WORK/flow-$flow_case.lua"
    "$LUAC" -p "$flow_file"
    set +e
    run_executor "$flow_file" > "$WORK/flow-$flow_case.stdout" 2> "$WORK/flow-$flow_case.stderr"
    flow_code=$?
    set -e
    assert_payload_rejected "$flow_code" "$WORK/flow-$flow_case.stdout" \
        "$WORK/flow-$flow_case.stderr" "flow $flow_case tamper"
done
echo "PASS block body, flow edge/state and chunk-state-chain tamper rejection"

# Force a CLOSURE and its 30 pseudo upvalue-binding instructions across the
# 16-instruction page boundary. OpClosure must carry the same Flow state while
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
    r"(?:[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*nil(?:\s*,\s*nil)*;\s*)?"
    r"(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
cleanup_candidates = []
cleanup_region = source[match.end(1):match.start(3)]
for cleanup in re.finditer(
    r"((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)\s*=\s*"
    r"(nil(?:\s*,\s*nil)*)\s*;",
    cleanup_region,
):
    names = [name.strip() for name in cleanup.group(1).split(",")]
    nils = [value.strip() for value in cleanup.group(2).split(",")]
    if len(names) == len(nils) and len(names) >= 4:
        cleanup_candidates.append(names)
if not cleanup_candidates:
    raise SystemExit("paged deserializer cleanup assignment not found")
source_state_names = max(cleanup_candidates, key=len)
lifecycle_probe = (
    "assert(" + " and ".join(name + "==nil" for name in source_state_names)
    + ",'payload page/ciphertext source survived deserializer cleanup');"
)
probe = (
    "_G.__ib2_lazy_opaque=function() "
    "assert(next(" + root + f"[{chunk_slots[1]}])==nil,'decoded instructions escaped invocation-local cache');"
    "local constant_count=" + root + f"[{chunk_slots[15]}];assert(type(constant_count)=='number');"
    "assert(next(" + root + f"[{chunk_slots[1]}])==nil,'instruction material survived current fetch');"
    "local n=0;local blocks=" + root + f"[{chunk_slots[9]}];"
    "if blocks then for _,block in pairs(blocks) do "
    f"if type(block[{block_slots[3]}])=='string' then n=n+1;end;end;end;"
    "return n;end;\n"
)
source = (
    source[:match.end(1)] + probe
    + source[match.end(1):match.start(3)] + lifecycle_probe
    + source[match.start(3):]
)
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/lazy-instrumented.lua"
run_executor "$WORK/lazy-instrumented.lua" > "$WORK/lazy-instrumented.out"
grep -Eq '^lazy-blocks:[1-9][0-9]*:executed-constant:37$' "$WORK/lazy-instrumented.out"
echo "PASS paged-source release, current-record instruction lifetime, partitioned constants and opaque block retention"

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
assert_payload_rejected "$tamper_code" "$WORK/tamper.stdout" "$WORK/tamper.stderr" "outer payload tamper"
echo "PASS tamper detection without fixed diagnostic leakage"

if grep -aEq "[\"'](constants|nested|closure)[\"']|A\\\\000B" "$WORK/fixed.lua"; then
    echo "A semantic string literal leaked into generated output." >&2
    exit 1
fi
echo "PASS no test string literals visible in generated source"

echo "All IronBrew2 Linux tests passed."
