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

obfuscate "$WORK/fixed.lua"
python3 tests/verify_v3_payload.py "$WORK/fixed.lua"
"$LUA" "$WORK/fixed.lua" > "$WORK/fixed.out"
cmp "$WORK/baseline.out" "$WORK/fixed.out"
echo "PASS single fixed configuration"

# Capability-gated Luau/executor probes must accept untouched native primitives,
# preserve executor globals, and silently select the decoy route for either an
# active debug hook or a primitive replaced by a Lua closure.
"$LUA" tests/anti_debug_runner.lua capabilities "$WORK/fixed.lua" > "$WORK/anti-debug-capabilities.out"
cmp "$WORK/baseline.out" "$WORK/anti-debug-capabilities.out"
"$LUA" tests/anti_debug_runner.lua primitive-hook "$WORK/fixed.lua" > "$WORK/anti-debug-primitive.out"
[[ ! -s "$WORK/anti-debug-primitive.out" ]]
"$LUA" tests/anti_debug_runner.lua debug-hook "$WORK/fixed.lua" > "$WORK/anti-debug-hook.out"
[[ ! -s "$WORK/anti-debug-hook.out" ]]
echo "PASS capability-gated anti-debug probes and silent decoy routing"

# semantic.lua contains no IB_MAX_CFLOW markers. Assert that its root prototype
# was nevertheless selected and received a complete random route-state map.
python3 - "$ROOT/temp/t2.lua" "$WORK/automatic-dispatch.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = (
    "do local d=" + root + "[13];local s=" + root + "[14];"
    "assert(type(d)=='table' and type(s)=='number' and d[s]==1);"
    "local n=0;for _ in pairs(d) do n=n+1;end;assert(n>=2);end;\n"
)
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/automatic-dispatch.lua"
"$LUA" "$WORK/automatic-dispatch.lua" > "$WORK/automatic-dispatch.out"
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
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = "assert(" + root + "[13]==nil and " + root + "[14]==nil);\n"
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/dispatcher-fallback-obfuscated.lua"
"$LUAC" -p "$WORK/dispatcher-fallback-instrumented.lua"
"$LUA" "$WORK/dispatcher-fallback-instrumented.lua" > "$WORK/dispatcher-fallback.out"
cmp "$WORK/dispatcher-fallback-baseline.out" "$WORK/dispatcher-fallback.out"
echo "PASS unsupported dispatcher shape falls back without partial metadata"

# Repeat randomized prototype keys, opcode maps and schema orders.
for ((i = 1; i <= RANDOM_RUNS; i++)); do
    obfuscate "$WORK/random.lua"
    "$LUA" "$WORK/random.lua" > "$WORK/random.out"
    cmp -s "$WORK/baseline.out" "$WORK/random.out"
done
echo "PASS randomized runs: $RANDOM_RUNS/$RANDOM_RUNS"

# Tamper with v3's invocation-local flow metadata only after the outer payload
# has been authenticated and deserialized. These probes target the unminified
# generated VM so each rejection is attributable to block/flow validation, not
# to the top-level encrypted-payload checksum.
python3 - "$ROOT/temp/t2.lua" "$WORK" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
out_dir = Path(sys.argv[2])
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)

probes = {
    "block-body": (
        "do local b;for _,v in pairs(" + root + "[9]) do if v[1]==1 then b=v;break;end;end;"
        "assert(b and type(b[3])=='string' and #b[3]>0);"
        "b[3]=string.char((string.byte(b[3],1)+1)%256)..string.sub(b[3],2);end;\n"
    ),
    "initial-state": root + "[12]=(" + root + "[12]+1)%4294967296;\n",
    "dispatcher-state": root + "[14]=1;\n",
    "missing-edge": (
        "do local b;for _,v in pairs(" + root + "[9]) do if v[1]==1 then b=v;break;end;end;"
        "assert(b and next(b[5]));b[5]={};end;\n"
    ),
    "wrapped-edge-state": (
        "do local b;for _,v in pairs(" + root + "[9]) do if v[1]==1 then b=v;break;end;end;"
        "assert(b);local changed=false;for k,v in pairs(b[5]) do b[5][k]=(v+1)%4294967296;changed=true;break;end;"
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
    "$LUA" "$flow_file" > "$WORK/flow-$flow_case.stdout" 2> "$WORK/flow-$flow_case.stderr"
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
"$LUA" "$WORK/closure-boundary.lua" > "$WORK/closure-boundary.out"
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
"$LUA" "$WORK/lazy.lua" > "$WORK/lazy.out"
cmp "$WORK/lazy-baseline.out" "$WORK/lazy.out"
python3 - "$ROOT/temp/t2.lua" "$WORK/lazy-instrumented.lua" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text("latin1")
pattern = re.compile(
    r"(local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\(\);\s*)"
    r"([A-Za-z_]\w*)\s*=\s*nil;\s*(return\s+[A-Za-z_]\w*\(\2\b)"
)
match = pattern.search(source)
if not match:
    raise SystemExit("could not locate the generated root prototype")
root = match.group(2)
probe = (
    "_G.__ib2_lazy_opaque=function() "
    "assert(next(" + root + "[1])==nil,'decoded instructions escaped invocation-local cache');"
    "local n=0;local blocks=" + root + "[9];"
    "if blocks then for _,block in pairs(blocks) do "
    "if type(block[3])=='string' then n=n+1;end;end;end;"
    "return n;end;\n"
)
source = source[:match.end(1)] + probe + source[match.end(1):]
Path(sys.argv[2]).write_text(source, "latin1")
PY
"$LUAC" -p "$WORK/lazy-instrumented.lua"
"$LUA" "$WORK/lazy-instrumented.lua" > "$WORK/lazy-instrumented.out"
grep -Eq '^lazy-blocks:[1-9][0-9]*:executed-constant:37$' "$WORK/lazy-instrumented.out"
echo "PASS ephemeral instruction cache and opaque block retention"

# Exercise Lua 5.1's SETLIST C == 0 data word without checking in a huge table
# constructor. A test-only luac wrapper patches the one-element fixture after
# source preprocessing and before IronBrew2 deserializes it.
mkdir -p "$WORK/setlist-bin"
ln -s "$ROOT/tests/luac_setlist_c0_wrapper.py" "$WORK/setlist-bin/luac"
printf '%s\n' 'local t={123}; print("setlist-c0:" .. t[1])' > "$WORK/setlist-c0.lua"
"$LUA" "$WORK/setlist-c0.lua" > "$WORK/setlist-c0-baseline.out"
rm -rf temp out.lua
IB2_REAL_LUAC="$LUAC" PATH="$WORK/setlist-bin:$PATH" \
    "$DOTNET" "$CLI" "$WORK/setlist-c0.lua" > "$WORK/setlist-c0-build.log"
mv out.lua "$WORK/setlist-c0-obfuscated.lua"
"$LUAC" -p "$WORK/setlist-c0-obfuscated.lua"
"$LUA" "$WORK/setlist-c0-obfuscated.lua" > "$WORK/setlist-c0-obfuscated.out"
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
"$LUA" "$WORK/line.lua" > "$WORK/line.stdout" 2> "$WORK/line.stderr"
line_code=$?
set -e
[[ $line_code -ne 0 ]]
grep -q 'ERROR IN IRONBREW SCRIPT \[LINE 4\]' "$WORK/line.stderr"
echo "PASS nested line-info reporting"

# Simulate LuaJIT's signed 32-bit bit.bxor result.
"$LUA" tests/signed_bit_runner.lua "$WORK/fixed.lua" > "$WORK/signed-bit.out"
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
"$LUA" "$WORK/tampered.lua" > "$WORK/tamper.stdout" 2> "$WORK/tamper.stderr"
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
