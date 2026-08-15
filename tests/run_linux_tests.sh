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
    rm -rf "$WORK" "$ROOT/temp" "$ROOT/out.lua"
}
trap cleanup EXIT

cd "$ROOT"
"$DOTNET" build "IronBrew2 CLI/IronBrew2 CLI.csproj" -c Release --nologo >/dev/null
CLI="$ROOT/IronBrew2 CLI/bin/Release/net8.0/IronBrew2 CLI.dll"
"$LUA" tests/semantic.lua > "$WORK/baseline.out"

obfuscate() {
    local output=$1
    rm -rf temp out.lua
    "$DOTNET" "$CLI" tests/semantic.lua > "$WORK/obfuscator.log"
    mv out.lua "$output"
    "$LUAC" -p "$output"
}

obfuscate "$WORK/fixed.lua"
"$LUA" "$WORK/fixed.lua" > "$WORK/fixed.out"
cmp "$WORK/baseline.out" "$WORK/fixed.out"
echo "PASS single fixed configuration"

# Repeat randomized prototype keys, opcode maps and schema orders.
for ((i = 1; i <= RANDOM_RUNS; i++)); do
    obfuscate "$WORK/random.lua"
    "$LUA" "$WORK/random.lua" > "$WORK/random.out"
    cmp -s "$WORK/baseline.out" "$WORK/random.out"
done
echo "PASS randomized runs: $RANDOM_RUNS/$RANDOM_RUNS"

# Verify the runtime keeps unexecuted basic blocks as opaque byte slices. The
# production output is executed first. We then instrument the unminified VM
# generated in temp/t2.lua, without changing product code, to count root blocks
# whose encoded body has not yet been decoded when the protected program starts.
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
echo "PASS unexecuted basic blocks remain opaque"

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

if grep -aEq 'constants|nested|closure|A\\000B' "$WORK/fixed.lua"; then
    echo "A semantic string literal leaked into generated output." >&2
    exit 1
fi
echo "PASS no test string literals visible in generated source"

echo "All IronBrew2 Linux tests passed."
