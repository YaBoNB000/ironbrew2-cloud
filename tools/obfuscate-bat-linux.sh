#!/usr/bin/env bash
set -uo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

DOTNET_BIN="${DOTNET_BIN:-}"
if [[ -z "$DOTNET_BIN" ]]; then
    if [[ -x /home/user/.dotnet/dotnet ]]; then
        DOTNET_BIN=/home/user/.dotnet/dotnet
    else
        DOTNET_BIN="$(command -v dotnet || true)"
    fi
fi
if [[ -z "$DOTNET_BIN" || ! -x "$DOTNET_BIN" ]]; then
    printf '%s\n' '[ERROR] dotnet not found. Install .NET 8 first.' >&2
    exit 1
fi

# The Linux validation environment keeps the Lua 5.1 toolchain here. Prefer it
# over the bundled Windows PE tools; otherwise use a native PATH installation.
if [[ -x /tmp/lua51/bin/lua && -x /tmp/lua51/bin/luac ]]; then
    export PATH="/tmp/lua51/bin:$PATH"
fi

CLI_PROJECT="$ROOT/IronBrew2 CLI/IronBrew2 CLI.csproj"
CLI_DLL="$ROOT/IronBrew2 CLI/bin/Release/net8.0/IronBrew2 CLI.dll"

printf '%s\n' '[BUILD] Synchronizing Release binaries with the current source...'
if ! "$DOTNET_BIN" build "$CLI_PROJECT" -c Release --nologo; then
    printf '%s\n' '[FAILED] Release build failed.' >&2
    exit 1
fi
if [[ ! -f "$CLI_DLL" ]]; then
    printf '[FAILED] Obfuscator not found: %s\n' "$CLI_DLL" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    cat <<'USAGE'
IronBrew2 Drag-and-Drop Obfuscator
Usage: bash obfuscate.bat file1.lua [file2.lua ...]
USAGE
    exit 0
fi

processed=0
failed=0
for input in "$@"; do
    case "${input##*.}" in
        lua|Lua|LUA|txt|Txt|TXT|lur|Lur|LUR) ;;
        *) printf '[SKIP] unsupported type: %s\n' "$input"; continue ;;
    esac
    if [[ ! -f "$input" ]]; then
        printf '[SKIP] file not found: %s\n' "$input"
        failed=1
        continue
    fi

    input_abs="$(cd -- "$(dirname -- "$input")" && pwd)/$(basename -- "$input")"
    stem="${input_abs%.*}"
    output="${stem}_obf.lua"
    processed=$((processed + 1))

    printf '\n============================================================\n'
    printf ' [%d] Obfuscating: %s\n' "$processed" "$input_abs"
    printf '============================================================\n'

    rm -f "$ROOT/out.lua"
    if ! "$DOTNET_BIN" "$CLI_DLL" "$input_abs"; then
        printf '[FAILED] %s - obfuscator returned an error\n' "$input_abs" >&2
        failed=1
        continue
    fi
    if [[ ! -s "$ROOT/out.lua" ]]; then
        printf '[FAILED] fresh out.lua was not created for: %s\n' "$input_abs" >&2
        failed=1
        continue
    fi
    if ! mv -f "$ROOT/out.lua" "$output"; then
        printf '[FAILED] cannot write: %s\n' "$output" >&2
        failed=1
        continue
    fi

    luac_bin="${LUAC_BIN:-$(command -v luac5.1 || command -v luac || true)}"
    if [[ -z "$luac_bin" ]] || ! "$luac_bin" -v 2>&1 | grep -q 'Lua 5\.1'; then
        printf '[FAILED] native Lua 5.1 luac is required for syntax validation.\n' >&2
        failed=1
        continue
    fi
    if ! "$luac_bin" -p "$output"; then
        printf '[FAILED] Lua 5.1 syntax validation failed: %s\n' "$output" >&2
        failed=1
        continue
    fi
    printf '%s\n' '[CHECK] Lua 5.1 syntax OK'

    luau_bin="${LUAU_COMPILE_BIN:-$(command -v luau-compile || true)}"
    if [[ -z "$luau_bin" ]]; then
        if [[ -n "${IB2_REQUIRE_LUAU_VALIDATION:-}" ]]; then
            printf '%s\n' '[FAILED] luau-compile not found while Luau validation is required.' >&2
            failed=1
            continue
        fi
        printf '%s\n' '[WARN] luau-compile not found; skipped Luau syntax validation.'
    elif ! "$luau_bin" "$output" >/dev/null; then
        printf '[FAILED] Luau syntax validation failed: %s\n' "$output" >&2
        failed=1
        continue
    else
        printf '%s\n' '[CHECK] Luau syntax OK'
    fi

    printf '[OK] output: %s\n' "$output"
done

printf '\nDone. %d file(s) processed.\n' "$processed"
exit "$failed"
