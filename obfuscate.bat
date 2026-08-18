:; exec bash tools/obfuscate-bat-linux.sh "$@"
@echo off
setlocal enabledelayedexpansion
title IronBrew2 Obfuscator
cd /d "%~dp0"

rem ============================================================
rem  IronBrew2 Drag-and-Drop Obfuscator
rem  Drop .lua / .txt / .lur files onto this bat to obfuscate.
rem  Or: obfuscate.bat file1 file2 ...
rem ============================================================

set "CLI=IronBrew2 CLI\bin\Release\net8.0\IronBrew2 CLI.dll"

rem Use the bundled Lua 5.1 tools (luac/lua/luasrcdiet) if present
if exist "%~dp0Lua" set "PATH=%~dp0Lua;%PATH%"
if exist "%~dp0Lua\Minifier" set "LUA_PATH=%~dp0Lua\Minifier\?.lua;;"

rem ---- check .NET ----
where dotnet >nul 2>&1
if errorlevel 1 (
    echo [ERROR] dotnet not found. Install .NET 8 first:
    echo   https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

rem ---- keep the shipped Release DLL synchronized with current source ----
echo [BUILD] Synchronizing Release binaries with the current source...
dotnet build "IronBrew2 CLI\IronBrew2 CLI.csproj" -c Release --nologo
if errorlevel 1 (
    echo [ERROR] Release build failed.
    echo.
    if not defined IB2_NO_PAUSE pause
    exit /b 1
)
if not exist "%CLI%" (
    echo [ERROR] Obfuscator not found after build:
    echo   %CLI%
    echo.
    if not defined IB2_NO_PAUSE pause
    exit /b 1
)

rem ---- no args: show usage ----
if "%~1"=="" (
    echo.
    echo ============================================================
    echo   IronBrew2 Drag-and-Drop Obfuscator
    echo.
    echo   Usage 1: drop .lua / .txt / .lur files onto this bat
    echo   Usage 2: obfuscate.bat file1 file2 ...
    echo.
    echo   A single stable configuration is used for every file.
    echo ============================================================
    echo.
    pause
    exit /b 0
)

set /a N=0
set /a FAIL=0

:next
if "%~1"=="" goto finish

set "INP=%~1"
set "EXT=%~x1"

if /i not "!EXT!"==".lua" if /i not "!EXT!"==".txt" if /i not "!EXT!"==".lur" (
    echo [SKIP] unsupported type: !INP!
    shift
    goto next
)

if not exist "!INP!" (
    echo [SKIP] file not found: !INP!
    shift
    goto next
)

set "OUT=%~dpn1_obf.lua"
set /a N+=1

echo.
echo ============================================================
echo  [!N!] Obfuscating: !INP!
echo ============================================================

if exist "out.lua" del /q "out.lua" >nul 2>&1

dotnet "%CLI%" "!INP!"

if errorlevel 1 (
    echo [FAILED] !INP! - obfuscator returned an error
    set /a FAIL=1
    shift
    goto next
)

if not exist "out.lua" (
    echo [FAILED] a fresh out.lua was not created for: !INP!
    set /a FAIL=1
    shift
    goto next
)

move /y "out.lua" "!OUT!" >nul
if exist "!OUT!" (
    echo [OK] output: !OUT!
) else (
    echo [FAILED] cannot write: !OUT!
    set /a FAIL=1
)

shift
goto next

:finish
echo.
if !N! GTR 0 (
    echo Done. !N! file(s) processed.
) else (
    echo No file was obfuscated.
)
echo.
if not defined IB2_NO_PAUSE pause
exit /b !FAIL!
