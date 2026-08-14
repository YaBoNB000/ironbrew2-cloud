@echo off
setlocal enabledelayedexpansion
title IronBrew2 Obfuscator
cd /d "%~dp0"

rem ============================================================
rem  IronBrew2 Drag-and-Drop Obfuscator
rem  Drop .lua / .txt / .lur files onto this bat to obfuscate.
rem  Or: obfuscate.bat [low|mid|high] file1 file2 ...
rem ============================================================

set "CLI=IronBrew2 CLI\bin\Release\net8.0\IronBrew2 CLI.dll"
set "DEFAULT_STRENGTH=high"

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

rem ---- check the obfuscator DLL ----
if not exist "%CLI%" (
    echo [ERROR] Obfuscator not found:
    echo   %CLI%
    echo Build it once with:
    echo   dotnet build "IronBrew2 CLI\IronBrew2 CLI.csproj" -c Release
    echo.
    pause
    exit /b 1
)

rem ---- no args: show usage ----
if "%~1"=="" (
    echo.
    echo ============================================================
    echo   IronBrew2 Drag-and-Drop Obfuscator
    echo.
    echo   Usage 1: drop .lua / .txt / .lur files onto this bat
    echo   Usage 2: obfuscate.bat [low^|mid^|high] file1 file2 ...
    echo.
    echo   Default strength: %DEFAULT_STRENGTH%
    echo   Note: low  = runnable in plain Lua
    echo         mid/high = Roblox executor only
    echo ============================================================
    echo.
    pause
    exit /b 0
)

set "ST=%DEFAULT_STRENGTH%"
set /a N=0

:next
if "%~1"=="" goto finish

if /i "%~1"=="low"  ( set "ST=low"  & shift & goto next )
if /i "%~1"=="mid"  ( set "ST=mid"  & shift & goto next )
if /i "%~1"=="high" ( set "ST=high" & shift & goto next )

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
echo        Strength: !ST!
echo ============================================================

if exist "out.lua" del /q "out.lua" >nul 2>&1

dotnet "%CLI%" "!INP!" --strength !ST!

if errorlevel 1 (
    echo [FAILED] !INP! - obfuscator returned an error
    shift
    goto next
)

if not exist "out.lua" (
    echo [FAILED] out.lua was not created for: !INP!
    shift
    goto next
)

move /y "out.lua" "!OUT!" >nul
if exist "!OUT!" (
    echo [OK] output: !OUT!
) else (
    echo [FAILED] cannot write: !OUT!
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
pause
exit /b 0
