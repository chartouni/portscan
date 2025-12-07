@echo off
echo ============================================================
echo Professional Network Security Scanner
echo Windows Compilation Script
echo FOR AUTHORIZED SECURITY TESTING ONLY
echo ============================================================
echo.

echo Compiling security scanner for Windows...
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o security_scanner.exe -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS! Compilation completed.
    echo ========================================
    echo.
    echo Executable created: security_scanner.exe
    echo.
    echo Try running:
    echo   security_scanner.exe -h
    echo   security_scanner.exe -t localhost -c -a "Homelab audit" -o report.html
    echo.
    echo REMINDER: Only scan systems you own or have
    echo explicit written permission to test.
    echo.
) else (
    echo.
    echo ========================================
    echo ERROR: Compilation failed
    echo ========================================
    echo.
    echo Troubleshooting:
    echo 1. Make sure g++ is installed and in PATH
    echo 2. Try: g++ --version
    echo 3. Install MinGW-w64: choco install mingw
    echo    OR download from: https://www.mingw-w64.org/
    echo.
    pause
)
