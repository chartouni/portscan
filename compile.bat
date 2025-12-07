@echo off
echo ========================================
echo Lebanese Government Port Scanner
echo Windows Compilation Script
echo ========================================
echo.

echo Compiling port scanner for Windows...
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS! Compilation completed.
    echo ========================================
    echo.
    echo Executable created: lb_scanner.exe
    echo.
    echo Try running:
    echo   lb_scanner.exe -h
    echo   lb_scanner.exe -t bdl.gov.lb -c -o results.csv
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
    echo 3. You may need MinGW-w64
    echo.
    pause
)
