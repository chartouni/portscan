# Windows Compilation Guide

## For PowerShell Users

### Step 1: Navigate to your directory
```powershell
cd "C:\Users\ici beyrouth\Downloads\portscan"
```

### Step 2: Compile the program
```powershell
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32
```

If that doesn't work, try:
```powershell
g++ -std=c++17 -Wall -O2 -c main_win.cpp
g++ -std=c++17 -Wall -O2 -c port_scanner_win.cpp  
g++ -std=c++17 -Wall -O2 -o lb_scanner.exe main_win.o port_scanner_win.o -lws2_32
```

### Step 3: Run your first scan
```powershell
.\lb_scanner.exe -h
```

You should see the help menu!

### Step 4: Test with a real scan
```powershell
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl_results.csv
```

## Common Issues & Solutions

### Issue: "g++ is not recognized"
**Solution:** Make sure MinGW or similar is in your PATH
```powershell
# Check if g++ is available
g++ --version
```

### Issue: "cannot find -lws2_32"
**Solution:** Try compiling without the -l flag (it should link automatically)
```powershell
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32
```

### Issue: Compilation errors about Winsock
**Solution:** Make sure you're using MinGW-w64 (not old MinGW)

## Quick Start Commands

```powershell
# Compile
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32

# View help
.\lb_scanner.exe -h

# Scan Central Bank
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl_scan.csv

# Scan all government sites
.\lb_scanner.exe --preset -o govt_scan.csv

# Scan port range
.\lb_scanner.exe -t finance.gov.lb -r 1-100 -o finance.csv
```

## File List

Make sure you have these Windows-specific files:
- `port_scanner_win.h` - Header file
- `port_scanner_win.cpp` - Scanner implementation (uses Winsock)
- `main_win.cpp` - Main program
- `WINDOWS_COMPILE.md` - This file

## What's Different from Linux Version?

The Windows version uses:
- `winsock2.h` instead of `<sys/socket.h>`
- `ws2tcpip.h` instead of `<netinet/in.h>`, `<arpa/inet.h>`
- `closesocket()` instead of `close()`
- `ioctlsocket()` instead of `fcntl()`
- `SOCKET` type instead of `int`
- `WSAStartup()` / `WSACleanup()` for Winsock initialization

Everything else works the same!

## Opening Results

After scanning:
1. CSV files open in Excel automatically
2. JSON files can be viewed in any text editor or imported to Python/Tableau

```powershell
# Open CSV in Excel
.\bdl_scan.csv

# View JSON in notepad
notepad govt_scan.json
```

## Next Steps

1. Compile successfully ✓
2. Run test scan ✓
3. Import results to Tableau/Excel ✓
4. Start your investigation ✓

Happy scanning!
