# Windows Quick Start - Port Scanner

## For Your PowerShell Terminal

### Option 1: Easy Compilation (Double-click)
1. Double-click `compile.bat`
2. Wait for compilation to finish
3. You'll get `lb_scanner.exe`

### Option 2: Manual Compilation (PowerShell)
```powershell
# Navigate to your folder
cd "C:\Users\ici beyrouth\Downloads\portscan"

# Compile
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32

# Test
.\lb_scanner.exe -h
```

## Your First Scan (3 Minutes)

### Step 1: Open PowerShell in your folder
```powershell
cd "C:\Users\ici beyrouth\Downloads\portscan"
```

### Step 2: Run the scanner
```powershell
# Scan Central Bank of Lebanon
.\lb_scanner.exe -t bdl.gov.lb -c -o my_first_scan.csv
```

### Step 3: Open results
- The file `my_first_scan.csv` will be created
- Double-click it to open in Excel
- Look for open ports and security warnings

## Common Commands

```powershell
# Help
.\lb_scanner.exe -h

# Scan one target → CSV
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl.csv

# Scan one target → JSON  
.\lb_scanner.exe -t finance.gov.lb -c -o finance.json

# Scan ALL government sites
.\lb_scanner.exe --preset -o govt_audit.csv

# Scan specific port range
.\lb_scanner.exe -t customs.gov.lb -r 1-100 -o customs.csv

# Slower scan (more polite)
.\lb_scanner.exe -t presidency.gov.lb -c -d 200 -o pres.csv
```

## Understanding Output

### Console shows:
```
Scanning bdl.gov.lb from port 20 to 27017...
Port 80 (HTTP) is OPEN - Apache/2.4.41
Port 443 (HTTPS) is OPEN - HTTPS (encrypted)
Port 21 (FTP) is OPEN - vsftpd 3.0.3

========================================
PORT SCAN REPORT
========================================
Target: bdl.gov.lb
IP Address: 185.x.x.x

OPEN PORTS:
Port    80 - HTTP           | Apache/2.4.41
Port   443 - HTTPS          | HTTPS (encrypted)
Port    21 - FTP            | vsftpd 3.0.3

SECURITY CONCERNS:
WARNING: FTP (Port 21) exposed - credentials transmitted in plaintext
========================================
```

### CSV file contains:
```
Target,IP Address,Scan Time,Port,Status,Service,Banner
bdl.gov.lb,185.x.x.x,Sun Dec 07 2025,80,open,HTTP,Apache/2.4.41
bdl.gov.lb,185.x.x.x,Sun Dec 07 2025,443,open,HTTPS,HTTPS (encrypted)
bdl.gov.lb,185.x.x.x,Sun Dec 07 2025,21,open,FTP,vsftpd 3.0.3
```

## What to Look For

### 🚨 RED FLAGS (Critical)
- **Port 23** (Telnet) - Completely insecure
- **Port 3306** (MySQL) - Database exposed!
- **Port 5432** (PostgreSQL) - Database exposed!
- **Port 27017** (MongoDB) - Database exposed!

### ⚠️ WARNINGS (Concerning)
- **Port 21** (FTP) - Unencrypted file transfer
- **Port 3389** (RDP) - Remote desktop (attack target)
- **Port 445** (SMB) - Ransomware risk

### ✅ GOOD (Normal)
- **Port 80** (HTTP) - Web server
- **Port 443** (HTTPS) - Secure web
- **Port 22** (SSH) - Encrypted remote access

## Workflow for Investigation

### Week 1: Collect Data
```powershell
.\lb_scanner.exe --preset -o week1_scan.csv
```

### Week 2: Detailed Analysis
```powershell
# Scan specific ministries in more detail
.\lb_scanner.exe -t bdl.gov.lb -r 1-1000 -o bdl_detailed.csv
.\lb_scanner.exe -t finance.gov.lb -r 1-1000 -o finance_detailed.csv
```

### Week 3: Import to Tableau
1. Open Tableau
2. Import `week1_scan.csv`
3. Create visualizations:
   - Bar chart: Open ports by ministry
   - Heat map: Security warnings
   - Table: Port details

### Week 4: Write Article
Use the data to support your story at ICI Beyrouth.

## Files You Need

Windows-specific files (already in your folder):
- ✅ `port_scanner_win.h`
- ✅ `port_scanner_win.cpp`
- ✅ `main_win.cpp`
- ✅ `compile.bat`
- ✅ `WINDOWS_COMPILE.md`
- ✅ `WINDOWS_QUICKSTART.md` (this file)

After compilation:
- `lb_scanner.exe` - The program you'll run

## Troubleshooting

### "g++ is not recognized"
You need to install MinGW or similar:
1. Download MinGW-w64 from: https://www.mingw-w64.org/
2. Or install via chocolatey: `choco install mingw`
3. Make sure it's in your PATH

### "Cannot find lb_scanner.exe"
Make sure you're in the right directory:
```powershell
cd "C:\Users\ici beyrouth\Downloads\portscan"
dir
```

### Compilation fails
Try step-by-step:
```powershell
g++ -std=c++17 -c main_win.cpp
g++ -std=c++17 -c port_scanner_win.cpp
g++ -std=c++17 -o lb_scanner.exe main_win.o port_scanner_win.o -lws2_32
```

### "No open ports found"
This could mean:
- Target has very tight security (good for them!)
- DNS resolution failed
- Network firewall blocking you
- Target website is down

Try with a known-good target like:
```powershell
.\lb_scanner.exe -t google.com -r 80-443 -o test.csv
```

## Next Steps

1. ✅ Compile: `compile.bat` or manual command
2. ✅ Test: `.\lb_scanner.exe -h`
3. ✅ First scan: `.\lb_scanner.exe -t bdl.gov.lb -c -o test.csv`
4. ✅ Full investigation: `.\lb_scanner.exe --preset -o investigation.csv`
5. ✅ Analyze in Tableau/Excel
6. ✅ Write your story!

## Ready to Start?

```powershell
# Compile
.\compile.bat

# Run first scan
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl_scan.csv

# Open results in Excel
.\bdl_scan.csv
```

Good luck with your investigation! 🔍
