# Lebanese Government Port Scanner - Windows Edition
## Complete Project Package

---

## 🎯 WHAT YOU HAVE

A professional port scanner built in C++ specifically for Windows, designed for investigative journalism on Lebanese government infrastructure.

---

## 📁 FILES IN YOUR FOLDER

### Windows-Specific Files (Use These!)
- **port_scanner_win.h** - Header file (Winsock version)
- **port_scanner_win.cpp** - Main scanner code (Windows networking)
- **main_win.cpp** - Command-line interface
- **compile.bat** - Easy compilation script (just double-click!)
- **WINDOWS_QUICKSTART.md** - Quick start guide (READ THIS FIRST)
- **WINDOWS_COMPILE.md** - Detailed compilation instructions

### Documentation
- **README.md** - Complete guide (Linux-focused but concepts apply)
- **PROJECT_OVERVIEW.md** - Architecture and story ideas
- **EXAMPLES.md** - Sample outputs and analysis ideas
- **QUICKSTART.md** - General quick start (Linux-focused)

### Linux Files (Ignore These on Windows)
- port_scanner.h / port_scanner.cpp
- main.cpp
- Makefile
- demo.sh
- lb_scanner (Linux executable)

---

## 🚀 GET STARTED IN 3 STEPS

### Step 1: Compile (30 seconds)
```powershell
# Option A: Double-click this file
compile.bat

# Option B: In PowerShell
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o lb_scanner.exe -lws2_32
```

### Step 2: Test (10 seconds)
```powershell
.\lb_scanner.exe -h
```

### Step 3: Scan (2-5 minutes)
```powershell
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl_results.csv
```

Done! You now have scan results in `bdl_results.csv` - open it in Excel!

---

## 💡 COMMON COMMANDS

```powershell
# Help menu
.\lb_scanner.exe -h

# Scan Central Bank → CSV
.\lb_scanner.exe -t bdl.gov.lb -c -o bdl.csv

# Scan Ministry of Finance → JSON
.\lb_scanner.exe -t finance.gov.lb -c -o finance.json

# Scan ALL preset government sites
.\lb_scanner.exe --preset -o govt_audit.csv

# Scan specific port range
.\lb_scanner.exe -t customs.gov.lb -r 1-1000 -o customs.csv

# Slower, more polite scan
.\lb_scanner.exe -t presidency.gov.lb -c -d 200 -o pres.csv
```

---

## 🎯 PRESET GOVERNMENT TARGETS

The `--preset` flag scans these Lebanese government websites:
- bdl.gov.lb (Central Bank)
- finance.gov.lb (Ministry of Finance)
- customs.gov.lb (Lebanese Customs)
- presidency.gov.lb (Presidency)
- lp.gov.lb (Parliament)
- economy.gov.lb (Ministry of Economy)
- interior.gov.lb (Ministry of Interior)

---

## 📊 WHAT YOU'LL FIND

### Security Issues the Scanner Detects:

**🚨 CRITICAL (Should NEVER be exposed):**
- Port 23 (Telnet) - Completely insecure remote access
- Port 3306 (MySQL) - Database directly on internet
- Port 5432 (PostgreSQL) - Database exposed
- Port 27017 (MongoDB) - Database exposed

**⚠️ CONCERNING (Should be behind firewall):**
- Port 21 (FTP) - Unencrypted file transfer
- Port 3389 (RDP) - Remote desktop (brute-force target)
- Port 445 (SMB) - Ransomware vulnerability
- Port 6379 (Redis) - Often misconfigured

**✅ NORMAL (Expected for websites):**
- Port 80 (HTTP) - Regular web traffic
- Port 443 (HTTPS) - Secure web traffic
- Port 22 (SSH) - Encrypted remote access

---

## 📈 WORKFLOW FOR YOUR INVESTIGATION

### Phase 1: Data Collection (Week 1)
```powershell
# Baseline scan of all government sites
.\lb_scanner.exe --preset -o baseline_scan.csv
```

### Phase 2: Deep Dive (Week 2)
```powershell
# Detailed scans of interesting targets
.\lb_scanner.exe -t bdl.gov.lb -r 1-1000 -o bdl_deep.csv
.\lb_scanner.exe -t finance.gov.lb -r 1-1000 -o finance_deep.csv
```

### Phase 3: Analysis (Week 3)
1. Import CSV files into Tableau
2. Create visualizations:
   - Open ports by ministry
   - Security warnings distribution
   - Ministry security rankings
3. Identify patterns and stories

### Phase 4: Verification & Outreach (Week 4)
```powershell
# Re-scan to confirm findings
.\lb_scanner.exe --preset -o verification_scan.csv
```
- Compare with baseline
- Contact ministries for comment
- Document everything

### Phase 5: Publication (Week 5+)
- Write data-driven article for ICI Beyrouth
- Include visualizations from Tableau
- Frame in public interest context

---

## 📰 STORY IDEAS

### Angles for ICI Beyrouth:

1. **"Security Audit Reveals Gaps in Lebanese Government Digital Infrastructure"**
   - Technical investigation with concrete findings
   - Compare ministries' security postures
   - Public accountability angle

2. **"Which Lebanese Ministries Protect Your Data?"**
   - Ministry-by-ministry breakdown
   - Security rankings
   - Budget vs. security correlation

3. **"Digital Divide: Lebanon's Government Cybersecurity Gap"**
   - Regional comparison (vs. Jordan, Egypt)
   - Economic implications
   - Governance failures

4. **"Exposed: Lebanese Government Databases Accessible from Internet"**
   - Focus on critical vulnerabilities
   - Data breach risks
   - National security implications

5. **"One Year Later: Has Government Cybersecurity Improved?"**
   - Time-series analysis
   - Track changes over time
   - Policy effectiveness evaluation

---

## 🔧 TECHNICAL DETAILS

### What Makes This Windows-Compatible:
- Uses **Winsock2** instead of POSIX sockets
- Uses `ws2tcpip.h` for networking
- Calls `WSAStartup()` / `WSACleanup()` for initialization
- Uses `closesocket()` instead of `close()`
- Uses `ioctlsocket()` for non-blocking mode

### How It Works:
1. Resolves hostname to IP via DNS
2. Attempts TCP connection to each port
3. Grabs service banners for identification
4. Analyzes results for security issues
5. Exports to CSV/JSON for analysis

### Why It's Safe & Legal:
- Uses TCP connect (most polite scanning method)
- Includes delays between scans (default 100ms)
- Only scans public-facing government websites
- Designed for security research, not exploitation
- Focuses on public interest journalism

---

## 📋 EXAMPLE OUTPUT

### Console Output:
```
===========================================
Scanning: bdl.gov.lb
===========================================
Scanning common ports on bdl.gov.lb...
Port 80 (HTTP) is OPEN - Apache/2.4.41
Port 443 (HTTPS) is OPEN - HTTPS (encrypted)
Port 21 (FTP) is OPEN - vsftpd 3.0.3

========================================
PORT SCAN REPORT
========================================

Target: bdl.gov.lb
IP Address: 185.x.x.x
Scan Time: Sun Dec 7 15:30:00 2025

OPEN PORTS:
Port    80 - HTTP           | Apache/2.4.41
Port   443 - HTTPS          | HTTPS (encrypted)
Port    21 - FTP            | vsftpd 3.0.3

SECURITY CONCERNS:
WARNING: FTP (Port 21) exposed - credentials transmitted in plaintext

========================================

Report exported to bdl.csv
```

### CSV Output (opens in Excel):
```
Target,IP Address,Scan Time,Port,Status,Service,Banner
bdl.gov.lb,185.x.x.x,Sun Dec 7 2025,80,open,HTTP,Apache/2.4.41
bdl.gov.lb,185.x.x.x,Sun Dec 7 2025,443,open,HTTPS,HTTPS (encrypted)
bdl.gov.lb,185.x.x.x,Sun Dec 7 2025,21,open,FTP,vsftpd 3.0.3
```

---

## 🛠️ TROUBLESHOOTING

### Problem: "g++ is not recognized"
**Solution:** Install MinGW-w64
- Download: https://www.mingw-w64.org/
- Or via chocolatey: `choco install mingw`

### Problem: Compilation fails
**Solution:** Try step-by-step:
```powershell
g++ -std=c++17 -c main_win.cpp
g++ -std=c++17 -c port_scanner_win.cpp
g++ -o lb_scanner.exe main_win.o port_scanner_win.o -lws2_32
```

### Problem: "No open ports found"
**Solutions:**
- Target might have tight security (good for them!)
- Try a different target
- Check your internet connection
- DNS might be blocked

### Problem: CSV won't open
**Solution:** 
- Right-click → Open with → Excel
- Or import into Tableau/Python

---

## ⚖️ LEGAL & ETHICAL GUIDELINES

### DO:
✅ Scan public-facing government websites
✅ Use reasonable delays (100ms minimum)
✅ Focus on public interest reporting
✅ Document everything thoroughly
✅ Give ministries time to respond
✅ Frame findings responsibly

### DON'T:
❌ Attempt to exploit vulnerabilities
❌ Scan at high speed (be respectful)
❌ Access unauthorized systems
❌ Publish without ministry comment
❌ Cause service disruptions

---

## 🎓 SKILLS YOU'RE DEMONSTRATING

This project combines:
- **C++ Programming**: Socket programming, OOP design
- **Networking**: TCP/IP, DNS, protocol analysis
- **Security Research**: Vulnerability identification
- **Data Journalism**: Export to Tableau/Excel
- **Systems Thinking**: Understanding infrastructure
- **Professional Development**: Documentation, build systems

Perfect bridge between your MSBA program and journalism career at ICI Beyrouth!

---

## 📞 NEXT STEPS

1. **Compile**: Run `compile.bat` or use PowerShell command
2. **Test**: `.\lb_scanner.exe -h`
3. **First Scan**: `.\lb_scanner.exe -t bdl.gov.lb -c -o test.csv`
4. **Open Results**: Double-click `test.csv` in Excel
5. **Full Investigation**: `.\lb_scanner.exe --preset -o investigation.csv`
6. **Analyze**: Import to Tableau, create visualizations
7. **Report**: Write your story for ICI Beyrouth

---

## 📚 DOCUMENTATION HIERARCHY

**START HERE:**
1. WINDOWS_QUICKSTART.md ← You are here!
2. Try compiling and running first scan

**THEN READ:**
3. WINDOWS_COMPILE.md (if you have issues)
4. PROJECT_OVERVIEW.md (architecture & story ideas)
5. EXAMPLES.md (output samples & analysis tips)

**REFERENCE:**
6. README.md (comprehensive guide)

---

## ✨ READY TO GO?

Open PowerShell in your project folder and run:

```powershell
# Step 1: Compile
.\compile.bat

# Step 2: Test
.\lb_scanner.exe -h

# Step 3: Your first scan!
.\lb_scanner.exe -t bdl.gov.lb -c -o my_first_scan.csv

# Step 4: Open results
.\my_first_scan.csv
```

**That's it!** You're now running professional security research for investigative journalism.

Good luck with your investigation! 🔍📰

---

*Questions? Check WINDOWS_COMPILE.md for detailed troubleshooting.*
