# Professional Network Security Scanner

A comprehensive C++ port scanner with vulnerability detection, designed for authorized security assessments and penetration testing engagements.

## 🔒 Legal & Ethical Notice

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for:
- ✅ Security professionals conducting authorized penetration tests
- ✅ System administrators auditing their own infrastructure
- ✅ Students learning security in controlled lab environments
- ✅ Bug bounty hunters with proper authorization
- ✅ Homelab enthusiasts testing their own networks

**Unauthorized port scanning is illegal in most jurisdictions:**
- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act 1990
- 🇩🇪 StGB §202a-c (Computer Fraud Act)
- 🇪🇺 GDPR compliance requirements
- Similar laws worldwide

**You must have explicit written permission before scanning any network or system you do not own.**

---

## ✨ Features

### Core Capabilities
- **TCP Connect Scanning** - Reliable, non-intrusive scanning method
- **Common Port Detection** - Scans 20+ most critical ports
- **Custom Port Ranges** - Full flexibility (1-65535)
- **Banner Grabbing** - Service version detection
- **Retry Logic** - Improved accuracy with automatic retries

### Security Analysis
- **Vulnerability Database** - Detection of 15+ common vulnerabilities
- **CVE Mapping** - Links to known security issues
- **Severity Ratings** - CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Service Version Extraction** - Automatic parsing of Apache, nginx, OpenSSH versions
- **Security Recommendations** - Actionable remediation guidance

### Professional Reporting
- **CSV Export** - Excel-compatible data export
- **JSON Export** - Machine-readable structured data
- **HTML Reports** - Professional, styled security assessment reports
- **Detailed Logging** - Audit trail for compliance
- **Scan Statistics** - Performance and finding metrics
- **Authorization Tracking** - Documents permission for scans

### Advanced Features
- **Configurable Delays** - Rate limiting to prevent DoS
- **Verbose Mode** - Detailed scanning progress
- **Scan ID Generation** - Unique identifiers for tracking
- **Timestamp Logging** - Complete audit trail
- **Color-Coded Reports** - Easy vulnerability identification

---

## 🚀 Quick Start

### Prerequisites

**Windows:**
- MinGW-w64 (C++ compiler with C++17 support)
- Windows 7 or later
- Administrator privileges (for some scan types)

**Install MinGW-w64:**
```powershell
# Using Chocolatey (recommended)
choco install mingw

# Or download from: https://www.mingw-w64.org/
```

### Compilation

```powershell
# Quick compile
g++ -std=c++17 -Wall -O2 main_win.cpp port_scanner_win.cpp -o security_scanner.exe -lws2_32

# Or use the included batch file
.\compile.bat
```

### Basic Usage

```powershell
# Scan your local server (with authorization)
.\security_scanner.exe -t localhost -c -a "Internal audit" -o report.html

# Scan your homelab with logging
.\security_scanner.exe -t 192.168.1.100 -c -a "Homelab assessment" -l scan.log

# Full port range scan with statistics
.\security_scanner.exe -t myserver.local -r 1-1000 -a "Pentest engagement" --stats

# Help menu
.\security_scanner.exe -h
```

---

## 📖 Detailed Usage

### Command-Line Options

**Required:**
```
-t <target>    Target hostname or IP address
-a <note>      Authorization documentation (REQUIRED)
```

**Scan Options:**
```
-c             Scan common ports only (default)
-r <start-end> Scan custom port range (e.g., 1-1000)
-d <ms>        Delay between scans in milliseconds (default: 100)
-v             Enable verbose output
```

**Output Options:**
```
-o <filename>  Export report (.csv, .json, or .html)
-l <logfile>   Enable detailed logging to file
--stats        Display detailed statistics after scan
```

### Professional Use Cases

#### 1. Homelab Security Assessment
```powershell
.\security_scanner.exe -t 192.168.1.0/24 -c -a "Homelab security audit 2024" -o homelab_scan.html -l audit.log --stats
```

#### 2. Penetration Test Engagement
```powershell
.\security_scanner.exe -t client-server.example.com -r 1-10000 -a "Pentest engagement #2024-001 - Approved by John Doe" -o pentest_report.html -l pentest.log -d 200 -v
```

#### 3. Internal Infrastructure Audit
```powershell
.\security_scanner.exe -t internal-web.corp.local -c -a "Q4 2024 security audit - IT Dept approved" -o audit.html --stats
```

#### 4. Bug Bounty Research
```powershell
.\security_scanner.exe -t target.bugcrowd.com -c -a "Bug bounty program - in scope per policy" -o bounty_scan.html
```

---

## 🎓 Project Highlights for CV/Portfolio

### Technical Skills Demonstrated

**Programming:**
- Advanced C++ (OOP, templates, STL)
- Windows Socket Programming (Winsock2)
- Cross-platform considerations
- Memory management and RAII principles

**Networking:**
- TCP/IP protocol understanding
- Socket programming and non-blocking I/O
- DNS resolution
- Service banner analysis
- Network security concepts

**Security:**
- Vulnerability assessment methodologies
- CVE database understanding
- OWASP principles
- Security severity classification
- Ethical hacking practices

**Software Engineering:**
- Professional code structure
- Documentation best practices
- Error handling and retry logic
- Logging and audit trails
- User experience design

### Suitable for German Job Market

**Why this project works for German cybersecurity roles:**

1. **Compliance-Focused** - Emphasizes authorization and legal frameworks (StGB §202a-c)
2. **Professional Standards** - Follows security assessment best practices
3. **Documentation** - Comprehensive German-style technical documentation
4. **Ethics First** - Clear legal disclaimers and authorization requirements
5. **Audit Trail** - Logging capabilities for compliance requirements

---

## 🔬 Sample Homelab Setup

### Creating a Safe Testing Environment

```powershell
# 1. Set up VirtualBox/VMware with isolated network
# 2. Deploy vulnerable VMs:
#    - Metasploitable2
#    - DVWA (Damn Vulnerable Web Application)
#    - WebGoat
#    - Your own test servers

# 3. Scan your lab environment
.\security_scanner.exe -t 192.168.56.101 -c -a "Homelab training - Metasploitable2" -o lab_results.html
```

### Recommended Lab Targets
- **Metasploitable2** - Intentionally vulnerable Linux VM
- **DVWA** - Web application security practice
- **OWASP WebGoat** - Security training platform
- **Vulnerable Docker containers** - Controlled test environments

---

## 📊 Understanding the Reports

### HTML Report Sections

1. **Scan Information**
   - Scan ID for tracking
   - Target and IP address
   - Timestamp
   - Authorization documentation

2. **Statistics Dashboard**
   - Open ports count
   - Vulnerabilities found
   - Scan duration

3. **Detailed Findings**
   - Port number and service
   - Service version
   - Banner information
   - Vulnerabilities with severity
   - CVE references
   - Remediation recommendations

4. **Security Warnings**
   - Critical exposure alerts
   - Protocol vulnerabilities
   - Configuration issues

### Severity Levels

- **CRITICAL** 🔴 - Immediate action required (e.g., exposed databases, Telnet)
- **HIGH** 🟠 - Serious vulnerabilities (e.g., outdated software, weak protocols)
- **MEDIUM** 🟡 - Moderate risk issues
- **LOW** 🟢 - Minor concerns
- **INFO** ℹ️ - Informational findings

---

## 🛠️ Extending the Tool

### Adding Custom Vulnerabilities

Edit `port_scanner_win.cpp` in the `initializeVulnerabilityDatabase()` function:

```cpp
vulnerability_db["service_name/version"] = {
    {"Service", "Description of vulnerability",
     "CVE-YYYY-XXXXX", Severity::HIGH, "Recommendation"}
};
```

### Adding Custom Ports

Edit `initializeCommonPorts()` in `port_scanner_win.cpp`:

```cpp
{port_number, "SERVICE_NAME"},
```

---

## 📝 Report Example

```html
Security Assessment Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan ID: SCAN-1733582400
Target: testserver.local
IP: 192.168.1.100
Authorization: Homelab security assessment

Open Ports:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Port    80 - HTTP (Apache/2.2.22)
  [HIGH] Apache 2.2.x is end-of-life
  CVE: CVE-2017-15710
  Recommendation: Upgrade to Apache 2.4.x

Port   443 - HTTPS (detected)

Port    21 - FTP (vsftpd 2.3.4)
  [CRITICAL] FTP transmits credentials in cleartext
  Recommendation: Use SFTP or FTPS

Statistics:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ports Scanned: 22
Open Ports: 3
Vulnerabilities: 3
Duration: 12.4 seconds
```

---

## 🎯 Career Application

### For Your CV (German Format)

**Project Section:**
```
Professionelles Netzwerk-Sicherheitsscanner | C++, Winsock2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Entwicklung eines umfassenden Port-Scanners für autorisierte
  Penetrationstests mit Schwerpunkt auf Compliance (StGB §202a-c)
• Implementierung einer CVE-Vulnerability-Datenbank mit 15+
  Schwachstellenerkennung und Schweregradbewertung
• Professionelle HTML/CSV/JSON-Berichterstattung für Audit-Trail
  und Compliance-Anforderungen
• Technologien: C++17, Winsock2, TCP/IP, Banner Grabbing,
  Security Assessment Frameworks
```

### Interview Talking Points

1. **Why this project?**
   - "I wanted to understand network security from first principles by building a professional-grade scanning tool."

2. **What challenges did you face?**
   - "Implementing non-blocking I/O with Winsock2, designing a comprehensive vulnerability database, and ensuring ethical/legal compliance."

3. **What did you learn?**
   - "Deep understanding of TCP/IP, socket programming, vulnerability assessment methodologies, and the legal frameworks around security testing in Germany."

4. **How is it different from nmap?**
   - "This is an educational project focused on learning core concepts. It demonstrates understanding of networking fundamentals and security assessment practices."

---

## 🔐 Security & Privacy

This tool:
- ✅ Does NOT store scanned data externally
- ✅ Does NOT send data to third parties
- ✅ Requires authorization documentation
- ✅ Includes legal disclaimers
- ✅ Provides audit logging
- ✅ Implements rate limiting

---

## 📚 Learning Resources

**Networking:**
- Beej's Guide to Network Programming
- TCP/IP Illustrated (Stevens)
- Computer Networks (Tanenbaum)

**Security:**
- The Web Application Hacker's Handbook
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)

**Legal:**
- BSI (German Federal Office for Information Security) guidelines
- GDPR compliance framework
- Ethical hacking certifications (CEH, OSCP)

---

## 🤝 Contributing

This is a portfolio/educational project. For suggestions:
1. Document your use case
2. Provide code examples
3. Include test results
4. Follow ethical guidelines

---

## 📄 License

MIT License - See LICENSE file for details.

**Disclaimer:** This tool is provided "as is" for educational and authorized security testing purposes only. The authors assume no liability for misuse or damage caused by this software. Users are solely responsible for ensuring they have proper authorization before scanning any systems.

---

## 🌟 Acknowledgments

Built following industry-standard security assessment practices and frameworks:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
- BSI IT-Grundschutz (German security standards)

---

## 📧 Contact

**For legitimate security research, bug bounties, or professional inquiries only.**

This project demonstrates:
- Professional C++ development
- Network security fundamentals
- Ethical hacking practices
- Compliance awareness
- German cybersecurity standards

Perfect for MSBA graduates transitioning into cybersecurity roles in Germany.
