#include "port_scanner_win.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <chrono>

// Link with Winsock library
#pragma comment(lib, "ws2_32.lib")

// Global Winsock initialization
static bool winsockInitialized = false;

void initializeWinsock() {
    if (!winsockInitialized) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            std::cerr << "WSAStartup failed: " << result << std::endl;
            exit(1);
        }
        winsockInitialized = true;
    }
}

PortScanner::PortScanner(const std::string& target, int timeout_ms, int delay_ms,
                         int max_retries, bool verbose)
    : target(target), timeout_ms(timeout_ms), delay_ms(delay_ms),
      max_retries(max_retries), verbose_mode(verbose) {
    initializeWinsock();
    initializeCommonPorts();
    initializeVulnerabilityDatabase();
    scan_start_time = std::chrono::system_clock::now();
}

PortScanner::~PortScanner() {
    // Cleanup Winsock when done
    static bool cleaned = false;
    if (!cleaned) {
        WSACleanup();
        cleaned = true;
    }
}

void PortScanner::initializeCommonPorts() {
    // Most common ports for web services and potential vulnerabilities
    common_ports = {
        {20, "FTP-DATA"},
        {21, "FTP"},
        {22, "SSH"},
        {23, "TELNET"},
        {25, "SMTP"},
        {53, "DNS"},
        {80, "HTTP"},
        {110, "POP3"},
        {143, "IMAP"},
        {443, "HTTPS"},
        {445, "SMB"},
        {993, "IMAPS"},
        {995, "POP3S"},
        {1433, "MSSQL"},
        {3306, "MySQL"},
        {3389, "RDP"},
        {5432, "PostgreSQL"},
        {5900, "VNC"},
        {6379, "Redis"},
        {8080, "HTTP-Proxy"},
        {8443, "HTTPS-Alt"},
        {27017, "MongoDB"}
    };
}

void PortScanner::initializeVulnerabilityDatabase() {
    // Apache vulnerabilities
    vulnerability_db["apache/2.2"] = {
        {"Apache", "Apache 2.2.x is end-of-life and contains multiple known vulnerabilities",
         "CVE-2017-15710", Severity::HIGH, "Upgrade to Apache 2.4.x or later"},
        {"Apache", "Vulnerable to HTTPOXY attack", "CVE-2016-5387", Severity::MEDIUM,
         "Apply latest security patches"}
    };

    vulnerability_db["apache/2.0"] = {
        {"Apache", "Apache 2.0.x is severely outdated with critical vulnerabilities",
         "CVE-2011-3192", Severity::CRITICAL, "Immediately upgrade to Apache 2.4.x"}
    };

    // FTP vulnerabilities
    vulnerability_db["ftp"] = {
        {"FTP", "FTP transmits credentials in cleartext", "N/A", Severity::HIGH,
         "Use SFTP or FTPS instead"},
        {"FTP", "Vulnerable to man-in-the-middle attacks", "N/A", Severity::HIGH,
         "Implement encrypted file transfer protocols"}
    };

    // Telnet vulnerabilities
    vulnerability_db["telnet"] = {
        {"Telnet", "Telnet is completely unencrypted", "N/A", Severity::CRITICAL,
         "Replace with SSH immediately"},
        {"Telnet", "Credentials transmitted in plaintext", "N/A", Severity::CRITICAL,
         "Disable Telnet and use SSH"}
    };

    // Database exposure vulnerabilities
    vulnerability_db["mysql"] = {
        {"MySQL", "Database should not be directly exposed to internet",
         "N/A", Severity::CRITICAL, "Place behind firewall, allow only application server access"}
    };

    vulnerability_db["postgresql"] = {
        {"PostgreSQL", "Database exposed to internet - high breach risk",
         "N/A", Severity::CRITICAL, "Restrict access to internal networks only"}
    };

    vulnerability_db["mongodb"] = {
        {"MongoDB", "MongoDB often misconfigured with no authentication",
         "N/A", Severity::CRITICAL, "Enable authentication, restrict network access"}
    };

    vulnerability_db["redis"] = {
        {"Redis", "Redis commonly deployed without authentication",
         "CVE-2015-4335", Severity::HIGH, "Enable authentication, bind to localhost only"}
    };

    // Remote access vulnerabilities
    vulnerability_db["rdp"] = {
        {"RDP", "RDP exposed to internet - common brute force target",
         "CVE-2019-0708", Severity::CRITICAL, "Use VPN, enable NLA, apply patches"}
    };

    vulnerability_db["vnc"] = {
        {"VNC", "VNC often has weak authentication",
         "N/A", Severity::HIGH, "Use strong passwords, tunnel through SSH/VPN"}
    };

    vulnerability_db["smb"] = {
        {"SMB", "SMB exposure enables ransomware attacks",
         "CVE-2017-0144", Severity::CRITICAL, "Apply MS17-010 patch, restrict SMB access"}
    };
}

void PortScanner::setAuthorizationNote(const std::string& note) {
    logActivity("Authorization note set: " + note);
}

void PortScanner::enableLogging(const std::string& log_file_path) {
    log_file = log_file_path;
    logActivity("=== Scan session started ===");
    logActivity("Target: " + target);
}

void PortScanner::logActivity(const std::string& message) {
    if (log_file.empty()) return;

    std::ofstream log(log_file, std::ios::app);
    if (log.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char time_str[100];
        ctime_s(time_str, sizeof(time_str), &time_t);
        std::string timestamp(time_str);
        if (!timestamp.empty() && timestamp.back() == '\n') {
            timestamp.pop_back();
        }

        log << "[" << timestamp << "] " << message << std::endl;
        log.close();
    }
}

std::string PortScanner::generateScanId() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    return "SCAN-" + std::to_string(timestamp);
}

std::string PortScanner::extractServiceVersion(const std::string& banner,
                                               const std::string& service) {
    if (banner.empty()) return "unknown";

    std::string banner_lower = banner;
    std::transform(banner_lower.begin(), banner_lower.end(),
                   banner_lower.begin(), ::tolower);

    // Extract Apache version
    if (banner_lower.find("apache") != std::string::npos) {
        size_t pos = banner_lower.find("apache/");
        if (pos != std::string::npos) {
            size_t start = pos + 7; // Length of "apache/"
            size_t end = banner_lower.find_first_of(" \r\n", start);
            if (end == std::string::npos) end = banner_lower.length();
            return banner_lower.substr(start, end - start);
        }
    }

    // Extract nginx version
    if (banner_lower.find("nginx") != std::string::npos) {
        size_t pos = banner_lower.find("nginx/");
        if (pos != std::string::npos) {
            size_t start = pos + 6;
            size_t end = banner_lower.find_first_of(" \r\n", start);
            if (end == std::string::npos) end = banner_lower.length();
            return banner_lower.substr(start, end - start);
        }
    }

    // Extract OpenSSH version
    if (banner_lower.find("openssh") != std::string::npos) {
        size_t pos = banner_lower.find("openssh_");
        if (pos != std::string::npos) {
            size_t start = pos + 8;
            size_t end = banner_lower.find_first_of(" \r\n", start);
            if (end == std::string::npos) end = banner_lower.length();
            return banner_lower.substr(start, end - start);
        }
    }

    return "detected";
}

std::vector<Vulnerability> PortScanner::checkVulnerabilities(
    const std::string& service, const std::string& version) {

    std::vector<Vulnerability> vulns;

    std::string service_lower = service;
    std::transform(service_lower.begin(), service_lower.end(),
                   service_lower.begin(), ::tolower);

    std::string version_lower = version;
    std::transform(version_lower.begin(), version_lower.end(),
                   version_lower.begin(), ::tolower);

    // Check for exact version matches
    std::string key = service_lower + "/" + version_lower;
    if (vulnerability_db.find(key) != vulnerability_db.end()) {
        vulns.insert(vulns.end(), vulnerability_db[key].begin(),
                    vulnerability_db[key].end());
    }

    // Check for service-level vulnerabilities
    if (vulnerability_db.find(service_lower) != vulnerability_db.end()) {
        vulns.insert(vulns.end(), vulnerability_db[service_lower].begin(),
                    vulnerability_db[service_lower].end());
    }

    return vulns;
}

void PortScanner::calculateStatistics(ScanReport& report) {
    report.statistics.total_ports_scanned = report.results.size();

    for (const auto& result : report.results) {
        if (result.is_open) {
            report.statistics.open_ports++;
        } else if (result.status == "filtered") {
            report.statistics.filtered_ports++;
        } else {
            report.statistics.closed_ports++;
        }

        report.statistics.vulnerabilities_found += result.vulnerabilities.size();
    }

    auto scan_end = std::chrono::system_clock::now();
    std::chrono::duration<double> duration = scan_end - scan_start_time;
    report.statistics.scan_duration_seconds = duration.count();
}

std::string PortScanner::resolveHostname(const std::string& hostname) {
    struct addrinfo hints, *result;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), NULL, &hints, &result) != 0) {
        return "";
    }
    
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
    
    std::string ip_str(ip);
    freeaddrinfo(result);
    return ip_str;
}

bool PortScanner::connectToPort(const std::string& ip, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    
    // Set socket to non-blocking mode for timeout support
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
    
    // Attempt connection
    connect(sock, (struct sockaddr*)&server, sizeof(server));
    
    // Use select to implement timeout
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    bool is_open = false;
    if (select(0, nullptr, &fdset, nullptr, &tv) > 0) {
        int so_error;
        int len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        
        if (so_error == 0) {
            is_open = true;
        }
    }
    
    closesocket(sock);
    return is_open;
}

std::string PortScanner::grabBanner(const std::string& ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return "";
    }
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
    
    // Set timeout
    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        return "";
    }
    
    // For HTTP/HTTPS ports, send a simple GET request
    if (port == 80 || port == 8080) {
        const char* request = "GET / HTTP/1.0\r\n\r\n";
        send(sock, request, strlen(request), 0);
    } else if (port == 443 || port == 8443) {
        // For HTTPS, we'd need SSL/TLS - skip banner for now
        closesocket(sock);
        return "HTTPS (encrypted)";
    }
    
    // Try to receive banner
    char buffer[1024] = {0};
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    closesocket(sock);
    
    if (received > 0) {
        std::string banner(buffer, received);
        // Clean up the banner - just get first line
        size_t newline = banner.find('\n');
        if (newline != std::string::npos) {
            banner = banner.substr(0, newline);
        }
        // Remove carriage returns
        banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
        return banner;
    }
    
    return "";
}

PortResult PortScanner::scanPort(int port) {
    PortResult result;
    result.port = port;

    // Resolve hostname to IP
    std::string ip = resolveHostname(target);
    if (ip.empty()) {
        result.is_open = false;
        result.status = "error";
        logActivity("Failed to resolve hostname: " + target);
        return result;
    }

    // Check if port is open (with retry logic)
    bool is_open = false;
    for (int attempt = 0; attempt <= max_retries && !is_open; attempt++) {
        is_open = connectToPort(ip, port, timeout_ms);
        if (!is_open && attempt < max_retries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    result.is_open = is_open;
    result.status = result.is_open ? "open" : "closed";

    // Get service name
    if (common_ports.find(port) != common_ports.end()) {
        result.service_name = common_ports[port];
    } else {
        result.service_name = "unknown";
    }

    // If port is open, try to grab banner and detect vulnerabilities
    if (result.is_open) {
        result.banner = grabBanner(ip, port);
        result.service_version = extractServiceVersion(result.banner, result.service_name);

        // Check for vulnerabilities
        result.vulnerabilities = checkVulnerabilities(result.service_name, result.service_version);

        logActivity("Port " + std::to_string(port) + " (" + result.service_name + ") is OPEN - " +
                   result.service_version);

        if (!result.vulnerabilities.empty()) {
            logActivity("  Found " + std::to_string(result.vulnerabilities.size()) +
                       " vulnerabilities on port " + std::to_string(port));
        }
    }

    return result;
}

std::vector<PortResult> PortScanner::scanPortRange(int start_port, int end_port) {
    std::vector<PortResult> results;
    
    std::cout << "Scanning " << target << " from port " << start_port 
              << " to " << end_port << "..." << std::endl;
    
    for (int port = start_port; port <= end_port; port++) {
        PortResult result = scanPort(port);
        results.push_back(result);
        
        if (result.is_open) {
            std::cout << "Port " << port << " (" << result.service_name << ") is OPEN";
            if (!result.banner.empty()) {
                std::cout << " - " << result.banner;
            }
            std::cout << std::endl;
        }
        
        // Be polite - delay between scans
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    
    return results;
}

std::vector<PortResult> PortScanner::scanCommonPorts() {
    std::vector<PortResult> results;
    
    std::cout << "Scanning common ports on " << target << "..." << std::endl;
    
    for (const auto& [port, service] : common_ports) {
        PortResult result = scanPort(port);
        results.push_back(result);
        
        if (result.is_open) {
            std::cout << "Port " << port << " (" << result.service_name << ") is OPEN";
            if (!result.banner.empty()) {
                std::cout << " - " << result.banner;
            }
            std::cout << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    
    return results;
}

void PortScanner::analyzeSecurityConcerns(ScanReport& report) {
    for (const auto& result : report.results) {
        if (!result.is_open) continue;
        
        // Check for insecure protocols
        if (result.port == 21) {
            report.security_warnings.push_back(
                "WARNING: FTP (Port 21) exposed - credentials transmitted in plaintext");
        }
        if (result.port == 23) {
            report.security_warnings.push_back(
                "WARNING: TELNET (Port 23) exposed - extremely insecure, unencrypted protocol");
        }
        if (result.port == 3306) {
            report.security_warnings.push_back(
                "WARNING: MySQL (Port 3306) directly exposed to internet - potential data breach risk");
        }
        if (result.port == 5432) {
            report.security_warnings.push_back(
                "WARNING: PostgreSQL (Port 5432) directly exposed - database should not be public");
        }
        if (result.port == 27017) {
            report.security_warnings.push_back(
                "WARNING: MongoDB (Port 27017) exposed - often misconfigured, high breach risk");
        }
        if (result.port == 6379) {
            report.security_warnings.push_back(
                "WARNING: Redis (Port 6379) exposed - commonly exploited if not properly secured");
        }
        if (result.port == 3389) {
            report.security_warnings.push_back(
                "WARNING: RDP (Port 3389) exposed - common target for brute force attacks");
        }
        if (result.port == 445) {
            report.security_warnings.push_back(
                "WARNING: SMB (Port 445) exposed - vulnerable to ransomware attacks");
        }
        
        // Check for outdated services in banners
        if (!result.banner.empty()) {
            std::string banner_lower = result.banner;
            std::transform(banner_lower.begin(), banner_lower.end(), 
                          banner_lower.begin(), ::tolower);
            
            if (banner_lower.find("apache/2.2") != std::string::npos ||
                banner_lower.find("apache/2.0") != std::string::npos) {
                report.security_warnings.push_back(
                    "WARNING: Outdated Apache version detected - should be updated");
            }
        }
    }
}

ScanReport PortScanner::generateReport(const std::vector<PortResult>& results) {
    ScanReport report;
    report.target = target;
    report.ip_address = resolveHostname(target);
    report.scan_time = std::chrono::system_clock::now();
    report.results = results;
    report.scan_id = generateScanId();

    analyzeSecurityConcerns(report);
    calculateStatistics(report);

    logActivity("Scan completed - " + std::to_string(report.statistics.open_ports) +
               " open ports, " + std::to_string(report.statistics.vulnerabilities_found) +
               " vulnerabilities found");

    return report;
}

void PortScanner::exportToCSV(const ScanReport& report, const std::string& filename) {
    std::ofstream file(filename);
    
    file << "Target,IP Address,Scan Time,Port,Status,Service,Banner\n";
    
    auto time_t = std::chrono::system_clock::to_time_t(report.scan_time);
    char time_str[100];
    ctime_s(time_str, sizeof(time_str), &time_t);
    std::string time_string(time_str);
    if (!time_string.empty() && time_string.back() == '\n') {
        time_string.pop_back();
    }
    
    for (const auto& result : report.results) {
        if (result.is_open) {
            file << report.target << ","
                 << report.ip_address << ","
                 << time_string << ","
                 << result.port << ","
                 << result.status << ","
                 << result.service_name << ","
                 << "\"" << result.banner << "\"\n";
        }
    }
    
    file.close();
    std::cout << "Report exported to " << filename << std::endl;
}

void PortScanner::exportToJSON(const ScanReport& report, const std::string& filename) {
    std::ofstream file(filename);
    
    auto time_t = std::chrono::system_clock::to_time_t(report.scan_time);
    char time_str[100];
    ctime_s(time_str, sizeof(time_str), &time_t);
    std::string time_string(time_str);
    if (!time_string.empty() && time_string.back() == '\n') {
        time_string.pop_back();
    }
    
    file << "{\n";
    file << "  \"target\": \"" << report.target << "\",\n";
    file << "  \"ip_address\": \"" << report.ip_address << "\",\n";
    file << "  \"scan_time\": \"" << time_string << "\",\n";
    file << "  \"open_ports\": [\n";
    
    bool first = true;
    for (const auto& result : report.results) {
        if (result.is_open) {
            if (!first) file << ",\n";
            first = false;
            
            file << "    {\n";
            file << "      \"port\": " << result.port << ",\n";
            file << "      \"service\": \"" << result.service_name << "\",\n";
            file << "      \"banner\": \"" << result.banner << "\"\n";
            file << "    }";
        }
    }
    
    file << "\n  ],\n";
    file << "  \"security_warnings\": [\n";
    
    first = true;
    for (const auto& warning : report.security_warnings) {
        if (!first) file << ",\n";
        first = false;
        file << "    \"" << warning << "\"";
    }
    
    file << "\n  ]\n";
    file << "}\n";
    
    file.close();
    std::cout << "Report exported to " << filename << std::endl;
}

void PortScanner::printReport(const ScanReport& report) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "SECURITY ASSESSMENT REPORT\n";
    std::cout << std::string(60, '=') << "\n\n";

    std::cout << "Scan ID: " << report.scan_id << "\n";
    std::cout << "Target: " << report.target << "\n";
    std::cout << "IP Address: " << report.ip_address << "\n";

    auto time_t = std::chrono::system_clock::to_time_t(report.scan_time);
    char time_str[100];
    ctime_s(time_str, sizeof(time_str), &time_t);
    std::cout << "Scan Time: " << time_str;

    if (!report.authorization_note.empty()) {
        std::cout << "Authorization: " << report.authorization_note << "\n";
    }

    std::cout << "\nOPEN PORTS:\n";
    std::cout << std::string(60, '-') << "\n";

    int open_count = 0;
    for (const auto& result : report.results) {
        if (result.is_open) {
            open_count++;
            std::cout << "Port " << std::setw(5) << result.port
                     << " - " << std::setw(15) << result.service_name
                     << " (" << result.service_version << ")";
            if (!result.banner.empty() && result.banner != result.service_version) {
                std::cout << "\n       Banner: " << result.banner.substr(0, 60);
            }
            std::cout << "\n";

            // Print vulnerabilities for this port
            if (!result.vulnerabilities.empty()) {
                for (const auto& vuln : result.vulnerabilities) {
                    std::string sev_str;
                    switch(vuln.severity) {
                        case Severity::CRITICAL: sev_str = "[CRITICAL]"; break;
                        case Severity::HIGH: sev_str = "[HIGH]    "; break;
                        case Severity::MEDIUM: sev_str = "[MEDIUM]  "; break;
                        case Severity::LOW: sev_str = "[LOW]     "; break;
                        case Severity::INFO: sev_str = "[INFO]    "; break;
                    }
                    std::cout << "       " << sev_str << " " << vuln.description << "\n";
                    if (vuln.cve_id != "N/A") {
                        std::cout << "       CVE: " << vuln.cve_id << "\n";
                    }
                }
            }
        }
    }

    if (open_count == 0) {
        std::cout << "No open ports found.\n";
    }

    if (!report.security_warnings.empty()) {
        std::cout << "\nSECURITY WARNINGS:\n";
        std::cout << std::string(60, '-') << "\n";
        for (const auto& warning : report.security_warnings) {
            std::cout << "! " << warning << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

void PortScanner::printStatistics(const ScanReport& report) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "SCAN STATISTICS\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Total Ports Scanned:  " << report.statistics.total_ports_scanned << "\n";
    std::cout << "Open Ports:           " << report.statistics.open_ports << "\n";
    std::cout << "Closed Ports:         " << report.statistics.closed_ports << "\n";
    std::cout << "Filtered Ports:       " << report.statistics.filtered_ports << "\n";
    std::cout << "Vulnerabilities:      " << report.statistics.vulnerabilities_found << "\n";
    std::cout << "Scan Duration:        " << std::fixed << std::setprecision(2)
              << report.statistics.scan_duration_seconds << " seconds\n";
    std::cout << std::string(60, '=') << "\n\n";
}

void PortScanner::exportToHTML(const ScanReport& report, const std::string& filename) {
    std::ofstream file(filename);

    auto time_t = std::chrono::system_clock::to_time_t(report.scan_time);
    char time_str[100];
    ctime_s(time_str, sizeof(time_str), &time_t);
    std::string time_string(time_str);
    if (!time_string.empty() && time_string.back() == '\n') {
        time_string.pop_back();
    }

    file << "<!DOCTYPE html>\n<html>\n<head>\n";
    file << "<meta charset='UTF-8'>\n";
    file << "<title>Security Assessment Report - " << report.target << "</title>\n";
    file << "<style>\n";
    file << "body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }\n";
    file << ".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }\n";
    file << "h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }\n";
    file << "h2 { color: #34495e; margin-top: 30px; }\n";
    file << ".info-grid { display: grid; grid-template-columns: 150px 1fr; gap: 10px; margin: 20px 0; }\n";
    file << ".label { font-weight: bold; color: #7f8c8d; }\n";
    file << ".port { background: #ecf0f1; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; }\n";
    file << ".vuln { margin: 10px 0 10px 20px; padding: 10px; border-radius: 4px; }\n";
    file << ".critical { background: #e74c3c; color: white; }\n";
    file << ".high { background: #e67e22; color: white; }\n";
    file << ".medium { background: #f39c12; color: white; }\n";
    file << ".low { background: #f1c40f; color: #2c3e50; }\n";
    file << ".info { background: #3498db; color: white; }\n";
    file << ".stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }\n";
    file << ".stat-box { background: #3498db; color: white; padding: 20px; text-align: center; border-radius: 4px; }\n";
    file << ".stat-number { font-size: 36px; font-weight: bold; }\n";
    file << ".stat-label { font-size: 14px; margin-top: 5px; }\n";
    file << ".warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 5px 0; }\n";
    file << "</style>\n</head>\n<body>\n";

    file << "<div class='container'>\n";
    file << "<h1>Security Assessment Report</h1>\n";

    file << "<div class='info-grid'>\n";
    file << "<div class='label'>Scan ID:</div><div>" << report.scan_id << "</div>\n";
    file << "<div class='label'>Target:</div><div>" << report.target << "</div>\n";
    file << "<div class='label'>IP Address:</div><div>" << report.ip_address << "</div>\n";
    file << "<div class='label'>Scan Time:</div><div>" << time_string << "</div>\n";
    if (!report.authorization_note.empty()) {
        file << "<div class='label'>Authorization:</div><div>" << report.authorization_note << "</div>\n";
    }
    file << "</div>\n";

    // Statistics
    file << "<h2>Statistics</h2>\n";
    file << "<div class='stats'>\n";
    file << "<div class='stat-box'><div class='stat-number'>" << report.statistics.open_ports
         << "</div><div class='stat-label'>Open Ports</div></div>\n";
    file << "<div class='stat-box' style='background: #e74c3c;'><div class='stat-number'>"
         << report.statistics.vulnerabilities_found
         << "</div><div class='stat-label'>Vulnerabilities</div></div>\n";
    file << "<div class='stat-box' style='background: #2ecc71;'><div class='stat-number'>"
         << std::fixed << std::setprecision(1) << report.statistics.scan_duration_seconds
         << "s</div><div class='stat-label'>Scan Duration</div></div>\n";
    file << "</div>\n";

    // Open Ports
    file << "<h2>Open Ports</h2>\n";
    int open_count = 0;
    for (const auto& result : report.results) {
        if (result.is_open) {
            open_count++;
            file << "<div class='port'>\n";
            file << "<strong>Port " << result.port << "</strong> - "
                 << result.service_name << " (" << result.service_version << ")<br>\n";
            if (!result.banner.empty()) {
                file << "<small>Banner: " << result.banner << "</small><br>\n";
            }

            if (!result.vulnerabilities.empty()) {
                file << "<div style='margin-top: 10px;'>\n";
                for (const auto& vuln : result.vulnerabilities) {
                    std::string sev_class;
                    std::string sev_text;
                    switch(vuln.severity) {
                        case Severity::CRITICAL: sev_class = "critical"; sev_text = "CRITICAL"; break;
                        case Severity::HIGH: sev_class = "high"; sev_text = "HIGH"; break;
                        case Severity::MEDIUM: sev_class = "medium"; sev_text = "MEDIUM"; break;
                        case Severity::LOW: sev_class = "low"; sev_text = "LOW"; break;
                        case Severity::INFO: sev_class = "info"; sev_text = "INFO"; break;
                    }
                    file << "<div class='vuln " << sev_class << "'>\n";
                    file << "<strong>[" << sev_text << "]</strong> " << vuln.description << "<br>\n";
                    if (vuln.cve_id != "N/A") {
                        file << "<small>CVE: " << vuln.cve_id << "</small><br>\n";
                    }
                    file << "<small><em>Recommendation: " << vuln.recommendation << "</em></small>\n";
                    file << "</div>\n";
                }
                file << "</div>\n";
            }
            file << "</div>\n";
        }
    }

    if (open_count == 0) {
        file << "<p>No open ports found.</p>\n";
    }

    // Security Warnings
    if (!report.security_warnings.empty()) {
        file << "<h2>Security Warnings</h2>\n";
        for (const auto& warning : report.security_warnings) {
            file << "<div class='warning'>" << warning << "</div>\n";
        }
    }

    file << "<hr style='margin-top: 40px;'>\n";
    file << "<p style='text-align: center; color: #7f8c8d; font-size: 12px;'>\n";
    file << "Generated by Professional Port Scanner | For Authorized Security Testing Only\n";
    file << "</p>\n";

    file << "</div>\n</body>\n</html>\n";
    file.close();

    std::cout << "Professional HTML report exported to " << filename << std::endl;
}
