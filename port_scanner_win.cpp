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

PortScanner::PortScanner(const std::string& target, int timeout_ms, int delay_ms) 
    : target(target), timeout_ms(timeout_ms), delay_ms(delay_ms) {
    initializeWinsock();
    initializeCommonPorts();
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
        return result;
    }
    
    // Check if port is open
    result.is_open = connectToPort(ip, port, timeout_ms);
    result.status = result.is_open ? "open" : "closed";
    
    // Get service name
    if (common_ports.find(port) != common_ports.end()) {
        result.service_name = common_ports[port];
    } else {
        result.service_name = "unknown";
    }
    
    // If port is open, try to grab banner
    if (result.is_open) {
        result.banner = grabBanner(ip, port);
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
    
    analyzeSecurityConcerns(report);
    
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
    std::cout << "\n========================================\n";
    std::cout << "PORT SCAN REPORT\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Target: " << report.target << "\n";
    std::cout << "IP Address: " << report.ip_address << "\n";
    
    auto time_t = std::chrono::system_clock::to_time_t(report.scan_time);
    char time_str[100];
    ctime_s(time_str, sizeof(time_str), &time_t);
    std::cout << "Scan Time: " << time_str;
    
    std::cout << "\nOPEN PORTS:\n";
    std::cout << "----------------------------------------\n";
    
    int open_count = 0;
    for (const auto& result : report.results) {
        if (result.is_open) {
            open_count++;
            std::cout << "Port " << std::setw(5) << result.port 
                     << " - " << std::setw(15) << result.service_name;
            if (!result.banner.empty()) {
                std::cout << " | " << result.banner;
            }
            std::cout << "\n";
        }
    }
    
    if (open_count == 0) {
        std::cout << "No open ports found.\n";
    }
    
    if (!report.security_warnings.empty()) {
        std::cout << "\nSECURITY CONCERNS:\n";
        std::cout << "----------------------------------------\n";
        for (const auto& warning : report.security_warnings) {
            std::cout << warning << "\n";
        }
    }
    
    std::cout << "\n========================================\n\n";
}
