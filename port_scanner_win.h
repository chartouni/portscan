#ifndef PORT_SCANNER_WIN_H
#define PORT_SCANNER_WIN_H

#include <string>
#include <vector>
#include <map>
#include <chrono>

// Structure to hold information about a single port scan result
struct PortResult {
    int port;
    bool is_open;
    std::string service_name;
    std::string banner;
    std::string status; // "open", "closed", "filtered"
};

// Structure to hold scan results for a target
struct ScanReport {
    std::string target;
    std::string ip_address;
    std::chrono::system_clock::time_point scan_time;
    std::vector<PortResult> results;
    std::vector<std::string> security_warnings;
};

class PortScanner {
private:
    std::string target;
    int timeout_ms;
    int delay_ms; // Delay between port scans to be polite
    
    // Common port to service name mapping
    std::map<int, std::string> common_ports;
    
    // Initialize the common ports map
    void initializeCommonPorts();
    
    // Resolve hostname to IP address
    std::string resolveHostname(const std::string& hostname);
    
    // Attempt to connect to a specific port
    bool connectToPort(const std::string& ip, int port, int timeout_ms);
    
    // Try to grab banner from an open port
    std::string grabBanner(const std::string& ip, int port);
    
    // Analyze results for security concerns
    void analyzeSecurityConcerns(ScanReport& report);
    
public:
    PortScanner(const std::string& target, int timeout_ms = 2000, int delay_ms = 100);
    ~PortScanner();
    
    // Scan a single port
    PortResult scanPort(int port);
    
    // Scan a range of ports
    std::vector<PortResult> scanPortRange(int start_port, int end_port);
    
    // Scan common ports (top 100 most used ports)
    std::vector<PortResult> scanCommonPorts();
    
    // Generate a full report
    ScanReport generateReport(const std::vector<PortResult>& results);
    
    // Export report to CSV
    void exportToCSV(const ScanReport& report, const std::string& filename);
    
    // Export report to JSON
    void exportToJSON(const ScanReport& report, const std::string& filename);
    
    // Print report to console
    void printReport(const ScanReport& report);
};

#endif
