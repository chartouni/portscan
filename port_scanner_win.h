#ifndef PORT_SCANNER_WIN_H
#define PORT_SCANNER_WIN_H

#include <string>
#include <vector>
#include <map>
#include <chrono>

// Vulnerability severity levels
enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Vulnerability information structure
struct Vulnerability {
    std::string service;
    std::string description;
    std::string cve_id;
    Severity severity;
    std::string recommendation;
};

// Structure to hold information about a single port scan result
struct PortResult {
    int port;
    bool is_open;
    std::string service_name;
    std::string service_version;
    std::string banner;
    std::string status; // "open", "closed", "filtered"
    std::vector<Vulnerability> vulnerabilities;
};

// Scan statistics
struct ScanStatistics {
    int total_ports_scanned = 0;
    int open_ports = 0;
    int closed_ports = 0;
    int filtered_ports = 0;
    double scan_duration_seconds = 0.0;
    int vulnerabilities_found = 0;
};

// Structure to hold scan results for a target
struct ScanReport {
    std::string target;
    std::string ip_address;
    std::chrono::system_clock::time_point scan_time;
    std::vector<PortResult> results;
    std::vector<std::string> security_warnings;
    ScanStatistics statistics;
    std::string scan_id; // Unique identifier for this scan
    std::string authorization_note; // Document authorization
};

class PortScanner {
private:
    std::string target;
    int timeout_ms;
    int delay_ms; // Delay between port scans to be polite
    int max_retries; // Maximum connection retry attempts
    bool verbose_mode;
    std::string log_file;
    std::chrono::system_clock::time_point scan_start_time;

    // Common port to service name mapping
    std::map<int, std::string> common_ports;

    // Known vulnerable service versions
    std::map<std::string, std::vector<Vulnerability>> vulnerability_db;

    // Initialize the common ports map
    void initializeCommonPorts();

    // Initialize vulnerability database
    void initializeVulnerabilityDatabase();

    // Resolve hostname to IP address
    std::string resolveHostname(const std::string& hostname);

    // Attempt to connect to a specific port
    bool connectToPort(const std::string& ip, int port, int timeout_ms);

    // Try to grab banner from an open port
    std::string grabBanner(const std::string& ip, int port);

    // Extract service version from banner
    std::string extractServiceVersion(const std::string& banner, const std::string& service);

    // Check for known vulnerabilities
    std::vector<Vulnerability> checkVulnerabilities(const std::string& service, const std::string& version);

    // Analyze results for security concerns
    void analyzeSecurityConcerns(ScanReport& report);

    // Log scan activity
    void logActivity(const std::string& message);

    // Calculate scan statistics
    void calculateStatistics(ScanReport& report);

    // Generate unique scan ID
    std::string generateScanId();

public:
    PortScanner(const std::string& target, int timeout_ms = 2000, int delay_ms = 100,
                int max_retries = 2, bool verbose = false);
    ~PortScanner();

    // Set authorization note (REQUIRED for professional use)
    void setAuthorizationNote(const std::string& note);

    // Enable logging to file
    void enableLogging(const std::string& log_file_path);

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

    // Export professional pentest report (HTML)
    void exportToHTML(const ScanReport& report, const std::string& filename);

    // Print report to console
    void printReport(const ScanReport& report);

    // Print summary statistics
    void printStatistics(const ScanReport& report);
};

#endif
