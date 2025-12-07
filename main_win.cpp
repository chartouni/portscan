#include "port_scanner_win.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>

void printUsage(const char* program_name) {
    std::cout << "\n";
    std::cout << "===================================================================\n";
    std::cout << "  Professional Network Security Scanner (Windows)\n";
    std::cout << "  FOR AUTHORIZED SECURITY TESTING ONLY\n";
    std::cout << "===================================================================\n\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Required Options:\n";
    std::cout << "  -t <target>    Target hostname or IP address\n";
    std::cout << "  -a <note>      Authorization note (REQUIRED for all scans)\n\n";
    std::cout << "Scan Options:\n";
    std::cout << "  -r <start-end> Scan port range (e.g., 1-1000)\n";
    std::cout << "  -c             Scan common ports only (default)\n";
    std::cout << "  -d <ms>        Delay between scans in milliseconds (default: 100)\n";
    std::cout << "  -v             Verbose output\n\n";
    std::cout << "Output Options:\n";
    std::cout << "  -o <filename>  Output file (.csv, .json, or .html)\n";
    std::cout << "  -l <logfile>   Enable detailed logging to file\n";
    std::cout << "  --stats        Show detailed statistics\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Scan your own server (authorized)\n";
    std::cout << "  " << program_name << " -t localhost -c -a \"Internal security audit\" -o report.html\n\n";
    std::cout << "  # Scan homelab infrastructure\n";
    std::cout << "  " << program_name << " -t 192.168.1.100 -r 1-1000 -a \"Homelab assessment\" -o scan.csv\n\n";
    std::cout << "  # Detailed scan with logging\n";
    std::cout << "  " << program_name << " -t myserver.local -c -a \"Pentest engagement #2024-001\" -v -l scan.log\n\n";
    std::cout << "LEGAL NOTICE:\n";
    std::cout << "Only scan systems you own or have explicit written permission to test.\n";
    std::cout << "Unauthorized port scanning may violate laws in your jurisdiction.\n";
    std::cout << "The developers assume no liability for misuse of this tool.\n";
    std::cout << "===================================================================\n\n";
}

struct ScanConfig {
    std::string target;
    bool scan_range = false;
    int start_port = 1;
    int end_port = 1000;
    bool scan_common = true;
    std::string output_file;
    int delay_ms = 100;
    bool verbose = false;
    std::string authorization_note;
    std::string log_file;
    bool show_stats = false;
};

ScanConfig parseArguments(int argc, char* argv[]) {
    ScanConfig config;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-t" && i + 1 < argc) {
            config.target = argv[++i];
        } else if (arg == "-r" && i + 1 < argc) {
            std::string range = argv[++i];
            size_t dash = range.find('-');
            if (dash != std::string::npos) {
                config.start_port = std::stoi(range.substr(0, dash));
                config.end_port = std::stoi(range.substr(dash + 1));
                config.scan_range = true;
                config.scan_common = false;
            }
        } else if (arg == "-c") {
            config.scan_common = true;
            config.scan_range = false;
        } else if (arg == "-o" && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "-d" && i + 1 < argc) {
            config.delay_ms = std::stoi(argv[++i]);
        } else if (arg == "-a" && i + 1 < argc) {
            config.authorization_note = argv[++i];
        } else if (arg == "-l" && i + 1 < argc) {
            config.log_file = argv[++i];
        } else if (arg == "-v") {
            config.verbose = true;
        } else if (arg == "--stats") {
            config.show_stats = true;
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
    }

    return config;
}

void scanTarget(const std::string& target, const ScanConfig& config) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Security Assessment: " << target << "\n";
    std::cout << std::string(60, '=') << "\n";

    // Create scanner with enhanced configuration
    PortScanner scanner(target, 2000, config.delay_ms, 2, config.verbose);

    // Set authorization note
    if (!config.authorization_note.empty()) {
        scanner.setAuthorizationNote(config.authorization_note);
    }

    // Enable logging if specified
    if (!config.log_file.empty()) {
        scanner.enableLogging(config.log_file);
    }

    std::vector<PortResult> results;

    if (config.scan_range) {
        results = scanner.scanPortRange(config.start_port, config.end_port);
    } else {
        results = scanner.scanCommonPorts();
    }

    ScanReport report = scanner.generateReport(results);
    report.authorization_note = config.authorization_note;

    scanner.printReport(report);

    if (config.show_stats) {
        scanner.printStatistics(report);
    }

    // Export if output file specified
    if (!config.output_file.empty()) {
        std::string output_file = config.output_file;

        if (output_file.find(".json") != std::string::npos) {
            scanner.exportToJSON(report, output_file);
        } else if (output_file.find(".html") != std::string::npos) {
            scanner.exportToHTML(report, output_file);
        } else {
            scanner.exportToCSV(report, output_file);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    ScanConfig config = parseArguments(argc, argv);

    // Validate that target is specified
    if (config.target.empty()) {
        std::cerr << "\n[ERROR] No target specified. Use -t <target>\n\n";
        printUsage(argv[0]);
        return 1;
    }

    // Check for authorization note
    if (config.authorization_note.empty()) {
        std::cerr << "\n";
        std::cerr << "============================================================\n";
        std::cerr << "  WARNING: Authorization Note Required\n";
        std::cerr << "============================================================\n\n";
        std::cerr << "This tool requires an authorization note for all scans.\n";
        std::cerr << "Use the -a flag to document your authorization:\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  -a \"Internal security audit - approved by IT dept\"\n";
        std::cerr << "  -a \"Homelab security assessment\"\n";
        std::cerr << "  -a \"Penetration test engagement #2024-001\"\n\n";
        std::cerr << "REMINDER: Only scan systems you own or have written\n";
        std::cerr << "permission to test. Unauthorized scanning is illegal.\n";
        std::cerr << "============================================================\n\n";

        char response;
        std::cout << "Proceed without authorization note? (y/N): ";
        std::cin >> response;

        if (response != 'y' && response != 'Y') {
            std::cout << "\nScan cancelled. Please provide authorization with -a flag.\n";
            return 1;
        }

        config.authorization_note = "WARNING: No authorization documented";
    }

    // Display legal disclaimer
    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "  LEGAL DISCLAIMER\n";
    std::cout << "============================================================\n";
    std::cout << "This tool is for authorized security testing only.\n";
    std::cout << "You must have explicit permission to scan the target.\n";
    std::cout << "Unauthorized access attempts may violate:\n";
    std::cout << "  - Computer Fraud and Abuse Act (USA)\n";
    std::cout << "  - Computer Misuse Act (UK)\n";
    std::cout << "  - StGB §202a-c (Germany)\n";
    std::cout << "  - Similar laws in other jurisdictions\n\n";
    std::cout << "By proceeding, you confirm you have proper authorization.\n";
    std::cout << "============================================================\n";

    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Perform the scan
    scanTarget(config.target, config);

    return 0;
}
