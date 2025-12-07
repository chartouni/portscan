#include "port_scanner_win.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>

void printUsage(const char* program_name) {
    std::cout << "Lebanese Government Website Port Scanner (Windows)\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -t <target>    Target hostname or IP address\n";
    std::cout << "  -r <start-end> Scan port range (e.g., 1-1000)\n";
    std::cout << "  -c             Scan common ports only (default)\n";
    std::cout << "  -o <filename>  Output file (CSV or JSON based on extension)\n";
    std::cout << "  -d <ms>        Delay between scans in milliseconds (default: 100)\n";
    std::cout << "  --preset       Use preset Lebanese government websites\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -t bdl.gov.lb -c -o bdl_scan.csv\n";
    std::cout << "  " << program_name << " -t finance.gov.lb -r 1-100\n";
    std::cout << "  " << program_name << " --preset\n";
}

struct ScanConfig {
    std::string target;
    bool scan_range = false;
    int start_port = 1;
    int end_port = 1000;
    bool scan_common = true;
    std::string output_file;
    int delay_ms = 100;
    bool use_preset = false;
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
        } else if (arg == "--preset") {
            config.use_preset = true;
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
    }
    
    return config;
}

void scanTarget(const std::string& target, const ScanConfig& config) {
    std::cout << "\n===========================================\n";
    std::cout << "Scanning: " << target << "\n";
    std::cout << "===========================================\n";
    
    PortScanner scanner(target, 2000, config.delay_ms);
    std::vector<PortResult> results;
    
    if (config.scan_range) {
        results = scanner.scanPortRange(config.start_port, config.end_port);
    } else {
        results = scanner.scanCommonPorts();
    }
    
    ScanReport report = scanner.generateReport(results);
    scanner.printReport(report);
    
    // Export if output file specified
    if (!config.output_file.empty()) {
        std::string output_file = config.output_file;
        
        // If using preset, modify filename to include target
        if (config.use_preset) {
            size_t dot = output_file.find_last_of('.');
            std::string ext = (dot != std::string::npos) ? output_file.substr(dot) : "";
            std::string base = (dot != std::string::npos) ? output_file.substr(0, dot) : output_file;
            
            // Sanitize target name for filename
            std::string safe_target = target;
            std::replace(safe_target.begin(), safe_target.end(), '.', '_');
            output_file = base + "_" + safe_target + ext;
        }
        
        if (output_file.find(".json") != std::string::npos) {
            scanner.exportToJSON(report, output_file);
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
    
    if (config.use_preset) {
        std::cout << "\n" << std::string(56, '=') << "\n";
        std::cout << "  Lebanese Government Infrastructure Scan\n";
        std::cout << "  For Research & Journalism Purposes Only\n";
        std::cout << std::string(56, '=') << "\n";
        
        std::vector<std::string> targets = {
            "bdl.gov.lb",           // Central Bank of Lebanon
            "finance.gov.lb",        // Ministry of Finance
            "customs.gov.lb",        // Lebanese Customs
            "presidency.gov.lb",     // Presidency
            "lp.gov.lb",            // Lebanese Parliament
            "economy.gov.lb",        // Ministry of Economy
            "interior.gov.lb"        // Ministry of Interior
        };
        
        for (const auto& target : targets) {
            scanTarget(target, config);
            
            // Longer delay between different targets
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        
        std::cout << "\nAll preset scans completed.\n";
        std::cout << "Consider analyzing the results for:\n";
        std::cout << "  - Exposed databases or admin interfaces\n";
        std::cout << "  - Outdated or insecure protocols (FTP, Telnet)\n";
        std::cout << "  - Inconsistent security postures across ministries\n";
        std::cout << "  - Services that shouldn't be public-facing\n\n";
        
    } else if (!config.target.empty()) {
        scanTarget(config.target, config);
    } else {
        std::cerr << "Error: No target specified. Use -t <target> or --preset\n";
        printUsage(argv[0]);
        return 1;
    }
    
    return 0;
}
