#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include "core/raw_socket.h"
#include "scanner/Scanner.h"
#include "scanner/BannerGrabber.h"

std::vector<int> parse_port_list(const std::string &port_str) {
    std::vector<int> ports;
    std::stringstream ss(port_str);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (token.find('-') != std::string::npos) {
            std::stringstream rs(token);
            std::string s, e;
            std::getline(rs, s, '-');
            std::getline(rs, e, '-');
            int start = std::stoi(s);
            int end   = std::stoi(e);
            for (int i = start; i <= end; i++) ports.push_back(i);
        } else {
            try { ports.push_back(std::stoi(token)); } catch (...) {}
        }
    }
    return ports;
}

std::string get_arg(int argc, char *argv[], const std::string &flag,
                    const std::string &default_val = "") {
    for (int i = 1; i < argc - 1; i++)
        if (std::string(argv[i]) == flag) return std::string(argv[i+1]);
    return default_val;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: scanner_main --target <ip> --source <ip> "
                  << "--ports <list> --threads <n> --timeout <s> "
                  << "--retries <n> --output <file>\n";
        return 1;
    }
    std::string target  = get_arg(argc, argv, "--target");
    std::string source  = get_arg(argc, argv, "--source");
    std::string ports_s = get_arg(argc, argv, "--ports");
    int threads = std::stoi(get_arg(argc, argv, "--threads", "100"));
    int timeout = std::stoi(get_arg(argc, argv, "--timeout", "2"));
    int retries = std::stoi(get_arg(argc, argv, "--retries", "2"));
    std::string outfile = get_arg(argc, argv, "--output", "/tmp/scan_out.json");

    if (target.empty() || source.empty() || ports_s.empty()) {
        std::cerr << "Error: --target, --source, and --ports are required\n";
        return 1;
    }

    std::cout << "[*] Target: " << target << "\n";
    std::cout << "[*] Source: " << source << "\n";

    Scanner scanner(target, source, threads, timeout, retries);
    std::vector<int> ports = parse_port_list(ports_s);
    std::cout << "[*] Total ports to scan: " << ports.size() << "\n";
    scanner.scan_list(ports);

    BannerGrabber grabber("signatures/services.json");
    std::vector<PortResult> results = scanner.get_results();

    for (size_t i = 0; i < results.size(); i++) {
        if (results[i].status == PORT_OPEN) {
            std::cout << "[*] Grabbing banner from port " << results[i].port << "...\n";
            results[i].banner  = grabber.grab_banner(target, results[i].port, 3);
            results[i].service = grabber.identify_service(results[i].banner, results[i].port);
            if (!results[i].banner.empty()) {
                std::string b = results[i].banner;
                if (b.length() > 80) b = b.substr(0, 80);
                std::cout << "    Banner: " << b << "\n";
            }
            std::cout << "    Service: " << results[i].service << "\n";
        }
    }

    scanner.print_results();
    scanner.save_results_json(outfile);
    return 0;
}