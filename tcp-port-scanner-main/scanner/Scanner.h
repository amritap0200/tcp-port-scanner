#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <mutex>
#include <chrono>

struct PortResult {
    int port;
    int status;
    double response_ms;
    std::string banner;
    std::string service;
};

struct ScanStats {
    int total_ports;
    int open_ports;
    int closed_ports;
    int filtered_ports;
    double total_time_sec;
    double ports_per_second;
};

class Scanner {
public:
    Scanner(const std::string &target_ip,
            const std::string &source_ip,
            int num_threads,
            int timeout_sec,
            int retries);
    void scan_range(int start_port, int end_port);
    void scan_list(const std::vector<int> &ports);
    std::vector<PortResult> get_results();
    void set_results(const std::vector<PortResult> &new_results);
    ScanStats get_stats();
    void print_results();
    void save_results_json(const std::string &filename);
private:
    std::string target_ip;
    std::string source_ip;
    int num_threads;
    int timeout_sec;
    int retries;
    int raw_sock;
    std::vector<PortResult> results;
    std::mutex results_mutex;
    std::mutex sock_mutex;
    void scan_single_port(int port);
    std::chrono::high_resolution_clock::time_point scan_start;
    std::chrono::high_resolution_clock::time_point scan_end;
};

#endif