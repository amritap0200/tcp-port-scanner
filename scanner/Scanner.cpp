#include "Scanner.h"
#include "ThreadPool.h"
#include "../core/raw_socket.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

Scanner::Scanner(const std::string &target_ip,
                 const std::string &source_ip,
                 int num_threads,
                 int timeout_sec,
                 int retries)
    : target_ip(target_ip), source_ip(source_ip),
      num_threads(num_threads), timeout_sec(timeout_sec),
      retries(retries), raw_sock(-1)
{
    std::cout << "[+] Scanner initialized (TCP connect mode)\n";
}

void Scanner::scan_single_port(int port) {
    auto start = std::chrono::high_resolution_clock::now();
    int status = PORT_FILTERED;

    for (int attempt = 0; attempt <= retries; attempt++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family      = AF_INET;
        dest.sin_port        = htons(port);
        dest.sin_addr.s_addr = inet_addr(target_ip.c_str());
        int ret = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
        if (ret == 0) { status = PORT_OPEN; close(sock); break; }
        if (errno == ECONNREFUSED) { status = PORT_CLOSED; close(sock); break; }
        if (errno == EINPROGRESS) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
            struct timeval tv; tv.tv_sec = timeout_sec; tv.tv_usec = 0;
            int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (sel > 0) {
                int err = 0; socklen_t len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) status = PORT_OPEN;
                else if (err == ECONNREFUSED) status = PORT_CLOSED;
                else status = PORT_FILTERED;
            } else {
                status = PORT_FILTERED;
            }
        }
        close(sock);
        if (status != PORT_FILTERED) break;
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(results_mutex);
        PortResult result;
        result.port        = port;
        result.status      = status;
        result.response_ms = ms;
        result.banner      = "";
        result.service     = "";
        results.push_back(result);
    }
    if (status == PORT_OPEN)
        std::cout << "\n[OPEN] Port " << port << " (" << ms << " ms)\n";
}

void Scanner::scan_range(int start_port, int end_port) {
    std::cout << "[*] Scanning " << target_ip << " ports "
              << start_port << "-" << end_port
              << " with " << num_threads << " threads\n";
    scan_start = std::chrono::high_resolution_clock::now();
    ThreadPool pool(num_threads);
    for (int port = start_port; port <= end_port; port++)
        pool.enqueue([this, port] { scan_single_port(port); });
    pool.wait_all();
    scan_end = std::chrono::high_resolution_clock::now();
    std::cout << "\n[*] Scan complete!\n";
}

void Scanner::scan_list(const std::vector<int> &ports) {
    std::cout << "[*] Scanning " << ports.size()
              << " specific ports on " << target_ip << "\n";
    scan_start = std::chrono::high_resolution_clock::now();
    ThreadPool pool(num_threads);
    for (int port : ports)
        pool.enqueue([this, port] { scan_single_port(port); });
    pool.wait_all();
    scan_end = std::chrono::high_resolution_clock::now();
    std::cout << "\n[*] Scan complete!\n";
}

std::vector<PortResult> Scanner::get_results() { return results; }

ScanStats Scanner::get_stats() {
    ScanStats stats;
    stats.total_ports    = results.size();
    stats.open_ports     = 0;
    stats.closed_ports   = 0;
    stats.filtered_ports = 0;
    for (const auto &r : results) {
        if      (r.status == PORT_OPEN)     stats.open_ports++;
        else if (r.status == PORT_CLOSED)   stats.closed_ports++;
        else if (r.status == PORT_FILTERED) stats.filtered_ports++;
    }
    double elapsed = std::chrono::duration<double>(scan_end - scan_start).count();
    stats.total_time_sec   = elapsed;
    stats.ports_per_second = elapsed > 0 ? stats.total_ports / elapsed : 0;
    return stats;
}

void Scanner::print_results() {
    std::cout << "\n";
    std::cout << std::setw(8)  << "PORT"
              << std::setw(12) << "STATUS"
              << std::setw(12) << "RESP(ms)"
              << std::setw(20) << "SERVICE" << "\n";
    std::cout << std::string(52, '-') << "\n";
    for (const auto &r : results) {
        if (r.status != PORT_OPEN) continue;
        std::cout << std::setw(8)  << r.port
                  << std::setw(12) << "OPEN"
                  << std::setw(12) << std::fixed << std::setprecision(2) << r.response_ms
                  << std::setw(20) << (r.service.empty() ? "unknown" : r.service) << "\n";
    }
    ScanStats stats = get_stats();
    std::cout << "\n--- Summary ---\n";
    std::cout << "Open:     " << stats.open_ports     << "\n";
    std::cout << "Closed:   " << stats.closed_ports   << "\n";
    std::cout << "Filtered: " << stats.filtered_ports << "\n";
    std::cout << "Speed:    " << std::fixed << std::setprecision(1)
              << stats.ports_per_second << " ports/sec\n";
    std::cout << "Time:     " << stats.total_time_sec << " sec\n";
}

void Scanner::save_results_json(const std::string &filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open " << filename << "\n";
        return;
    }
    ScanStats stats = get_stats();
    file << "{\n";
    file << "  \"target\": \"" << target_ip << "\",\n";
    file << "  \"stats\": {\n";
    file << "    \"total_ports\": "      << stats.total_ports    << ",\n";
    file << "    \"open_ports\": "       << stats.open_ports     << ",\n";
    file << "    \"closed_ports\": "     << stats.closed_ports   << ",\n";
    file << "    \"filtered_ports\": "   << stats.filtered_ports << ",\n";
    file << "    \"total_time_sec\": "   << std::fixed << std::setprecision(3) << stats.total_time_sec << ",\n";
    file << "    \"ports_per_second\": " << std::fixed << std::setprecision(1) << stats.ports_per_second << "\n";
    file << "  },\n";
    file << "  \"results\": [\n";
    bool first = true;
    for (const auto &r : results) {
        if (r.status != PORT_OPEN) continue;
        if (!first) file << ",\n";
        first = false;
        file << "    {\n";
        file << "      \"port\": "        << r.port        << ",\n";
        file << "      \"status\": \"open\",\n";
        file << "      \"response_ms\": " << r.response_ms << ",\n";
        file << "      \"banner\": \""    << r.banner      << "\",\n";
        file << "      \"service\": \""   << r.service     << "\"\n";
        file << "    }";
    }
    file << "\n  ]\n}\n";
    file.close();
    std::cout << "[+] Results saved to " << filename << "\n";
}