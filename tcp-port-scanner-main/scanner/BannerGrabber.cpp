#include "BannerGrabber.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

const char* BannerGrabber::HTTP_PROBE = "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";

BannerGrabber::BannerGrabber(const std::string &signatures_file) {
    load_signatures(signatures_file);
}

static std::string to_lower(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out += std::tolower(static_cast<unsigned char>(c));
    return out;
}

void BannerGrabber::load_signatures(const std::string &filename) {
    signatures["SSH-"]       = "SSH";
    signatures["220"]        = "FTP";
    signatures["HTTP/"]      = "HTTP";
    signatures["Apache"]     = "HTTP-Apache";
    signatures["nginx"]      = "HTTP-nginx";
    signatures["SMTP"]       = "SMTP";
    signatures["MySQL"]      = "MySQL";
    signatures["PostgreSQL"] = "PostgreSQL";
    signatures["RFB"]        = "VNC";

    port_defaults["21"]    = "FTP";
    port_defaults["22"]    = "SSH";
    port_defaults["23"]    = "Telnet";
    port_defaults["25"]    = "SMTP";
    port_defaults["53"]    = "DNS";
    port_defaults["80"]    = "HTTP";
    port_defaults["443"]   = "HTTPS";
    port_defaults["2121"]  = "FTP";
    port_defaults["2222"]  = "SSH";
    port_defaults["5000"]  = "HTTP-Alt";
    port_defaults["3306"]  = "MySQL";
    port_defaults["3389"]  = "RDP";
    port_defaults["5432"]  = "PostgreSQL";
    port_defaults["5900"]  = "VNC";
    port_defaults["6379"]  = "Redis";
    port_defaults["8080"]  = "HTTP-Alt";
    port_defaults["27017"] = "MongoDB";

    std::ifstream ifs(filename);
    if (ifs) {
        std::string content((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
        std::string name;
        std::string pattern;
        size_t pos = 0;
        while (true) {
            auto name_key = content.find("\"name\"", pos);
            if (name_key == std::string::npos) break;
            auto colon = content.find(':', name_key);
            if (colon == std::string::npos) break;
            auto start_q = content.find('"', colon + 1);
            if (start_q == std::string::npos) break;
            auto end_q = content.find('"', start_q + 1);
            if (end_q == std::string::npos) break;
            name = content.substr(start_q + 1, end_q - start_q - 1);

            auto pattern_key = content.find("\"pattern\"", end_q);
            if (pattern_key == std::string::npos) break;
            colon = content.find(':', pattern_key);
            if (colon == std::string::npos) break;
            start_q = content.find('"', colon + 1);
            if (start_q == std::string::npos) break;
            end_q = content.find('"', start_q + 1);
            if (end_q == std::string::npos) break;
            pattern = content.substr(start_q + 1, end_q - start_q - 1);

            if (!name.empty() && !pattern.empty()) {
                // JSON-image based patterns have priority over hardcoded signature key if duplicate.
                signatures[pattern] = name;
            }
            pos = end_q + 1;
        }
    }

    std::cout << "[+] Loaded " << signatures.size() << " service signatures (from ";
    if (ifs) std::cout << filename;
    else std::cout << "builtin only";
    std::cout << ")\n";
}

std::string BannerGrabber::grab_banner(const std::string &target_ip,
                                        int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    struct timeval tv;
    tv.tv_sec = timeout_sec; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(port);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());
    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(sock); return "";
    }
    if (port == 80 || port == 8080 || port == 5000 || port == 8000 || port == 8888)
        send(sock, HTTP_PROBE, strlen(HTTP_PROBE), 0);
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);
    if (bytes <= 0) return "";
    std::string clean;
    for (int i = 0; i < bytes; i++) {
        char c = buffer[i];
        if (c >= 32 && c < 127) clean += c;
        else if (c == '\n' || c == '\r') clean += ' ';
    }
    if (clean.length() > 200) clean = clean.substr(0, 200);
    return clean;
}

std::string BannerGrabber::identify_service(const std::string &banner, int port) {
    if (!banner.empty()) {
        std::string lower_banner = to_lower(banner);
        for (const auto &sig : signatures) {
            std::string lower_sig = to_lower(sig.first);
            if (lower_banner.find(lower_sig) != std::string::npos) {
                std::cerr << "[DBG] Service match by banner; port=" << port << " banner='" << banner << "' -> " << sig.second << "\n";
                return sig.second;
            }
        }
    }

    // Fallback based on common ports (even if no banner or no match)
    auto it = port_defaults.find(std::to_string(port));
    if (it != port_defaults.end()) {
        std::cerr << "[DBG] Service fallback by port default; port=" << port << " -> " << it->second << "\n";
        return it->second;
    }

    if (port == 80 || port == 8080 || port == 5000 || port == 8000 || port == 8888) {
        std::cerr << "[DBG] Service heuristic HTTP port; port=" << port << " -> HTTP\n";
        return "HTTP";
    }
    if (port == 443 || port == 8443) {
        std::cerr << "[DBG] Service heuristic HTTPS port; port=" << port << " -> HTTPS\n";
        return "HTTPS";
    }

    std::cerr << "[DBG] Service unknown; port=" << port << " banner='" << banner << "'\n";
    return "unknown";
}