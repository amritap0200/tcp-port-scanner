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
    port_defaults["3306"]  = "MySQL";
    port_defaults["3389"]  = "RDP";
    port_defaults["5432"]  = "PostgreSQL";
    port_defaults["5900"]  = "VNC";
    port_defaults["6379"]  = "Redis";
    port_defaults["8080"]  = "HTTP-Alt";
    port_defaults["27017"] = "MongoDB";
    std::cout << "[+] Loaded " << signatures.size() << " service signatures\n";
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
    if (port == 80 || port == 8080 || port == 443 || port == 8443)
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
    if (!banner.empty())
        for (const auto &sig : signatures)
            if (banner.find(sig.first) != std::string::npos)
                return sig.second;
    auto it = port_defaults.find(std::to_string(port));
    if (it != port_defaults.end()) return it->second;
    return "unknown";
}