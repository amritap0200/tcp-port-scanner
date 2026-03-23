#ifndef BANNERGRABBER_H
#define BANNERGRABBER_H

#include <string>
#include <map>

class BannerGrabber {
public:
    BannerGrabber(const std::string &signatures_file);
    std::string grab_banner(const std::string &target_ip, int port, int timeout_sec);
    std::string identify_service(const std::string &banner, int port);
private:
    std::map<std::string, std::string> signatures;
    std::map<std::string, std::string> port_defaults;
    static const char* HTTP_PROBE;
    void load_signatures(const std::string &filename);
};

#endif