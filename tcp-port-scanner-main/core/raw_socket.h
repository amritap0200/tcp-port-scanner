#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#define PORT_OPEN     1
#define PORT_CLOSED   0
#define PORT_FILTERED -1
#define PORT_ERROR    -2

struct pseudo_header {
    unsigned int  source_address;
    unsigned int  dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

#ifdef __cplusplus
extern "C" {
#endif

unsigned short calculate_checksum(unsigned short *ptr, int nbytes);
int create_raw_socket();
int send_syn_packet(int sock, const char *src_ip, const char *dst_ip,
                    int src_port, int dst_port);
int receive_response(int sock, int expected_src_port, int timeout_seconds);

#ifdef __cplusplus
}
#endif

#endif