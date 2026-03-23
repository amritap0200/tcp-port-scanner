#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "raw_socket.h"

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}

int create_raw_socket() {
    int sock;
    int one = 1;
    const int *val = &one;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "Error creating raw socket: %s\n", strerror(errno));
        return -1;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        fprintf(stderr, "Error setting IP_HDRINCL: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    printf("[+] Raw socket created successfully (fd=%d)\n", sock);
    return sock;
}

int send_syn_packet(int sock, const char *src_ip, const char *dst_ip,
                    int src_port, int dst_port) {
    char datagram[4096];
    memset(datagram, 0, 4096);
    struct iphdr *iph   = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in dest;
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(dst_port);
    dest.sin_addr.s_addr = inet_addr(dst_ip);
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id       = htonl(54321);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check    = 0;
    iph->saddr    = inet_addr(src_ip);
    iph->daddr    = dest.sin_addr.s_addr;
    iph->check    = calculate_checksum((unsigned short *)datagram, iph->tot_len);
    tcph->source  = htons(src_port);
    tcph->dest    = htons(dst_port);
    tcph->seq     = 0;
    tcph->ack_seq = 0;
    tcph->doff    = 5;
    tcph->syn     = 1;
    tcph->window  = htons(5840);
    tcph->check   = 0;
    struct pseudo_header psh;
    psh.source_address = inet_addr(src_ip);
    psh.dest_address   = dest.sin_addr.s_addr;
    psh.placeholder    = 0;
    psh.protocol       = IPPROTO_TCP;
    psh.tcp_length     = htons(sizeof(struct tcphdr));
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = calculate_checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);
    if (sendto(sock, datagram, iph->tot_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) return -1;
    return 0;
}

int receive_response(int sock, int expected_src_port, int timeout_seconds) {
    char buffer[65536];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    struct timeval timeout;
    timeout.tv_sec  = timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    while (1) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&source, &source_len);
        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return PORT_FILTERED;
            return PORT_ERROR;
        }
        struct iphdr  *iph  = (struct iphdr *)buffer;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));
        if (ntohs(tcph->dest) != expected_src_port) continue;
        if (tcph->syn == 1 && tcph->ack == 1) return PORT_OPEN;
        if (tcph->rst == 1) return PORT_CLOSED;
    }
}