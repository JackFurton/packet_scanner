#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>

// Function prototypes
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void analyze_ethernet(const u_char *packet);
void analyze_ip(const u_char *packet);
void analyze_tcp(const u_char *packet, int ip_header_length);
void analyze_udp(const u_char *packet, int ip_header_length);
void print_data(const u_char *data, int size);

#endif /* PACKET_SNIFFER_H */