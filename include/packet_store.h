#ifndef PACKET_STORE_H
#define PACKET_STORE_H

#include <pcap.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAX_PACKETS 10000
#define MAX_PACKET_SIZE 65535

// Protocol types for color coding
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ARP,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS,
    PROTO_DHCP
} protocol_t;

// Packet summary information
typedef struct {
    int number;
    struct timeval timestamp;
    int length;
    char src_mac[18];
    char dst_mac[18];
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    protocol_t protocol;
    char info[128];
    const u_char *data;
    int data_len;
} packet_info_t;

// Initialize the packet store
void packet_store_init();

// Add a packet to the store
int packet_store_add(const struct pcap_pkthdr *header, const u_char *packet);

// Get a packet by index
packet_info_t *packet_store_get(int index);

// Get the total number of stored packets
int packet_store_count();

// Clear all stored packets
void packet_store_clear();

// Get specific details about protocols and packet fields
void get_protocol_info(const u_char *packet, packet_info_t *info);
protocol_t identify_application_protocol(int src_port, int dst_port);
void add_protocol_details(packet_info_t *info, const u_char *packet);

#endif /* PACKET_STORE_H */