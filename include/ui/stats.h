#ifndef STATS_H
#define STATS_H

#include "../packet_store.h"
#include <time.h>

// Structure to hold traffic statistics
typedef struct {
    // Protocol counts
    int total_packets;
    int tcp_packets;
    int udp_packets;
    int icmp_packets;
    int arp_packets;
    int other_packets;
    
    // Application protocol counts
    int http_packets;
    int https_packets;
    int dns_packets;
    int dhcp_packets;
    
    // Data volume
    unsigned long long total_bytes;
    unsigned long long tcp_bytes;
    unsigned long long udp_bytes;
    
    // Rate tracking
    unsigned long long bytes_per_sec;
    int packets_per_sec;
    
    // Timing
    time_t start_time;
    time_t current_time;
    
    // Top talkers (IPs) - simple fixed-size tracking
    #define MAX_TOP_ENTRIES 10
    struct {
        char ip[16];
        int count;
        unsigned long long bytes;
    } top_sources[MAX_TOP_ENTRIES];
    
    struct {
        char ip[16];
        int count;
        unsigned long long bytes;
    } top_destinations[MAX_TOP_ENTRIES];
    
    // Port distribution
    struct {
        int port;
        int count;
    } top_ports[MAX_TOP_ENTRIES];
    
} traffic_stats_t;

// Initialize statistics
void stats_init();

// Update statistics with a new packet
void stats_add_packet(packet_info_t *packet);

// Calculate rates
void stats_update_rates();

// Get the global stats structure
traffic_stats_t *stats_get();

// Reset statistics
void stats_reset();

#endif /* STATS_H */