#include "../../include/ui/stats.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Global stats structure
static traffic_stats_t stats;

// Compare function for sorting top talkers by count (descending)
static int compare_by_count(const void *a, const void *b) {
    const struct { char ip[16]; int count; unsigned long long bytes; } *ea = a;
    const struct { char ip[16]; int count; unsigned long long bytes; } *eb = b;
    
    // Sort by count in descending order
    return (eb->count - ea->count);
}

// Compare function for sorting top ports by count (descending)
static int compare_ports_by_count(const void *a, const void *b) {
    const struct { int port; int count; } *ea = a;
    const struct { int port; int count; } *eb = b;
    
    // Sort by count in descending order
    return (eb->count - ea->count);
}

// Initialize statistics
void stats_init() {
    // Zero out the entire structure
    memset(&stats, 0, sizeof(traffic_stats_t));
    
    // Set start time
    stats.start_time = time(NULL);
    stats.current_time = stats.start_time;
}

// Update statistics with a new packet
void stats_add_packet(packet_info_t *packet) {
    int i, found;
    
    // Update total counts
    stats.total_packets++;
    stats.total_bytes += packet->length;
    
    // Update protocol counts
    switch (packet->protocol) {
        case PROTO_TCP:
            stats.tcp_packets++;
            stats.tcp_bytes += packet->length;
            break;
        case PROTO_UDP:
            stats.udp_packets++;
            stats.udp_bytes += packet->length;
            break;
        case PROTO_ICMP:
            stats.icmp_packets++;
            break;
        case PROTO_ARP:
            stats.arp_packets++;
            break;
        case PROTO_HTTP:
            stats.http_packets++;
            stats.tcp_packets++;  // HTTP is over TCP
            stats.tcp_bytes += packet->length;
            break;
        case PROTO_HTTPS:
            stats.https_packets++;
            stats.tcp_packets++;  // HTTPS is over TCP
            stats.tcp_bytes += packet->length;
            break;
        case PROTO_DNS:
            stats.dns_packets++;
            stats.udp_packets++;  // DNS is typically over UDP
            stats.udp_bytes += packet->length;
            break;
        case PROTO_DHCP:
            stats.dhcp_packets++;
            stats.udp_packets++;  // DHCP is over UDP
            stats.udp_bytes += packet->length;
            break;
        default:
            stats.other_packets++;
            break;
    }
    
    // Only track IP-based traffic for top talkers
    if (strlen(packet->src_ip) > 0 && strlen(packet->dst_ip) > 0) {
        // Update top sources
        found = 0;
        for (i = 0; i < MAX_TOP_ENTRIES; i++) {
            if (strcmp(stats.top_sources[i].ip, packet->src_ip) == 0) {
                // Found existing entry
                stats.top_sources[i].count++;
                stats.top_sources[i].bytes += packet->length;
                found = 1;
                break;
            }
        }
        
        if (!found) {
            // Entry not found, check if we have space or need to replace lowest count
            for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                if (stats.top_sources[i].count == 0) {
                    // Empty slot available
                    strcpy(stats.top_sources[i].ip, packet->src_ip);
                    stats.top_sources[i].count = 1;
                    stats.top_sources[i].bytes = packet->length;
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                // No empty slots, sort and possibly replace the lowest count
                qsort(stats.top_sources, MAX_TOP_ENTRIES, sizeof(stats.top_sources[0]), compare_by_count);
                
                // Check if the new entry has a higher count than the lowest
                // (always 1 for a new entry, so this won't happen, but logic is here for future updates)
                if (1 > stats.top_sources[MAX_TOP_ENTRIES-1].count) {
                    strcpy(stats.top_sources[MAX_TOP_ENTRIES-1].ip, packet->src_ip);
                    stats.top_sources[MAX_TOP_ENTRIES-1].count = 1;
                    stats.top_sources[MAX_TOP_ENTRIES-1].bytes = packet->length;
                }
            }
        }
        
        // Update top destinations (same logic as sources)
        found = 0;
        for (i = 0; i < MAX_TOP_ENTRIES; i++) {
            if (strcmp(stats.top_destinations[i].ip, packet->dst_ip) == 0) {
                // Found existing entry
                stats.top_destinations[i].count++;
                stats.top_destinations[i].bytes += packet->length;
                found = 1;
                break;
            }
        }
        
        if (!found) {
            // Entry not found, check if we have space or need to replace lowest count
            for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                if (stats.top_destinations[i].count == 0) {
                    // Empty slot available
                    strcpy(stats.top_destinations[i].ip, packet->dst_ip);
                    stats.top_destinations[i].count = 1;
                    stats.top_destinations[i].bytes = packet->length;
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                // No empty slots, sort and possibly replace the lowest count
                qsort(stats.top_destinations, MAX_TOP_ENTRIES, sizeof(stats.top_destinations[0]), compare_by_count);
                
                // Check if the new entry has a higher count than the lowest
                if (1 > stats.top_destinations[MAX_TOP_ENTRIES-1].count) {
                    strcpy(stats.top_destinations[MAX_TOP_ENTRIES-1].ip, packet->dst_ip);
                    stats.top_destinations[MAX_TOP_ENTRIES-1].count = 1;
                    stats.top_destinations[MAX_TOP_ENTRIES-1].bytes = packet->length;
                }
            }
        }
        
        // Update top ports for TCP and UDP
        if (packet->protocol == PROTO_TCP || packet->protocol == PROTO_UDP || 
            packet->protocol == PROTO_HTTP || packet->protocol == PROTO_HTTPS || 
            packet->protocol == PROTO_DNS || packet->protocol == PROTO_DHCP) {
            
            // Track source port
            found = 0;
            for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                if (stats.top_ports[i].port == packet->src_port) {
                    stats.top_ports[i].count++;
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                    if (stats.top_ports[i].count == 0) {
                        stats.top_ports[i].port = packet->src_port;
                        stats.top_ports[i].count = 1;
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    qsort(stats.top_ports, MAX_TOP_ENTRIES, sizeof(stats.top_ports[0]), compare_ports_by_count);
                    
                    if (1 > stats.top_ports[MAX_TOP_ENTRIES-1].count) {
                        stats.top_ports[MAX_TOP_ENTRIES-1].port = packet->src_port;
                        stats.top_ports[MAX_TOP_ENTRIES-1].count = 1;
                    }
                }
            }
            
            // Track destination port
            found = 0;
            for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                if (stats.top_ports[i].port == packet->dst_port) {
                    stats.top_ports[i].count++;
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                for (i = 0; i < MAX_TOP_ENTRIES; i++) {
                    if (stats.top_ports[i].count == 0) {
                        stats.top_ports[i].port = packet->dst_port;
                        stats.top_ports[i].count = 1;
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    qsort(stats.top_ports, MAX_TOP_ENTRIES, sizeof(stats.top_ports[0]), compare_ports_by_count);
                    
                    if (1 > stats.top_ports[MAX_TOP_ENTRIES-1].count) {
                        stats.top_ports[MAX_TOP_ENTRIES-1].port = packet->dst_port;
                        stats.top_ports[MAX_TOP_ENTRIES-1].count = 1;
                    }
                }
            }
        }
    }
    
    // Update time for rate calculations
    stats.current_time = time(NULL);
}

// Calculate data rates
void stats_update_rates() {
    time_t now = time(NULL);
    time_t elapsed = now - stats.start_time;
    
    if (elapsed > 0) {
        stats.packets_per_sec = stats.total_packets / elapsed;
        stats.bytes_per_sec = stats.total_bytes / elapsed;
    } else {
        stats.packets_per_sec = stats.total_packets;
        stats.bytes_per_sec = stats.total_bytes;
    }
    
    stats.current_time = now;
    
    // Resort the top lists
    qsort(stats.top_sources, MAX_TOP_ENTRIES, sizeof(stats.top_sources[0]), compare_by_count);
    qsort(stats.top_destinations, MAX_TOP_ENTRIES, sizeof(stats.top_destinations[0]), compare_by_count);
    qsort(stats.top_ports, MAX_TOP_ENTRIES, sizeof(stats.top_ports[0]), compare_ports_by_count);
}

// Get the global stats structure
traffic_stats_t *stats_get() {
    return &stats;
}

// Reset statistics
void stats_reset() {
    stats_init();
}