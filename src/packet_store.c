#include "../include/packet_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Storage for captured packets
static packet_info_t *packet_store = NULL;
static int packet_count = 0;
static int store_initialized = 0;

void packet_store_init() {
    if (store_initialized) {
        packet_store_clear();
    } else {
        packet_store = (packet_info_t *)malloc(MAX_PACKETS * sizeof(packet_info_t));
        if (!packet_store) {
            fprintf(stderr, "Failed to allocate memory for packet store\n");
            exit(1);
        }
        
        // Also allocate memory for each packet's data
        for (int i = 0; i < MAX_PACKETS; i++) {
            packet_store[i].data = NULL;
            packet_store[i].data_len = 0;
        }
        
        store_initialized = 1;
    }
    
    packet_count = 0;
}

int packet_store_add(const struct pcap_pkthdr *header, const u_char *packet) {
    if (!store_initialized) {
        packet_store_init();
    }
    
    // Check if store is full
    if (packet_count >= MAX_PACKETS) {
        // Circular buffer behavior: overwrite oldest packet
        free((void *)packet_store[0].data);
        
        // Shift all packets down one position
        memmove(&packet_store[0], &packet_store[1], (MAX_PACKETS - 1) * sizeof(packet_info_t));
        packet_count = MAX_PACKETS - 1;
    }
    
    // Store the new packet
    packet_info_t *info = &packet_store[packet_count];
    
    // Basic information - ensure consecutive numbering starting from 1
    info->number = packet_count + 1;  // 1-based indexing for display
    info->timestamp = header->ts;
    info->length = header->len;
    
    // Allocate memory for the packet data
    info->data = (u_char *)malloc(header->caplen);
    if (!info->data) {
        fprintf(stderr, "Failed to allocate memory for packet data\n");
        return -1;
    }
    
    // Copy the packet data
    memcpy((void *)info->data, packet, header->caplen);
    info->data_len = header->caplen;
    
    // Extract protocol information
    get_protocol_info(info->data, info);
    
    return packet_count++;
}

packet_info_t *packet_store_get(int index) {
    if (index < 0 || index >= packet_count || !store_initialized) {
        return NULL;
    }
    
    return &packet_store[index];
}

int packet_store_count() {
    return packet_count;
}

void packet_store_clear() {
    if (!store_initialized) {
        return;
    }
    
    // Free packet data memory
    for (int i = 0; i < packet_count; i++) {
        if (packet_store[i].data) {
            free((void *)packet_store[i].data);
            packet_store[i].data = NULL;
        }
    }
    
    packet_count = 0;
}

protocol_t identify_application_protocol(int src_port, int dst_port) {
    // Check common ports to identify protocols
    int port = (src_port < dst_port) ? src_port : dst_port;
    
    switch (port) {
        case 80:
            return PROTO_HTTP;
        case 443:
            return PROTO_HTTPS;
        case 53:
            return PROTO_DNS;
        case 67:
        case 68:
            return PROTO_DHCP;
        default:
            break;
    }
    
    port = (src_port > dst_port) ? src_port : dst_port;
    
    switch (port) {
        case 80:
            return PROTO_HTTP;
        case 443:
            return PROTO_HTTPS;
        case 53:
            return PROTO_DNS;
        case 67:
        case 68:
            return PROTO_DHCP;
        default:
            break;
    }
    
    return PROTO_UNKNOWN;
}

void get_protocol_info(const u_char *packet, packet_info_t *info) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Format MAC addresses
    snprintf(info->src_mac, sizeof(info->src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0], eth_header->ether_shost[1],
             eth_header->ether_shost[2], eth_header->ether_shost[3],
             eth_header->ether_shost[4], eth_header->ether_shost[5]);
    
    snprintf(info->dst_mac, sizeof(info->dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_dhost[0], eth_header->ether_dhost[1],
             eth_header->ether_dhost[2], eth_header->ether_dhost[3],
             eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    // Default values
    info->protocol = PROTO_UNKNOWN;
    strcpy(info->src_ip, "");
    strcpy(info->dst_ip, "");
    info->src_port = 0;
    info->dst_port = 0;
    strcpy(info->info, "");
    
    // Process based on EtherType
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Get IP addresses
        inet_ntop(AF_INET, &(ip_header->ip_src), info->src_ip, sizeof(info->src_ip));
        inet_ntop(AF_INET, &(ip_header->ip_dst), info->dst_ip, sizeof(info->dst_ip));
        
        // Process based on IP protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                
                info->src_port = ntohs(tcp_header->th_sport);
                info->dst_port = ntohs(tcp_header->th_dport);
                
                // Identify application protocol
                protocol_t app_proto = identify_application_protocol(info->src_port, info->dst_port);
                if (app_proto != PROTO_UNKNOWN) {
                    info->protocol = app_proto;
                } else {
                    info->protocol = PROTO_TCP;
                }
                
                // Create info text
                char flags[8] = "";
                if (tcp_header->th_flags & TH_FIN) strcat(flags, "F");
                if (tcp_header->th_flags & TH_SYN) strcat(flags, "S");
                if (tcp_header->th_flags & TH_RST) strcat(flags, "R");
                if (tcp_header->th_flags & TH_PUSH) strcat(flags, "P");
                if (tcp_header->th_flags & TH_ACK) strcat(flags, "A");
                if (tcp_header->th_flags & TH_URG) strcat(flags, "U");
                
                snprintf(info->info, sizeof(info->info), "%d → %d [%s] Seq=%u Ack=%u Win=%d",
                         info->src_port, info->dst_port, flags,
                         ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack),
                         ntohs(tcp_header->th_win));
                break;
            }
            
            case IPPROTO_UDP: {
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                
                info->src_port = ntohs(udp_header->uh_sport);
                info->dst_port = ntohs(udp_header->uh_dport);
                
                // Identify application protocol
                protocol_t app_proto = identify_application_protocol(info->src_port, info->dst_port);
                if (app_proto != PROTO_UNKNOWN) {
                    info->protocol = app_proto;
                } else {
                    info->protocol = PROTO_UDP;
                }
                
                snprintf(info->info, sizeof(info->info), "%d → %d Len=%d",
                         info->src_port, info->dst_port, ntohs(udp_header->uh_ulen) - 8);
                break;
            }
            
            case IPPROTO_ICMP:
                info->protocol = PROTO_ICMP;
                snprintf(info->info, sizeof(info->info), "ICMP %s → %s", info->src_ip, info->dst_ip);
                break;
                
            default:
                snprintf(info->info, sizeof(info->info), "IP Protocol %d", ip_header->ip_p);
                break;
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        info->protocol = PROTO_ARP;
        snprintf(info->info, sizeof(info->info), "ARP");
    } else {
        snprintf(info->info, sizeof(info->info), "EtherType 0x%04x", ntohs(eth_header->ether_type));
    }
}

void add_protocol_details(packet_info_t *info __attribute__((unused)), 
                        const u_char *packet __attribute__((unused))) {
    // Additional protocol-specific details could be added here
}