#include "../include/packet_sniffer.h"

void packet_handler(u_char *user_data __attribute__((unused)), 
                  const struct pcap_pkthdr *pkthdr, 
                  const u_char *packet) {
    static int packet_count = 0;
    packet_count++;
    
    // Get timestamp
    struct tm *tm_info;
    char time_str[30];
    time_t raw_time = pkthdr->ts.tv_sec;
    tm_info = localtime(&raw_time);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("\n\n=== Packet #%d Captured at %s.%06d ===\n", 
           packet_count, time_str, (int)pkthdr->ts.tv_usec);
    printf("Packet length: %d bytes\n", pkthdr->len);
    printf("Captured length: %d bytes\n", pkthdr->caplen);
    
    // Start analyzing the packet at the Ethernet layer
    analyze_ethernet(packet);
    
    // Flush stdout to ensure output appears immediately
    fflush(stdout);
}

void analyze_ethernet(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    printf("\n=== Ethernet Header ===\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth_header->ether_shost[0], eth_header->ether_shost[1], 
        eth_header->ether_shost[2], eth_header->ether_shost[3], 
        eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        eth_header->ether_dhost[0], eth_header->ether_dhost[1], 
        eth_header->ether_dhost[2], eth_header->ether_dhost[3], 
        eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    // Check if it's an IP packet (type 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("Type: IP (0x0800)\n");
        analyze_ip(packet + sizeof(struct ether_header));
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("Type: ARP (0x0806)\n");
        // ARP analysis could be added here
    } else {
        printf("Type: 0x%04x\n", ntohs(eth_header->ether_type));
    }
}

void analyze_ip(const u_char *packet) {
    struct ip *ip_header = (struct ip *) packet;
    
    printf("\n=== IP Header ===\n");
    printf("Version: %d\n", ip_header->ip_v);
    printf("Header Length: %d bytes\n", ip_header->ip_hl * 4);
    printf("Type of Service: %d\n", ip_header->ip_tos);
    printf("Total Length: %d bytes\n", ntohs(ip_header->ip_len));
    printf("Identification: 0x%04x\n", ntohs(ip_header->ip_id));
    printf("TTL: %d\n", ip_header->ip_ttl);
    printf("Protocol: ");
    
    // Process based on protocol type
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("TCP (6)\n");
            analyze_tcp(packet, ip_header->ip_hl * 4);
            break;
        case IPPROTO_UDP:
            printf("UDP (17)\n");
            analyze_udp(packet, ip_header->ip_hl * 4);
            break;
        case IPPROTO_ICMP:
            printf("ICMP (1)\n");
            break;
        default:
            printf("Other (%d)\n", ip_header->ip_p);
    }
    
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

void analyze_tcp(const u_char *packet, int ip_header_length) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header_length);
    
    printf("\n=== TCP Header ===\n");
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    printf("Header Length: %d bytes\n", tcp_header->th_off * 4);
    
    // TCP Flags
    printf("Flags: ");
    if (tcp_header->th_flags & TH_FIN) printf("FIN ");
    if (tcp_header->th_flags & TH_SYN) printf("SYN ");
    if (tcp_header->th_flags & TH_RST) printf("RST ");
    if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
    if (tcp_header->th_flags & TH_ACK) printf("ACK ");
    if (tcp_header->th_flags & TH_URG) printf("URG ");
    printf("\n");
    
    printf("Window Size: %d\n", ntohs(tcp_header->th_win));
    printf("Checksum: 0x%04x\n", ntohs(tcp_header->th_sum));
    printf("Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
    
    // Print data payload if any
    int tcp_header_size = tcp_header->th_off * 4;
    int ip_total_len = ((struct ip *)packet)->ip_len;
    int payload_length = ntohs(ip_total_len) - ip_header_length - tcp_header_size;
    
    if (payload_length > 0) {
        printf("\n=== TCP Payload (%d bytes) ===\n", payload_length);
        print_data(packet + ip_header_length + tcp_header_size, payload_length);
    }
}

void analyze_udp(const u_char *packet, int ip_header_length) {
    struct udphdr *udp_header = (struct udphdr *)(packet + ip_header_length);
    
    printf("\n=== UDP Header ===\n");
    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    printf("Length: %d\n", ntohs(udp_header->uh_ulen));
    printf("Checksum: 0x%04x\n", ntohs(udp_header->uh_sum));
    
    // Print data payload if any
    int udp_header_size = sizeof(struct udphdr);
    int ip_total_len = ((struct ip *)packet)->ip_len;
    int payload_length = ntohs(ip_total_len) - ip_header_length - udp_header_size;
    
    if (payload_length > 0) {
        printf("\n=== UDP Payload (%d bytes) ===\n", payload_length);
        print_data(packet + ip_header_length + udp_header_size, payload_length);
    }
}

void print_data(const u_char *data, int size) {
    int i, j;
    
    for (i = 0; i < size; i += 16) {
        printf("%04x: ", i);
        
        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            
            if (j == 7)
                printf(" ");
        }
        
        // Print ASCII values
        printf(" |");
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                if (data[i + j] >= 32 && data[i + j] <= 126)
                    printf("%c", data[i + j]);
                else
                    printf(".");
            } else {
                printf(" ");
            }
        }
        printf("|\n");
    }
}