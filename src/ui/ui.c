#include "../../include/ui/ui.h"
#include "../../include/packet_store.h"
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

// Global UI state
static ui_t ui;

// Expose pause state for packet capture thread
int ui_paused = 0;

// Format timestamp as a string
static void format_timestamp(char *buf, size_t size, const struct timeval *tv) {
    struct tm *tm_info;
    char time_str[20];
    time_t raw_time = tv->tv_sec;
    
    tm_info = localtime(&raw_time);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    snprintf(buf, size, "%s.%06d", time_str, (int)tv->tv_usec);
}

// Initialize the UI
void ui_init() {
    // Initialize ncurses
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);  // Hide cursor
    timeout(100); // Non-blocking input
    
    // Initialize color pairs
    init_pair(COLOR_DEFAULT, COLOR_WHITE, COLOR_BLACK);
    init_pair(COLOR_HEADER, COLOR_BLACK, COLOR_WHITE);
    init_pair(COLOR_SELECTED, COLOR_BLACK, COLOR_CYAN);
    init_pair(COLOR_TCP, COLOR_GREEN, COLOR_BLACK);
    init_pair(COLOR_UDP, COLOR_YELLOW, COLOR_BLACK);
    init_pair(COLOR_ICMP, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(COLOR_ARP, COLOR_BLUE, COLOR_BLACK);
    init_pair(COLOR_HTTP, COLOR_RED, COLOR_BLACK);
    init_pair(COLOR_HTTPS, COLOR_RED, COLOR_BLACK);
    init_pair(COLOR_DNS, COLOR_CYAN, COLOR_BLACK);
    init_pair(COLOR_DHCP, COLOR_YELLOW, COLOR_BLACK);
    init_pair(COLOR_HELP, COLOR_BLACK, COLOR_GREEN);
    
    // Initialize UI state
    ui.active_window = 0;
    ui.selected_packet = -1;
    ui.list_offset = 0;
    ui.detail_offset = 0;
    ui.auto_scroll = 1;
    ui.paused = 0;
    ui.detail_mode = 0;
    ui.stats_mode = 0;
    ui.vim_count = 0;
    ui_paused = 0; // Initialize global state
    strcpy(ui.filter, "");
    
    // Initialize statistics
    stats_init();
    
    // Create windows
    ui_handle_resize();
}

// Clean up the UI
void ui_cleanup() {
    // Delete windows
    delwin(ui.header);
    delwin(ui.packet_list);
    delwin(ui.detail);
    delwin(ui.help);
    
    // End ncurses
    endwin();
}

// Handle window resize
void ui_handle_resize() {
    int screen_height, screen_width;
    
    // Get screen dimensions
    getmaxyx(stdscr, screen_height, screen_width);
    
    // Check minimum dimensions
    if (screen_width < MIN_SCREEN_WIDTH || screen_height < MIN_SCREEN_HEIGHT) {
        mvprintw(0, 0, "Terminal too small. Minimum size: %dx%d", 
                MIN_SCREEN_WIDTH, MIN_SCREEN_HEIGHT);
        return;
    }
    
    // Recalculate window dimensions
    int header_height = 3;
    int help_height = 2;
    int packet_list_height = (screen_height - header_height - help_height) / 2;
    int detail_height = screen_height - header_height - help_height - packet_list_height;
    
    // Delete old windows if they exist
    if (ui.header) delwin(ui.header);
    if (ui.packet_list) delwin(ui.packet_list);
    if (ui.detail) delwin(ui.detail);
    if (ui.help) delwin(ui.help);
    
    // Create new windows
    ui.header = newwin(header_height, screen_width, 0, 0);
    ui.packet_list = newwin(packet_list_height, screen_width, header_height, 0);
    ui.detail = newwin(detail_height, screen_width, header_height + packet_list_height, 0);
    ui.help = newwin(help_height, screen_width, screen_height - help_height, 0);
    
    // Enable scrolling for detail window
    scrollok(ui.detail, TRUE);
    
    // Draw windows
    ui_update();
}

// Get appropriate color for a protocol
int ui_get_protocol_color(protocol_t proto) {
    switch (proto) {
        case PROTO_TCP:
            return COLOR_TCP;
        case PROTO_UDP:
            return COLOR_UDP;
        case PROTO_ICMP:
            return COLOR_ICMP;
        case PROTO_ARP:
            return COLOR_ARP;
        case PROTO_HTTP:
            return COLOR_HTTP;
        case PROTO_HTTPS:
            return COLOR_HTTPS;
        case PROTO_DNS:
            return COLOR_DNS;
        case PROTO_DHCP:
            return COLOR_DHCP;
        default:
            return COLOR_DEFAULT;
    }
}

// Get protocol name as a string
const char *get_protocol_name(protocol_t proto) {
    switch (proto) {
        case PROTO_TCP:
            return "TCP";
        case PROTO_UDP:
            return "UDP";
        case PROTO_ICMP:
            return "ICMP";
        case PROTO_ARP:
            return "ARP";
        case PROTO_HTTP:
            return "HTTP";
        case PROTO_HTTPS:
            return "HTTPS";
        case PROTO_DNS:
            return "DNS";
        case PROTO_DHCP:
            return "DHCP";
        default:
            return "Unknown";
    }
}

// Draw the packet list
void ui_draw_packet_list() {
    int height, width;
    int i, row;
    char time_str[32];
    
    // Get window dimensions
    getmaxyx(ui.packet_list, height, width);
    
    // Adjust for header and borders
    height -= 2;
    
    // Clear the window
    werase(ui.packet_list);
    
    // Draw header
    wattron(ui.packet_list, A_REVERSE);
    mvwprintw(ui.packet_list, 0, 0, "%4s %-12s %-15s %-15s %-10s %-15s", 
              "No.", "Time", "Source", "Destination", "Protocol", "Info");
    wattroff(ui.packet_list, A_REVERSE);
    
    // Draw packet list
    int packet_count = packet_store_count();
    
    // Auto-scroll logic
    if (ui.auto_scroll && packet_count > 0 && !ui.paused) {
        // Automatically select the last packet
        ui.selected_packet = packet_count - 1;
        
        // Calculate the first packet to display
        ui.list_offset = packet_count - height;
        if (ui.list_offset < 0) {
            ui.list_offset = 0;
        }
    }
    
    // Ensure selected packet is visible
    if (ui.selected_packet < ui.list_offset) {
        ui.list_offset = ui.selected_packet;
    } else if (ui.selected_packet >= ui.list_offset + height) {
        ui.list_offset = ui.selected_packet - height + 1;
    }
    
    // Ensure offset is within valid range
    if (ui.list_offset < 0) {
        ui.list_offset = 0;
    } else if (packet_count > 0 && ui.list_offset > packet_count - 1) {
        ui.list_offset = packet_count - 1;
    }
    
    // Draw visible packets
    for (i = ui.list_offset, row = 1; i < packet_count && row <= height; i++, row++) {
        packet_info_t *packet = packet_store_get(i);
        
        if (packet) {
            // Format timestamp
            format_timestamp(time_str, sizeof(time_str), &packet->timestamp);
            
            // Determine source and destination
            char source[48] = "";
            char dest[48] = "";
            
            if (strlen(packet->src_ip) > 0) {
                if (packet->src_port > 0) {
                    snprintf(source, sizeof(source), "%s:%d", packet->src_ip, packet->src_port);
                } else {
                    snprintf(source, sizeof(source), "%s", packet->src_ip);
                }
            } else {
                snprintf(source, sizeof(source), "%s", packet->src_mac);
            }
            
            if (strlen(packet->dst_ip) > 0) {
                if (packet->dst_port > 0) {
                    snprintf(dest, sizeof(dest), "%s:%d", packet->dst_ip, packet->dst_port);
                } else {
                    snprintf(dest, sizeof(dest), "%s", packet->dst_ip);
                }
            } else {
                snprintf(dest, sizeof(dest), "%s", packet->dst_mac);
            }
            
            // Highlight selected packet
            if (i == ui.selected_packet) {
                wattron(ui.packet_list, COLOR_PAIR(COLOR_SELECTED) | A_BOLD);
            } else {
                wattron(ui.packet_list, COLOR_PAIR(ui_get_protocol_color(packet->protocol)));
            }
            
            // Print packet info with consistent number format (always show at least 4 digits)
            mvwprintw(ui.packet_list, row, 0, "%4d %-12s %-15.15s %-15.15s %-10s %-15.15s", 
                      packet->number, time_str, source, dest, 
                      get_protocol_name(packet->protocol), packet->info);
            
            // Reset attributes
            if (i == ui.selected_packet) {
                wattroff(ui.packet_list, COLOR_PAIR(COLOR_SELECTED) | A_BOLD);
            } else {
                wattroff(ui.packet_list, COLOR_PAIR(ui_get_protocol_color(packet->protocol)));
            }
        }
    }
    
    // Draw border
    box(ui.packet_list, 0, 0);
    mvwprintw(ui.packet_list, 0, 2, " Packets (%d) ", packet_count);
    
    // Refresh window
    wrefresh(ui.packet_list);
}

// Draw packet hex dump
void draw_hex_dump(WINDOW *win, int y, int x, const u_char *data, int len, int max_rows) {
    int i, j, rows = 0;
    char ascii[17];
    ascii[16] = '\0';
    
    for (i = 0; i < len && rows < max_rows; i += 16) {
        mvwprintw(win, y + rows, x, "%04x: ", i);
        
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                wprintw(win, "%02x ", data[i + j]);
                ascii[j] = isprint(data[i + j]) ? data[i + j] : '.';
            } else {
                wprintw(win, "   ");
                ascii[j] = ' ';
            }
            
            if (j == 7) {
                wprintw(win, " ");
            }
        }
        
        wprintw(win, " |%s|", ascii);
        rows++;
    }
}

// Draw the packet detail view
void ui_draw_packet_detail() {
    int height, width;
    
    // Get window dimensions
    getmaxyx(ui.detail, height, width);
    
    // Clear the window
    werase(ui.detail);
    
    // Draw selected packet details
    if (ui.selected_packet >= 0) {
        packet_info_t *packet = packet_store_get(ui.selected_packet);
        
        if (packet) {
            int y = 1;
            char time_str[32];
            
            // Format timestamp
            format_timestamp(time_str, sizeof(time_str), &packet->timestamp);
            
            // Print packet summary
            mvwprintw(ui.detail, y++, 2, "Packet: %d   Timestamp: %s   Length: %d bytes", 
                     packet->number, time_str, packet->length);
            y++;
            
            // Print Ethernet header
            wattron(ui.detail, A_BOLD);
            mvwprintw(ui.detail, y++, 2, "Ethernet Header:");
            wattroff(ui.detail, A_BOLD);
            mvwprintw(ui.detail, y++, 4, "Source MAC: %s", packet->src_mac);
            mvwprintw(ui.detail, y++, 4, "Destination MAC: %s", packet->dst_mac);
            y++;
            
            // Print IP header if available
            if (strlen(packet->src_ip) > 0) {
                wattron(ui.detail, A_BOLD);
                mvwprintw(ui.detail, y++, 2, "IP Header:");
                wattroff(ui.detail, A_BOLD);
                mvwprintw(ui.detail, y++, 4, "Source IP: %s", packet->src_ip);
                mvwprintw(ui.detail, y++, 4, "Destination IP: %s", packet->dst_ip);
                y++;
            }
            
            // Print protocol-specific info
            wattron(ui.detail, A_BOLD);
            mvwprintw(ui.detail, y++, 2, "%s Header:", get_protocol_name(packet->protocol));
            wattroff(ui.detail, A_BOLD);
            
            if (packet->protocol == PROTO_TCP || packet->protocol == PROTO_UDP ||
                packet->protocol == PROTO_HTTP || packet->protocol == PROTO_HTTPS || 
                packet->protocol == PROTO_DNS || packet->protocol == PROTO_DHCP) {
                mvwprintw(ui.detail, y++, 4, "Source Port: %d", packet->src_port);
                mvwprintw(ui.detail, y++, 4, "Destination Port: %d", packet->dst_port);
                mvwprintw(ui.detail, y++, 4, "Info: %s", packet->info);
                y++;
            }
            
            // Print hex dump
            wattron(ui.detail, A_BOLD);
            mvwprintw(ui.detail, y++, 2, "Payload Data (%d bytes):", packet->data_len);
            wattroff(ui.detail, A_BOLD);
            
            // Leave room for borders and headers
            int max_hex_rows = height - y - 2;
            if (max_hex_rows > 0) {
                draw_hex_dump(ui.detail, y, 4, packet->data, packet->data_len, max_hex_rows);
            }
        }
    } else {
        mvwprintw(ui.detail, 1, 2, "No packet selected");
    }
    
    // Draw border
    box(ui.detail, 0, 0);
    mvwprintw(ui.detail, 0, 2, " Packet Details ");
    
    // Refresh window
    wrefresh(ui.detail);
}

// Draw the header/status bar
void ui_draw_header() {
    int width;
    char status[256];
    
    // Get window width
    getmaxyx(ui.header, (int){0}, width);
    
    // Clear the window
    werase(ui.header);
    
    // Draw title
    wattron(ui.header, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvwprintw(ui.header, 0, 0, "Packet Sniffer v2.0");
    
    // Draw status
    if (ui.paused) {
        snprintf(status, sizeof(status), "PAUSED");
    } else {
        snprintf(status, sizeof(status), "CAPTURING");
    }
    
    mvwprintw(ui.header, 0, width - strlen(status), "%s", status);
    wattroff(ui.header, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    
    // Draw filter
    mvwprintw(ui.header, 1, 0, "Filter: %s", strlen(ui.filter) > 0 ? ui.filter : "[none]");
    
    // Refresh window
    wrefresh(ui.header);
}

// Draw the help/command bar
void ui_draw_help() {
    // Clear the window
    werase(ui.help);
    
    // Draw appropriate help text based on mode
    wattron(ui.help, COLOR_PAIR(COLOR_HELP));
    
    if (ui.stats_mode) {
        mvwprintw(ui.help, 0, 0, " q:Quit  ESC/s:Back  r:Reset Stats  Graphs update automatically as packets are captured ");
    } else if (ui.detail_mode) {
        mvwprintw(ui.help, 0, 0, " q:Quit  ESC/Enter:Back  ↑/↓,j/k:Navigate  g/G:Top/Bottom  Ctrl+D/U:Half Page  Ctrl+F/B:Page ");
    } else {
        mvwprintw(ui.help, 0, 0, " q:Quit  p:Pause  a:Auto  s:Stats  j/k:Nav  g/G:Top/Bot  Enter:Detail  [NUM]+CMD:Repeat ");
    }
    
    wattroff(ui.help, COLOR_PAIR(COLOR_HELP));
    
    // Refresh window
    wrefresh(ui.help);
}

// Draw the full packet view
void ui_draw_full_packet_view() {
    int packet_height, packet_width;
    int detail_height, detail_width;
    
    // Get window dimensions
    getmaxyx(ui.packet_list, packet_height, packet_width);
    getmaxyx(ui.detail, detail_height, detail_width);
    
    // Combined height for the detailed view
    // Combined height (not used but kept for future reference)
    __attribute__((unused)) int combined_height = packet_height + detail_height;
    
    // Clear both windows
    werase(ui.packet_list);
    werase(ui.detail);
    
    // Draw borders
    box(ui.packet_list, 0, 0);
    mvwprintw(ui.packet_list, 0, 2, " Full Packet View ");
    
    if (ui.selected_packet >= 0) {
        packet_info_t *packet = packet_store_get(ui.selected_packet);
        
        if (packet) {
            int y = 1;
            char time_str[32];
            
            // Format timestamp
            format_timestamp(time_str, sizeof(time_str), &packet->timestamp);
            
            // Print packet summary
            mvwprintw(ui.packet_list, y++, 2, "Packet: %d   Timestamp: %s   Length: %d bytes", 
                     packet->number, time_str, packet->length);
            y++;
            
            // Print Ethernet header
            wattron(ui.packet_list, A_BOLD);
            mvwprintw(ui.packet_list, y++, 2, "Ethernet Header:");
            wattroff(ui.packet_list, A_BOLD);
            mvwprintw(ui.packet_list, y++, 4, "Source MAC: %s", packet->src_mac);
            mvwprintw(ui.packet_list, y++, 4, "Destination MAC: %s", packet->dst_mac);
            y++;
            
            // Print IP header if available
            if (strlen(packet->src_ip) > 0) {
                wattron(ui.packet_list, A_BOLD);
                mvwprintw(ui.packet_list, y++, 2, "IP Header:");
                wattroff(ui.packet_list, A_BOLD);
                mvwprintw(ui.packet_list, y++, 4, "Source IP: %s", packet->src_ip);
                mvwprintw(ui.packet_list, y++, 4, "Destination IP: %s", packet->dst_ip);
                y++;
            }
            
            // Print protocol-specific info
            wattron(ui.packet_list, A_BOLD);
            mvwprintw(ui.packet_list, y++, 2, "%s Header:", get_protocol_name(packet->protocol));
            wattroff(ui.packet_list, A_BOLD);
            
            if (packet->protocol == PROTO_TCP || packet->protocol == PROTO_UDP ||
                packet->protocol == PROTO_HTTP || packet->protocol == PROTO_HTTPS || 
                packet->protocol == PROTO_DNS || packet->protocol == PROTO_DHCP) {
                mvwprintw(ui.packet_list, y++, 4, "Source Port: %d", packet->src_port);
                mvwprintw(ui.packet_list, y++, 4, "Destination Port: %d", packet->dst_port);
                mvwprintw(ui.packet_list, y++, 4, "Info: %s", packet->info);
                y++;
            }
            
            // Print full raw data dump in the detail window
            wattron(ui.detail, A_BOLD);
            mvwprintw(ui.detail, 1, 2, "Raw Packet Data (%d bytes):", packet->data_len);
            wattroff(ui.detail, A_BOLD);
            
            // Draw a large hex dump with as much data as possible
            int max_hex_rows = detail_height - 4;
            if (max_hex_rows > 0) {
                draw_hex_dump(ui.detail, 3, 2, packet->data, packet->data_len, max_hex_rows);
            }
            
            box(ui.detail, 0, 0);
            mvwprintw(ui.detail, 0, 2, " Hex Dump ");
        }
    } else {
        mvwprintw(ui.packet_list, 1, 2, "No packet selected");
    }
    
    // Refresh windows
    wrefresh(ui.packet_list);
    wrefresh(ui.detail);
}

// Helper to format a size with appropriate unit
void format_size(char *buf, size_t size, unsigned long long bytes) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size_value = bytes;
    
    while (size_value >= 1024 && unit < 4) {
        size_value /= 1024;
        unit++;
    }
    
    if (unit == 0) {
        snprintf(buf, size, "%llu %s", bytes, units[unit]);
    } else {
        snprintf(buf, size, "%.2f %s", size_value, units[unit]);
    }
}

// Draw an ASCII bar chart
void draw_bar_chart(WINDOW *win, int y, int x, int width, int value, int max_value, int attr) {
    int bar_width = 0;
    
    if (max_value > 0) {
        bar_width = (value * width) / max_value;
        if (bar_width > width) bar_width = width;
    }
    
    wattron(win, attr);
    for (int i = 0; i < bar_width; i++) {
        mvwprintw(win, y, x + i, "█");
    }
    wattroff(win, attr);
    
    // Print the value at the end of the bar
    mvwprintw(win, y, x + bar_width + 1, "(%d)", value);
}

// Draw the statistics view
void ui_draw_stats_view() {
    int __attribute__((unused)) packet_height, packet_width;
    int __attribute__((unused)) detail_height, detail_width;
    traffic_stats_t *stats = stats_get();
    char buffer[128];
    
    // Get window dimensions
    getmaxyx(ui.packet_list, packet_height, packet_width);
    getmaxyx(ui.detail, detail_height, detail_width);
    
    // Update statistics rates
    stats_update_rates();
    
    // Clear both windows
    werase(ui.packet_list);
    werase(ui.detail);
    
    // Draw borders
    box(ui.packet_list, 0, 0);
    box(ui.detail, 0, 0);
    
    mvwprintw(ui.packet_list, 0, 2, " Traffic Statistics ");
    mvwprintw(ui.detail, 0, 2, " Protocol Distribution ");
    
    // Draw session info
    int y = 1;
    mvwprintw(ui.packet_list, y++, 2, "Session duration: %ld seconds", stats->current_time - stats->start_time);
    mvwprintw(ui.packet_list, y++, 2, "Total packets:    %d", stats->total_packets);
    
    // Format total bytes
    format_size(buffer, sizeof(buffer), stats->total_bytes);
    mvwprintw(ui.packet_list, y++, 2, "Total data:       %s", buffer);
    
    // Format rate info
    format_size(buffer, sizeof(buffer), stats->bytes_per_sec);
    mvwprintw(ui.packet_list, y++, 2, "Current rate:     %s/sec (%d pkts/sec)", buffer, stats->packets_per_sec);
    
    y++;
    wattron(ui.packet_list, A_BOLD);
    mvwprintw(ui.packet_list, y++, 2, "Protocol Summary:");
    wattroff(ui.packet_list, A_BOLD);
    
    mvwprintw(ui.packet_list, y, 2, "TCP:  %d packets", stats->tcp_packets);
    format_size(buffer, sizeof(buffer), stats->tcp_bytes);
    mvwprintw(ui.packet_list, y++, 25, "%s", buffer);
    
    mvwprintw(ui.packet_list, y, 2, "UDP:  %d packets", stats->udp_packets);
    format_size(buffer, sizeof(buffer), stats->udp_bytes);
    mvwprintw(ui.packet_list, y++, 25, "%s", buffer);
    
    mvwprintw(ui.packet_list, y, 2, "ICMP: %d packets", stats->icmp_packets);
    y++;
    
    mvwprintw(ui.packet_list, y, 2, "ARP:  %d packets", stats->arp_packets);
    y++;
    
    y++;
    wattron(ui.packet_list, A_BOLD);
    mvwprintw(ui.packet_list, y++, 2, "Top Sources:");
    wattroff(ui.packet_list, A_BOLD);
    
    for (int i = 0; i < 5 && i < MAX_TOP_ENTRIES; i++) {
        if (stats->top_sources[i].count > 0) {
            mvwprintw(ui.packet_list, y, 2, "%-15s", stats->top_sources[i].ip);
            format_size(buffer, sizeof(buffer), stats->top_sources[i].bytes);
            mvwprintw(ui.packet_list, y++, 20, "%5d pkts  %s", 
                     stats->top_sources[i].count, buffer);
        }
    }
    
    y++;
    wattron(ui.packet_list, A_BOLD);
    mvwprintw(ui.packet_list, y++, 2, "Top Destinations:");
    wattroff(ui.packet_list, A_BOLD);
    
    for (int i = 0; i < 5 && i < MAX_TOP_ENTRIES; i++) {
        if (stats->top_destinations[i].count > 0) {
            mvwprintw(ui.packet_list, y, 2, "%-15s", stats->top_destinations[i].ip);
            format_size(buffer, sizeof(buffer), stats->top_destinations[i].bytes);
            mvwprintw(ui.packet_list, y++, 20, "%5d pkts  %s", 
                     stats->top_destinations[i].count, buffer);
        }
    }
    
    // Draw protocol distribution graph in the detail window
    y = 1;
    
    wattron(ui.detail, A_BOLD);
    mvwprintw(ui.detail, y++, 2, "Protocol Distribution (by packets):");
    wattroff(ui.detail, A_BOLD);
    y++;
    
    int max_packets = stats->total_packets > 0 ? stats->total_packets : 1;
    int graph_width = detail_width - 30;
    
    // Protocol distribution
    mvwprintw(ui.detail, y, 2, "TCP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->tcp_packets, max_packets, COLOR_PAIR(COLOR_TCP));
    
    mvwprintw(ui.detail, y, 2, "UDP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->udp_packets, max_packets, COLOR_PAIR(COLOR_UDP));
    
    mvwprintw(ui.detail, y, 2, "ICMP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->icmp_packets, max_packets, COLOR_PAIR(COLOR_ICMP));
    
    mvwprintw(ui.detail, y, 2, "ARP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->arp_packets, max_packets, COLOR_PAIR(COLOR_ARP));
    
    y++;
    
    // Application protocol distribution
    wattron(ui.detail, A_BOLD);
    mvwprintw(ui.detail, y++, 2, "Application Protocol Distribution:");
    wattroff(ui.detail, A_BOLD);
    y++;
    
    mvwprintw(ui.detail, y, 2, "HTTP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->http_packets, max_packets, COLOR_PAIR(COLOR_HTTP));
    
    mvwprintw(ui.detail, y, 2, "HTTPS");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->https_packets, max_packets, COLOR_PAIR(COLOR_HTTPS));
    
    mvwprintw(ui.detail, y, 2, "DNS");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->dns_packets, max_packets, COLOR_PAIR(COLOR_DNS));
    
    mvwprintw(ui.detail, y, 2, "DHCP");
    draw_bar_chart(ui.detail, y++, 10, graph_width, stats->dhcp_packets, max_packets, COLOR_PAIR(COLOR_DHCP));
    
    y += 2;
    
    // Top ports
    wattron(ui.detail, A_BOLD);
    mvwprintw(ui.detail, y++, 2, "Top Ports:");
    wattroff(ui.detail, A_BOLD);
    
    for (int i = 0; i < 5 && i < MAX_TOP_ENTRIES; i++) {
        if (stats->top_ports[i].count > 0) {
            const char *service = "Unknown";
            
            // Map common ports to service names
            switch (stats->top_ports[i].port) {
                case 80: service = "HTTP"; break;
                case 443: service = "HTTPS"; break;
                case 53: service = "DNS"; break;
                case 22: service = "SSH"; break;
                case 25: service = "SMTP"; break;
                case 21: service = "FTP"; break;
                case 23: service = "Telnet"; break;
                case 110: service = "POP3"; break;
                case 143: service = "IMAP"; break;
                case 67: case 68: service = "DHCP"; break;
                case 123: service = "NTP"; break;
            }
            
            mvwprintw(ui.detail, y++, 2, "Port %-5d (%s): %d packets", 
                      stats->top_ports[i].port, service, stats->top_ports[i].count);
        }
    }
    
    // Refresh windows
    wrefresh(ui.packet_list);
    wrefresh(ui.detail);
}

// Update all windows
void ui_update() {
    ui_draw_header();
    
    if (ui.stats_mode) {
        ui_draw_stats_view();
    } else if (ui.detail_mode) {
        ui_draw_full_packet_view();
    } else {
        ui_draw_packet_list();
        ui_draw_packet_detail();
    }
    
    ui_draw_help();
}

// Select a packet
void ui_select_packet(int index) {
    int count = packet_store_count();
    
    if (index < 0) {
        index = 0;
    } else if (index >= count) {
        index = count - 1;
    }
    
    if (index >= 0 && index < count) {
        ui.selected_packet = index;
        ui.detail_offset = 0;
    }
}

// Process a vim-style numeric count 
void process_vim_count(int digit) {
    ui.vim_count = ui.vim_count * 10 + digit;
}

// Process user input
int ui_process_input() {
    int ch = getch();
    int packet_count = packet_store_count();
    
    if (ch == ERR) {
        return 0;  // No input available
    }
    
    // Handle digit input for vim count
    if (ch >= '0' && ch <= '9') {
        if (ch == '0' && ui.vim_count == 0) {
            // First 0 is treated as "go to start of line" in vim
            // Not applicable here, so we'll ignore
        } else {
            process_vim_count(ch - '0');
        }
        return 0;
    }
    
    // Get motion count (default to 1 if none specified)
    int count = (ui.vim_count > 0) ? ui.vim_count : 1;
    
    // Reset count after processing command
    ui.vim_count = 0;
    
    switch (ch) {
        case 'q':
        case 'Q':
            return 1;  // Quit
            
        case 'p':
        case 'P':
            ui_toggle_pause();
            break;
            
        // Vim motion: k = up
        case 'k':
        case KEY_UP:
            for (int i = 0; i < count; i++) {
                if (ui.selected_packet > 0) {
                    ui_select_packet(ui.selected_packet - 1);
                    ui.auto_scroll = 0;
                }
            }
            break;
            
        // Vim motion: j = down
        case 'j':
        case KEY_DOWN:
            for (int i = 0; i < count; i++) {
                if (ui.selected_packet < packet_count - 1) {
                    ui_select_packet(ui.selected_packet + 1);
                    ui.auto_scroll = 0;
                }
            }
            break;
            
        // Vim motion: H = high (top of screen)
        case 'H':
            if (packet_count > 0) {
                ui_select_packet(ui.list_offset);
                ui.auto_scroll = 0;
            }
            break;
            
        // Vim motion: M = middle of screen
        case 'M':
            if (packet_count > 0) {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height = (height - 3) / 2;  // Half of visible area
                ui_select_packet(ui.list_offset + height);
                ui.auto_scroll = 0;
            }
            break;
            
        // Vim motion: L = low (bottom of screen)
        case 'L':
            if (packet_count > 0) {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height = height - 3;  // Last visible row
                ui_select_packet(ui.list_offset + height);
                ui.auto_scroll = 0;
            }
            break;
            
        // Vim motions: gg = start, G = end
        case 'g':
            if (packet_count > 0) {
                ui_select_packet(0);
                ui.auto_scroll = 0;
            }
            break;
            
        case 'G':
            if (packet_count > 0) {
                if (count > 1 && count <= packet_count) {
                    // Vim allows G with a count to go to that line number
                    ui_select_packet(count - 1);  // Convert to 0-indexed
                } else {
                    ui_select_packet(packet_count - 1);
                }
                ui.auto_scroll = 0;
            }
            break;
            
        // Vim-style: Ctrl+F = page down, Ctrl+B = page up
        case KEY_HOME:
        case 5:  // Ctrl+E - vim-like behavior
            if (packet_count > 0) {
                ui_select_packet(0);
                ui.auto_scroll = 0;
            }
            break;
            
        case KEY_END:
        case 25:  // Ctrl+Y - vim-like behavior
            if (packet_count > 0) {
                ui_select_packet(packet_count - 1);
                ui.auto_scroll = 0;
            }
            break;
            
        case KEY_PPAGE:  // Page Up
        case 2:          // Ctrl+B (vim-like)
            {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height -= 3; // Adjust for header and borders
                ui_select_packet(ui.selected_packet - height);
                ui.auto_scroll = 0;
            }
            break;
            
        case KEY_NPAGE:  // Page Down
        case 6:          // Ctrl+F (vim-like)
            {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height -= 3; // Adjust for header and borders
                ui_select_packet(ui.selected_packet + height);
                ui.auto_scroll = 0;
            }
            break;
            
        case 4:  // Ctrl+D - half page down (vim-like)
            {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height = (height - 3) / 2;  // Half page
                ui_select_packet(ui.selected_packet + height);
                ui.auto_scroll = 0;
            }
            break;
            
        case 21:  // Ctrl+U - half page up (vim-like)
            {
                int height;
                getmaxyx(ui.packet_list, height, (int){0});
                height = (height - 3) / 2;  // Half page
                ui_select_packet(ui.selected_packet - height);
                ui.auto_scroll = 0;
            }
            break;
            
        // Toggle auto-scroll
        case 'a':
        case 'A':
            ui.auto_scroll = !ui.auto_scroll;
            if (ui.auto_scroll && packet_count > 0) {
                ui_select_packet(packet_count - 1);
            }
            break;
            
        // Enter/exit detailed view mode
        case '\n':
        case KEY_ENTER:
        case 13:  // ASCII Enter
            if (ui.selected_packet >= 0) {
                ui.detail_mode = !ui.detail_mode;
            }
            break;
            
        // Toggle statistics view
        case 's':
        case 'S':
            if (ui.stats_mode) {
                ui.stats_mode = 0;
            } else if (!ui.detail_mode) {
                ui.stats_mode = 1;
            }
            break;
            
        // Reset statistics
        case 'r':
        case 'R':
            if (ui.stats_mode) {
                stats_reset();
            }
            break;
            
        // Additional keys to exit detailed view (Escape, q in detail mode)
        case 27:  // ESC key
            if (ui.detail_mode) {
                ui.detail_mode = 0;
            } else if (ui.stats_mode) {
                ui.stats_mode = 0;
            }
            break;
            
        // Vim-like refresh
        case 'l':
            // Force a refresh
            break;
            
        case KEY_RESIZE:
            ui_handle_resize();
            break;
    }
    
    return 0;
}

// Toggle pause/capture
void ui_toggle_pause() {
    ui.paused = !ui.paused;
    ui_paused = ui.paused; // Update the global state
}