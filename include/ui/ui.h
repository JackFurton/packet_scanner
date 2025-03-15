#ifndef UI_H
#define UI_H

#include <ncurses.h>
#include "../packet_store.h"
#include "stats.h"

// Window dimensions
#define MIN_SCREEN_WIDTH 80
#define MIN_SCREEN_HEIGHT 24

// UI Windows
typedef struct {
    WINDOW *header;      // Title and status
    WINDOW *packet_list; // List of captured packets
    WINDOW *detail;      // Details of selected packet
    WINDOW *help;        // Help/commands bar
    
    // Current state
    int active_window;   // Which window has focus
    int selected_packet; // Index of the currently selected packet
    int list_offset;     // Scroll offset in packet list
    int detail_offset;   // Scroll offset in detail view
    char filter[256];    // Current active filter
    
    // Display settings
    int auto_scroll;     // Auto-scroll to latest packet
    int paused;          // Capture paused
    int detail_mode;     // 0=normal view, 1=detail view
    int stats_mode;      // 0=normal view, 1=statistics view
    int vim_count;       // Numeric argument for vim commands (e.g. 5j)
} ui_t;

// Color pairs
#define COLOR_DEFAULT    1
#define COLOR_HEADER     2
#define COLOR_SELECTED   3
#define COLOR_TCP        4
#define COLOR_UDP        5
#define COLOR_ICMP       6
#define COLOR_ARP        7
#define COLOR_HTTP       8
#define COLOR_HTTPS      9
#define COLOR_DNS        10
#define COLOR_DHCP       11
#define COLOR_HELP       12

// Initialize the UI
void ui_init();

// Clean up the UI
void ui_cleanup();

// Process user input
int ui_process_input();

// Update the display
void ui_update();

// Handle window resize
void ui_handle_resize();

// Draw the packet list
void ui_draw_packet_list();

// Draw the packet detail view
void ui_draw_packet_detail();

// Draw the full packet view (when in detail mode)
void ui_draw_full_packet_view();

// Draw the statistics view
void ui_draw_stats_view();

// Draw the header/status bar
void ui_draw_header();

// Draw the help/command bar
void ui_draw_help();

// Toggle pause/capture
void ui_toggle_pause();

// Apply a display filter
void ui_set_filter(const char *filter);

// Set the selected packet
void ui_select_packet(int index);

// Get the appropriate color for a protocol
int ui_get_protocol_color(protocol_t proto);

// Handle keyboard commands
void ui_handle_command(int key);

#endif /* UI_H */