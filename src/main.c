#include "../include/packet_sniffer.h"
#include "../include/packet_store.h"
#include "../include/ui/ui.h"
#include "../include/ui/stats.h"
#include <signal.h>
#include <pthread.h>
#include <unistd.h> // For usleep

// Global variables for capture thread
static pcap_t *handle = NULL;
static int running = 1;
static pthread_t capture_thread;

void list_devices() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("\nAvailable network interfaces:\n");
    
    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
    
    // Print the list
    int i = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        
        // Check if the device has addresses
        int has_ipv4 = 0;
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
                printf(" [IPv4: %s]", ip);
                has_ipv4 = 1;
                break;
            }
        }
        
        if (!has_ipv4) {
            printf(" [No IPv4]");
        }
        
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    // Free the device list
    pcap_freealldevs(alldevs);
}

// New packet handler for UI mode
void ui_packet_handler(u_char *user_data __attribute__((unused)), 
                      const struct pcap_pkthdr *pkthdr, 
                      const u_char *packet) {
    // Check if we're paused - we access the ui state via an extern
    extern int ui_paused;
    
    // Only store the packet if we're not paused
    if (!ui_paused) {
        int idx = packet_store_add(pkthdr, packet);
        if (idx >= 0) {
            // Update statistics for the captured packet
            packet_info_t *info = packet_store_get(idx);
            if (info) {
                stats_add_packet(info);
            }
        }
    }
}

// Signal handler for clean termination
void signal_handler(int signum __attribute__((unused))) {
    running = 0;
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Capture thread function
void *capture_thread_func(void *arg __attribute__((unused))) {
    // Start the packet capture loop
    pcap_loop(handle, 0, ui_packet_handler, NULL);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    pcap_if_t *alldevs, *d;
    int use_ui = 1;  // Default to UI mode
    
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Check if UI mode is disabled
    if (argc > 1 && strcmp(argv[1], "--no-ui") == 0) {
        use_ui = 0;
        // Shift arguments
        argc--;
        argv++;
    }
    
    // Check for command line arguments
    if (argc > 1) {
        dev = argv[1];
    } else {
        // Find all available devices
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return 1;
        }
        
        // Display available interfaces if not using UI
        if (!use_ui) {
            list_devices();
        }
        
        // Try to find a suitable device with IPv4 address
        pcap_if_t *suitable_dev = NULL;
        
        for (d = alldevs; d; d = d->next) {
            // Look for a device with an IPv4 address
            for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    suitable_dev = d;
                    break;
                }
            }
            if (suitable_dev) break;
        }
        
        // If no suitable device found, try common names
        if (!suitable_dev) {
            // Common interface names to try
            const char *common_interfaces[] = {"en0", "eth0", "wlan0", "lo0", NULL};
            
            for (int i = 0; common_interfaces[i]; i++) {
                for (d = alldevs; d; d = d->next) {
                    if (strcmp(d->name, common_interfaces[i]) == 0) {
                        suitable_dev = d;
                        break;
                    }
                }
                if (suitable_dev) break;
            }
        }
        
        if (suitable_dev) {
            dev = suitable_dev->name;
            if (!use_ui) {
                printf("\nSelected device: %s\n", dev);
            }
        } else if (alldevs != NULL) {
            // Fall back to the first device if no suitable device found
            dev = alldevs->name;
            if (!use_ui) {
                printf("\nUsing first available device: %s (no better option found)\n", dev);
            }
        } else {
            fprintf(stderr, "No devices found\n");
            return 1;
        }
    }
    
    if (!use_ui) {
        printf("Sniffing on device: %s\n", dev);
    }
    
    // Open the device for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        if (argc <= 1) pcap_freealldevs(alldevs);
        return 2;
    }
    
    // Make sure we're capturing on an Ethernet device
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", dev);
        pcap_close(handle);
        if (argc <= 1) pcap_freealldevs(alldevs);
        return 3;
    }
    
    // Compile and apply a filter
    struct bpf_program fp;
    char filter_exp[256];
    
    // Select filter based on arguments or default
    if (argc > 2) {
        strncpy(filter_exp, argv[2], sizeof(filter_exp)-1);
        filter_exp[sizeof(filter_exp)-1] = '\0'; // Ensure null termination
    } else {
        // Default filter: TCP or UDP
        strcpy(filter_exp, "tcp or udp");
    }
    
    bpf_u_int32 net, mask;
    
    // Get the network address and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: Can't get netmask for device %s: %s\n", dev, errbuf);
        fprintf(stderr, "This may be normal for some interfaces. Continuing with default netmask.\n");
        net = 0;
        mask = 0;
    }
    
    // Compile the filter with PCAP_NETMASK_UNKNOWN for better compatibility
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        
        // Try with a simpler filter
        if (strcmp(filter_exp, "tcp or udp") != 0) {
            fprintf(stderr, "Trying with default filter 'tcp or udp' instead...\n");
            if (pcap_compile(handle, &fp, "tcp or udp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
                fprintf(stderr, "Still couldn't parse filter: %s\n", pcap_geterr(handle));
                pcap_close(handle);
                if (argc <= 1) pcap_freealldevs(alldevs);
                return 4;
            }
        } else {
            pcap_close(handle);
            if (argc <= 1) pcap_freealldevs(alldevs);
            return 4;
        }
    }
    
    // Apply the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        if (argc <= 1) pcap_freealldevs(alldevs);
        return 5;
    }
    
    if (!use_ui) {
        printf("Filter set to: %s\n", filter_exp);
        printf("Starting packet capture. Press Ctrl+C to stop.\n");
        printf("Waiting for packets...\n");
        
        // Start capturing packets in console mode
        pcap_loop(handle, 0, packet_handler, NULL);
    } else {
        // Initialize the packet store
        packet_store_init();
        
        // Initialize the UI
        ui_init();
        
        // Create the capture thread
        if (pthread_create(&capture_thread, NULL, capture_thread_func, NULL) != 0) {
            fprintf(stderr, "Failed to create capture thread\n");
            ui_cleanup();
            packet_store_clear();
            pcap_close(handle);
            if (argc <= 1) pcap_freealldevs(alldevs);
            return 6;
        }
        
        // Main UI loop
        while (running) {
            // Process user input
            if (ui_process_input()) {
                running = 0;
                break;
            }
            
            // Update the UI
            ui_update();
            
            // Sleep a bit to reduce CPU usage
            usleep(10000);  // 10ms
        }
        
        // Clean up UI
        ui_cleanup();
        
        // Stop the capture thread
        pcap_breakloop(handle);
        pthread_join(capture_thread, NULL);
        
        // Clear packet store
        packet_store_clear();
    }
    
    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    if (argc <= 1) pcap_freealldevs(alldevs);
    
    return 0;
}