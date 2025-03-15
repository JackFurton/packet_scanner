# Packet Sniffer

A network packet sniffer written in C that captures and analyzes network traffic with a colorized interactive terminal UI.

## Features

- **Interactive Terminal UI**:
  - Colorized packet list with protocol-based highlighting
  - Detailed packet inspection view with hex dump
  - Real-time statistics dashboard with protocol distribution graphs
  - Vim-style navigation with keyboard shortcuts (j/k, g/G, etc.)
  - Detailed packet examination mode
  - Live packet capture display with pause/resume functionality
  - Smart scrolling with auto-follow for new packets

- **Network Analysis**:
  - Captures packets from any network interface
  - Analyzes Ethernet, IP, TCP, UDP, and higher-level protocols
  - Identifies application protocols like HTTP, HTTPS, DNS
  - Displays packet payload data in hexadecimal and ASCII format

- **Smart Interface Selection**:
  - Automatically selects interfaces with active IPv4 addresses
  - Shows available network interfaces with details
  - Supports manual interface selection via command line

- **Flexible Filtering**:
  - BPF (Berkeley Packet Filter) syntax support
  - Filter by protocol, port, host, and more
  - Command-line filter specification

## Requirements

- C compiler (gcc or clang)
- libpcap development package
- ncurses library
- pthread support
- Root/sudo privileges (required for packet capturing)

### Installing Dependencies on macOS

```bash
brew install libpcap ncurses
```

### Installing Dependencies on Ubuntu/Debian

```bash
sudo apt-get install libpcap-dev libncurses-dev
```

## Building the Project

```bash
make
```

This will compile the project and create the executable in the `bin` directory.

## Running the Program

### With Interactive UI (Default)

```bash
sudo make run
```

This launches the packet sniffer with the full-featured ncurses interface.

### Console Mode (Text-Only)

To run in legacy console mode without the UI:

```bash
sudo make run-console
```

### Command Line Options

```bash
# Specify interface
sudo ./bin/packet_sniffer [interface_name]

# Disable UI
sudo ./bin/packet_sniffer --no-ui [interface_name]

# Specify capture filter
sudo ./bin/packet_sniffer [interface_name] "[filter_expression]"
```

For example:

```bash
# Capture HTTP traffic on en0 with UI
sudo ./bin/packet_sniffer en0 "tcp port 80 or tcp port 443"

# Capture DNS traffic on en0 without UI
sudo ./bin/packet_sniffer --no-ui en0 "udp port 53"
```

## Interactive UI Controls

The ncurses interface provides Vim-like keyboard navigation:

### Basic Controls

- **q**: Quit the application
- **p**: Pause/resume packet capture
- **a**: Toggle auto-scroll mode (automatically follows new packets)
- **s**: Toggle statistics view (shows traffic analysis dashboard)
- **r**: Reset statistics (when in statistics view)
- **Enter**: Enter detailed packet view mode
- **ESC**: Exit current view mode (stats or details)

### Vim Navigation

- **j/k** or **↑/↓**: Navigate up/down through packets
- **g**: Jump to first packet
- **G**: Jump to last packet
- **[number]G**: Jump to packet number
- **H**: Jump to top of screen
- **M**: Jump to middle of screen
- **L**: Jump to bottom of screen
- **Ctrl+F** or **Page Down**: Page down
- **Ctrl+B** or **Page Up**: Page up
- **Ctrl+D**: Half page down
- **Ctrl+U**: Half page up
- **[number]+command**: Repeat command (e.g., "5j" to move down 5 packets)

## Traffic Statistics Dashboard

The statistics view (`s` key) provides real-time traffic analysis:

- **Overview Metrics**:
  - Total packet count and data volume
  - Current bandwidth usage (bytes/sec and packets/sec)
  - Session duration

- **Protocol Distribution**:
  - Protocol counts (TCP, UDP, ICMP, ARP)
  - Visual graphs of protocol distribution
  - Application protocol statistics (HTTP, HTTPS, DNS, DHCP)

- **Traffic Analysis**:
  - Top source and destination IP addresses
  - Top active ports with service identification
  - Automatically updated as new packets arrive

## Protocol Color Coding

The UI highlights packets based on protocol:
- **TCP**: Green
- **UDP**: Yellow
- **ICMP**: Magenta
- **ARP**: Blue
- **HTTP**: Red
- **DNS**: Cyan

## Filter Syntax

The filter syntax follows the Berkeley Packet Filter (BPF) format used by tcpdump. Examples:

```
tcp                      # TCP traffic only
udp port 53              # DNS queries and responses
host 192.168.1.1         # Traffic to/from specific host
port 80 or port 443      # Web traffic
```

## Extending the Program

Future enhancements could include:
1. Packet capture save/load from PCAP files
2. More detailed protocol analyzers (HTTP headers, DNS query parsing)
3. Packet statistics and traffic analysis
4. Enhanced filtering capabilities within the UI

## License

This project is open source and available under the MIT License.