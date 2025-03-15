# Packet Sniffer

A simple network packet sniffer written in C that captures and analyzes network traffic.

## Features

- Captures packets from a network interface
- Analyzes Ethernet, IP, TCP, and UDP headers
- Displays packet payload data in hexadecimal and ASCII format
- Supports both default interface selection and command-line interface specification

## Requirements

- C compiler (gcc or clang)
- libpcap development package
- Root/sudo privileges (required for packet capturing)

### Installing libpcap on macOS

```bash
brew install libpcap
```

## Building the Project

```bash
make
```

This will compile the project and create the executable in the `bin` directory.

## Running the Program

To run the program on the default network interface:

```bash
sudo make run
```

The program will list all available network interfaces and select the first one.

You can specify a network interface:

```bash
sudo ./bin/packet_sniffer <interface_name>
```

You can also specify a capture filter:

```bash
sudo ./bin/packet_sniffer <interface_name> "<filter_expression>"
```

For example:

```bash
# Capture on en0 interface
sudo ./bin/packet_sniffer en0

# Capture only HTTP traffic
sudo ./bin/packet_sniffer en0 "tcp port 80 or tcp port 443"

# Capture only DNS traffic
sudo ./bin/packet_sniffer en0 "udp port 53"

# Capture traffic to/from a specific IP
sudo ./bin/packet_sniffer en0 "host 192.168.1.1"
```

The filter syntax follows the Berkeley Packet Filter (BPF) format used by tcpdump.

## Output

The program provides detailed information about captured packets, including:

- Ethernet header (MAC addresses, packet type)
- IP header (version, addresses, protocol)
- TCP/UDP header (ports, flags, sequence numbers)
- Packet payload data in hex and ASCII format

## Extending the Program

Some ideas for extending the functionality:

1. Add packet filtering support
2. Implement protocol analysis for more protocols (HTTP, DNS, etc.)
3. Add packet statistics and summaries
4. Create a simple GUI interface
5. Add packet capture to file capabilities

## License

This project is open source and available under the MIT License.