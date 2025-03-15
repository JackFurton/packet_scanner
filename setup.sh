#!/bin/bash

# Set environment variables for libpcap
export LDFLAGS="-L/opt/homebrew/opt/libpcap/lib"
export CPPFLAGS="-I/opt/homebrew/opt/libpcap/include"

# Build the project
make

echo "Build complete. Run with 'sudo ./bin/packet_sniffer' or 'sudo make run'"