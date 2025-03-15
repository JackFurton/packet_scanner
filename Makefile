CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap -lncurses -lpthread

# Check if we're on macOS (Darwin)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # Add Homebrew libpcap paths for macOS
    LIBPCAP_PATH = /opt/homebrew/opt/libpcap
    CFLAGS += -I$(LIBPCAP_PATH)/include
    LDFLAGS += -L$(LIBPCAP_PATH)/lib
endif

SRC_DIR = src
INC_DIR = include
BIN_DIR = bin

# Include subdirectories for source files
SRC_FILES = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)

# Generate object files in bin directory, maintaining directory structure
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRC_FILES))

EXECUTABLE = $(BIN_DIR)/packet_sniffer

.PHONY: all clean run run-console

all: $(BIN_DIR) $(EXECUTABLE)

# Make sure bin directory and subdirectories exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)
	mkdir -p $(BIN_DIR)/ui

$(EXECUTABLE): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Rule for top-level source files
$(BIN_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Rule for subdirectory source files
$(BIN_DIR)/ui/%.o: $(SRC_DIR)/ui/%.c
	mkdir -p $(BIN_DIR)/ui
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Run with UI (default)
run: all
	sudo $(EXECUTABLE)

# Run in console mode
run-console: all
	sudo $(EXECUTABLE) --no-ui

clean:
	rm -rf $(BIN_DIR)