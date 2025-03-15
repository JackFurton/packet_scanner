CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

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

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%.o, $(SRC_FILES))
EXECUTABLE = $(BIN_DIR)/packet_sniffer

.PHONY: all clean run

all: $(BIN_DIR) $(EXECUTABLE)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(EXECUTABLE): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

run: all
	sudo $(EXECUTABLE)

clean:
	rm -rf $(BIN_DIR)