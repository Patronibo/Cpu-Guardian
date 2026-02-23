CC      ?= gcc
CFLAGS  = -std=c17 -Wall -Wextra -Wpedantic -D_GNU_SOURCE
LDFLAGS = -lpthread -lm


PREFIX  ?= /usr/local
DESTDIR ?=

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/config.c \
       $(SRC_DIR)/pmu.c \
       $(SRC_DIR)/telemetry.c \
       $(SRC_DIR)/ringbuffer.c \
       $(SRC_DIR)/anomaly.c \
       $(SRC_DIR)/correlation.c \
       $(SRC_DIR)/logger.c \
       $(SRC_DIR)/ipc_socket.c

OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TARGET = $(BIN_DIR)/cpu-guardian

TEST_SRCS = $(TEST_DIR)/test_synthetic.c
TEST_TARGET = $(BIN_DIR)/test_synthetic

.PHONY: all
all: CFLAGS += -O2 -DNDEBUG
all: $(TARGET)

.PHONY: debug
debug: CFLAGS += -g -O0 -fsanitize=address,undefined -DDEBUG
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

.PHONY: test
test: CFLAGS += -O2
test: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean install
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

.PHONY: help
help:
	@echo "Usage:"
	@echo "  make          - Build release version"
	@echo "  make debug    - Build debug version with sanitizers"
	@echo "  make test     - Build synthetic test workloads"
	@echo "  make install  - Install to PREFIX (default /usr/local)"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make help     - Show this help"
