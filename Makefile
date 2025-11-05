# Name of your binary
BINARY_NAME = tls

# Directories
CMD_DIR = ./cmd/tls

# Default target
.PHONY: all
all: build

# Build the project
.PHONY: build
build:
	mkdir -p bin
	go build -o bin/$(BINARY_NAME) $(CMD_DIR)

# Run all tests
.PHONY: test
test:
	go test ./... -v

# Clean up build artifacts
.PHONY: clean
clean:
	rm -rf bin