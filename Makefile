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
	go build -o $(BINARY_NAME) $(CMD_DIR)

# Run all tests
.PHONY: test
test:
	go test ./... -v

# Clean up build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)