BINARY_NAME ?= tools-server
IMAGE_NAME ?= tools-server
IMAGE_TAG ?= latest
BIN_DIR ?= bin
KEY_FILE ?= $(BIN_DIR)/client.jwk

.PHONY: all build run docker-build docker-run clean help

all: build

## build: Build the Go binary into bin/
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/server

## run: Build and run the binary locally, generating the OIDC client key if it is missing
run: build
	@test -f $(KEY_FILE) || ./$(BIN_DIR)/$(BINARY_NAME) -generate-key
	./$(BIN_DIR)/$(BINARY_NAME)

## docker-build: Build the container image
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

## docker-run: Run the container image locally
docker-run:
	docker run --rm -p 8080:8080 $(IMAGE_NAME):$(IMAGE_TAG)

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

## help: Display this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':'
