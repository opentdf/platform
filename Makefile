# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=myapp

# Docker parameters
DOCKER_BUILD_CMD=docker build
DOCKER_IMAGE_NAME=opentdf

# Buf parameters
BUFLINT=buf lint proto
BUFGENERATE=buf generate proto

# GolangCI-Lint
GOLANGCILINT=golangci-lint run

.PHONY: all lint buf-lint buf-generate golangci-lint test clean build docker-build

all: lint test build

lint: buf-lint golangci-lint

buf-lint:
	@$(BUFLINT) || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

buf-generate:
	$(BUFGENERATE)

golangci-lint:
	$(GOLANGCILINT)

test:
	$(GOTEST) ./... -race

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

build:
	$(GOBUILD) -o $(BINARY_NAME) -v

docker-build: build
	$(DOCKER_BUILD_CMD) -t $(DOCKER_IMAGE_NAME) .

