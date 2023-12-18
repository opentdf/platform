# Go parameters
V_GOCMD=go
V_GOBUILD=$(V_GOCMD) build
V_GOCLEAN=$(V_GOCMD) clean
V_GOTEST=$(V_GOCMD) test
V_BINARY_NAME=myapp

# Docker parameters
V_DOCKER_BUILD_CMD=docker build
V_DOCKER_IMAGE_NAME=opentdf

# Buf parameters
V_BUFLINT=buf lint proto
V_BUFGENERATE=buf generate proto

# GolangCI-Lint
V_GOLANGCILINT=golangci-lint run

.PHONY: all lint buf-lint buf-generate golangci-lint test clean build docker-build

all: lint test build

lint: buf-lint golangci-lint

buf-lint:
	@$(V_BUFLINT) || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

buf-generate:
	$(V_BUFGENERATE)

golangci-lint:
	$(V_GOLANGCILINT)

test-short:
	$(V_GOTEST) ./... -race -short

test:
	$(V_GOTEST) ./... -race

clean:
	$(V_GOCLEAN)
	rm -f $(V_BINARY_NAME)

build:
	$(V_GOBUILD) -o $(V_BINARY_NAME) -v

docker-build: build
	$(V_DOCKER_BUILD_CMD) -t $(V_DOCKER_IMAGE_NAME) .

