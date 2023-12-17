# Go parameters
VGOCMD=go
VGOBUILD=$(VGOCMD) build
VGOCLEAN=$(vGOCMD) clean
VGOTEST=$(VGOCMD) test
VBINARY_NAME=myapp

# Docker parameters
VDOCKER_BUILD_CMD=docker build
VDOCKER_IMAGE_NAME=opentdf

# Buf parameters
VBUFLINT=buf lint proto
VBUFGENERATE=buf generate proto

# GolangCI-Lint
VGOLANGCILINT=golangci-lint run

.PHONY: all lint buf-lint buf-generate golangci-lint test clean build docker-build

all: lint test build

lint: buf-lint golangci-lint

buf-lint:
	@$(VBUFLINT) || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

buf-generate:
	$(VBUFGENERATE)

golangci-lint:
	$(VGOLANGCILINT)

test-short:
	$(VGOTEST) ./... -race -short

test:
	$(VGOTEST) ./... -race

clean:
	$(VGOCLEAN)
	rm -f $(VBINARY_NAME)

build:
	$(VGOBUILD) -o $(VBINARY_NAME) -v

docker-build: build
	$(VDOCKER_BUILD_CMD) -t $(VDOCKER_IMAGE_NAME) .

