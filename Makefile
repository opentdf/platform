# make
# To run all lint checks: `LINT_OPTIONS= make lint`

.PHONY: all build clean docker-build fix go-lint lint proto-generate proto-lint test toolcheck

EXCLUDE_OPENAPI=./service/authorization/idp_plugin.proto

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

LINT_OPTIONS?=--new
# LINT_OPTIONS?=-new-from-rev=main
# LINT_OPTIONS?=-c $(ROOT_DIR)/.golangci-ratchet.yaml

all: toolcheck clean build lint test

toolcheck:
	@echo "Checking for required tools..."
	@which buf > /dev/null || (echo "buf not found, please install it from https://docs.buf.build/installation" && exit 1)
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, run  'go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.56.2'" && exit 1)
	@which protoc-gen-doc > /dev/null || (echo "protoc-gen-doc not found, run 'go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1'" && exit 1)
	@golangci-lint --version | grep "version v\?1.5[67]" > /dev/null || (echo "golangci-lint version must be v1.55 [$$(golangci-lint --version)]" && exit 1)

fix:
	go mod tidy && go fmt ./...

lint: proto-lint go-lint

proto-lint:
	buf lint service || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

go-lint:
	golangci-lint run $(LINT_OPTIONS)

proto-generate:
	rm -rf protocol/go/[a-fh-z]* docs/grpc docs/openapi
	buf generate service
	buf generate service --template buf.gen.grpc.docs.yaml
	buf generate service --exclude-path $(EXCLUDE_OPENAPI) --template buf.gen.openapi.docs.yaml
	
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen --template buf.gen.grpc.docs.yaml
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen --template buf.gen.openapi.docs.yaml

test:
	go test ./... -race

clean:
	go clean
	rm -f opentdf example

build: proto-generate opentdf example

opentdf: $(shell find service)
	go build -o opentdf -v service/main.go

example: $(shell find examples)
	go build -o example ./examples/main.go

docker-build: build
	docker build -t opentdf .
