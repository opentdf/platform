# make
# To run all lint checks: `LINT_OPTIONS= make lint`

.PHONY: all build clean docker-build fix go-lint lint proto-generate proto-lint sdk/sdk test toolcheck

MODS=protocol/go sdk . examples

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

LINT_OPTIONS?=--new
# LINT_OPTIONS?=-c $(ROOT_DIR)/.golangci-ratchet.yaml

all: toolcheck clean build lint test

toolcheck:
	@echo "Checking for required tools..."
	@which buf > /dev/null || (echo "buf not found, please install it from https://docs.buf.build/installation" && exit 1)
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, please install it from https://golangci-lint.run/usage/install/" && exit 1)
	@which protoc-gen-doc > /dev/null || (echo "protoc-gen-doc not found, run 'go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1'" && exit 1)
	@golangci-lint --version | grep "version 1.55" > /dev/null || (echo "golangci-lint version must be v1.55 [$$(golangci-lint --version)]" && exit 1)

go.work go.work.sum:
	go work init . examples protocol/go sdk
	go work edit --go=1.21.8

fix:
	for m in $(MODS); do (cd $$m && go mod tidy && go fmt ./...) || exit 1; done

lint: proto-lint go-lint

proto-lint:
	buf lint services || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

go-lint:
	for m in $(MODS); do (cd $$m && golangci-lint run $(LINT_OPTIONS) --path-prefix=$$m) || exit 1; done

proto-generate:
	rm -rf sdkjava/src protocol/go/[a-fh-z]*
	buf generate services
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen
	cp -r tmp-gen/sdkjava/src/main/java/grpc sdkjava/src/main/java/grpc
	rm -rf tmp-gen

test:
	go test ./... -race
	(cd sdk && go test ./... -race)
	(cd examples && go test ./... -race)

clean:
	for m in $(MODS); do (cd $$m && go clean) || exit 1; done
	rm -f opentdf examples/examples go.work go.work.sum

build: go.work proto-generate opentdf sdk/sdk examples/examples

opentdf: go.work go.mod go.sum main.go $(shell find cmd internal services)
	go build -o opentdf -v ./main.go

sdk/sdk: go.work $(shell find sdk)
	(cd sdk && go build ./...)

examples/examples: go.work $(shell find examples)
	(cd examples && go build -o examples .)

docker-build: build
	docker build -t opentdf .
