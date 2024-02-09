# make
# To run all lint checks: `LINT_OPTIONS= make lint`

.PHONY: all toolcheck lint test clean build docker-build buf-generate sdk/sdk

LINT_OPTIONS?=--new

all: toolcheck lint test build

toolcheck:
	@echo "Checking for required tools..."
	@which buf > /dev/null || (echo "buf not found, please install it from https://docs.buf.build/installation" && exit 1)
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, please install it from https://golangci-lint.run/usage/install/" && exit 1)
	@which protoc-gen-doc > /dev/null || (echo "protoc-gen-doc not found, run 'go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1'" && exit 1)
	@golangci-lint --version | grep "version 1.5" > /dev/null || (echo "golangci-lint version must be v1.55 [$$(golangci-lint --version)]" && exit 1)

go.work go.work.sum:
	go work init . examples/attributes sdk

lint:
	buf lint proto || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)
	golangci-lint run $(LINT_OPTIONS)
	golangci-lint run $(LINT_OPTIONS) --path-prefix sdk
	golangci-lint run $(LINT_OPTIONS) --path-prefix examples/attributes

buf-generate:
	buf generate proto

test:
	go test ./... -race
	(cd sdk && go test ./... -race)
	(cd examples/attributes && go test ./... -race)

clean:
	go clean
	rm -f serviceapp

build: go.work serviceapp sdk/sdk examples/attributes/attributes

serviceapp: go.work go.mod go.sum main.go $(shell find cmd internal services)
	go build -o serviceapp -v ./main.go

sdk/sdk: go.work $(shell find sdk)
	(cd sdk && go build ./...)

examples/attributes/attributes: go.work $(shell find examples/attributes)
	(cd examples/attributes && go build -o attributes ./...)

docker-build: build
	docker build -t opentdf .
