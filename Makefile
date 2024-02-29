# make
# To run all lint checks: `LINT_OPTIONS= make lint`

.PHONY: all build clean docker-build fix go-lint lint proto-generate proto-lint sdk/sdk test toolcheck

MODS=protocol/go sdk . examples


LINT_OPTIONS?=--new

all: toolcheck clean build lint test

toolcheck:
	@echo "Checking for required tools..."
	@which buf > /dev/null || (echo "buf not found, please install it from https://docs.buf.build/installation" && exit 1)
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, please install it from https://golangci-lint.run/usage/install/" && exit 1)
	@which protoc-gen-doc > /dev/null || (echo "protoc-gen-doc not found, run 'go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1'" && exit 1)
	@golangci-lint --version | grep "version 1.55" > /dev/null || (echo "golangci-lint version must be v1.55 [$$(golangci-lint --version)]" && exit 1)

go.work go.work.sum:
	go work init . examples protocol/go sdk
	go work edit --go=1.21.7

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
	for m in $(MODS); do (golangci-lint run $(LINT_OPTIONS) --path-prefix=$$m) || exit 1; done

proto-generate:
	rm -rf sdkjava/src protocol/go/[a-fh-z]*
	buf generate services 

test:
	go test ./... -race
	(cd sdk && go test ./... -race)
	(cd examples && go test ./... -race)

clean:
	for m in $(MODS); do (cd $$m && go clean) || exit 1; done
	rm -f serviceapp examples/examples go.work go.work.sum

build: go.work proto-generate serviceapp sdk/sdk examples/examples

serviceapp: go.work go.mod go.sum main.go $(shell find cmd internal services)
	go build -o serviceapp -v ./main.go

sdk/sdk: go.work $(shell find sdk)
	(cd sdk && go build ./...)

examples/examples: go.work $(shell find examples)
	(cd examples && go build -o examples .)

docker-build: build
	docker build -t opentdf .
