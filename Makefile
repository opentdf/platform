# make
# To run all lint checks: `LINT_OPTIONS= make lint`

.PHONY: all build clean connect-wrapper-generate docker-build fix fmt go-lint license lint proto-generate proto-lint sdk/sdk test tidy toolcheck

MODS=protocol/go lib/ocrypto lib/fixtures lib/flattening lib/identifier sdk service examples
HAND_MODS=lib/ocrypto lib/fixtures lib/flattening lib/identifier sdk service examples
REQUIRED_BUF_VERSION=1.56.0

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# LINT_OPTIONS?=--new
# LINT_OPTIONS?=-new-from-rev=main
LINT_OPTIONS?=-c $(ROOT_DIR)/.golangci.yaml

all: toolcheck clean build lint license test

toolcheck:
	@echo "Checking for required tools..."
	@which buf > /dev/null || (echo "buf not found, please install it from https://docs.buf.build/installation" && exit 1)
	@BUF_VERSION=$$(buf --version | head -n 1 | awk '{print $$1}'); \
	if [ "$$(printf '%s\n' '$(REQUIRED_BUF_VERSION)' "$$BUF_VERSION" | sort -V | head -n 1)" != "$(REQUIRED_BUF_VERSION)" ]; then \
		echo "Error: buf version $(REQUIRED_BUF_VERSION) or later is required, but found $$BUF_VERSION."; \
		echo "Please upgrade buf. See https://docs.buf.build/installation for instructions."; \
		exit 1; \
	fi
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, run  'go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0'" && exit 1)
	@which protoc-gen-doc > /dev/null || (echo "protoc-gen-doc not found, run 'go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1'" && exit 1)
	@which protoc-gen-connect-openapi > /dev/null || (echo "protoc-gen-connect-openapi not found, run 'go install github.com/sudorandom/protoc-gen-connect-openapi@v0.18.0'" && exit 1)
	@required_golangci_lint_version="2.8.0"; \
	current_version=$$(golangci-lint --version | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^v//' | head -n 1); \
	[ "$$(printf '%s\n' "$$required_golangci_lint_version" "$$current_version" | sort -V | head -n1)" = "$$required_golangci_lint_version" ] || \
		(echo "golangci-lint version must be v$$required_golangci_lint_version or later [found: $$current_version]" && exit 1)
	@which goimports >/dev/null || (echo "goimports not found, run 'go install golang.org/x/tools/cmd/goimports@latest'")
	@govulncheck -version >/dev/null || (echo "govulncheck not found, run 'go install golang.org/x/vuln/cmd/govulncheck@latest'")

fix: tidy fmt

fmt:
	for m in $(HAND_MODS); do  golangci-lint fmt $$m || exit 1; done

tidy:
	for m in $(MODS); do (cd $$m && go mod tidy) || exit 1; done

license:
	for m in $(MODS); do (cd $$m && go run github.com/google/go-licenses@v1.6.0 check --disallowed_types=forbidden --include_tests ./) || exit 1; done

lint: proto-lint go-lint govulncheck

proto-lint:
	buf lint service || (exit_code=$$?; \
	 if [ $$exit_code -eq 100 ]; then \
      echo "Buf lint exited with code 100, treating as success"; \
		else \
			echo "Buf lint exited with code $$exit_code"; \
			exit $$exit_code; \
		fi)

go-lint:
	status=0; \
	for m in $(HAND_MODS); do \
		echo "Linting module: $$m"; \
		(cd "$$m" && golangci-lint run $(LINT_OPTIONS) ) || status=1; \
	done; \
	exit $$status

govulncheck:
	status=0; \
	for m in $(MODS); do \
		echo "govulncheck module: $$m"; \
		(cd "$$m" && govulncheck ./...) || status=1; \
	done; \
	exit $$status

proto-generate: toolcheck
	# remove all generated directories under protocol/go
	find protocol/go -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
	rm -rf docs/grpc docs/openapi
	buf generate service
	buf generate service --template buf.gen.grpc.docs.yaml
	buf generate service --template buf.gen.openapi.docs.yaml

	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen --template buf.gen.grpc.docs.yaml
	buf generate buf.build/grpc-ecosystem/grpc-gateway -o tmp-gen --template buf.gen.openapi.docs.yaml

	go run ./sdk/codegen

connect-wrapper-generate:
	go run ./sdk/codegen

policy-sql-gen:
	@which sqlc > /dev/null || { echo "sqlc not found, please install it: https://docs.sqlc.dev/en/stable/overview/install.html"; exit 1; }
	sqlc generate -f service/policy/db/sqlc.yaml

policy-erd-gen:
	@which mermerd > /dev/null || { echo "mermerd not found, please install it: https://github.com/KarnerTh/mermerd#installation"; exit 1; }
	# Docs: https://github.com/KarnerTh/mermerd#parametersflags
	mermerd -c 'postgresql://postgres:changeme@localhost:5432/opentdf' -e -o service/policy/db/schema_erd.md -s opentdf_policy --useAllTables --showDescriptions enumValues,columnComments
	# Add mermaid CSS to the end of the generated file
	@echo '\n<style>div.mermaid{overflow-x:scroll;}div.mermaid>svg{width:250rem;}</style>' >> service/policy/db/schema_erd.md

test:
	for m in $(HAND_MODS); do (cd $$m && go test ./... -race) || exit 1; done

fuzz:
	cd sdk && go test ./... -fuzztime=2m

bench:
	for m in $(HAND_MODS); do (cd $$m && go test -bench ./... -benchmem) || exit 1; done

clean:
	for m in $(MODS); do (cd $$m && go clean) || exit 1; done
	rm -f opentdf examples/examples

build: proto-generate connect-wrapper-generate opentdf sdk/sdk examples/examples

opentdf: $(shell find service)
	go build -o opentdf -v service/main.go

sdk/sdk: $(shell find sdk)
	(cd sdk && go build ./...)

examples/examples: $(shell find examples)
	(cd examples && go build -o examples .)

docker-build: build
	docker build -t opentdf .
