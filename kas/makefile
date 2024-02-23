.PHONY: all clean test

all: gokas go-plugins pkg/access/service_grpc.pb.go pkg/access/service.pb.go
go-plugins: plugins/audit_hooks.so

GO_MOD_LINE = $(shell head -n 1 go.mod | cut -c 8-)
GO_MOD_NAME = ${GO_MOD_LINE}
CONF_PATH = ${GO_MOD_NAME}/internal/conf
VERSION = $(shell cat VERSION)
BUILD_TIME = $(shell date +'%Y-%m-%d_%T')
SHA1 = $(shell git rev-parse HEAD)
MAIN_FILE = cmd/microservice/main.go

gokas: pkg/access/service_grpc.pb.go pkg/access/service.pb.go $(shell find . -name "*.go" -and -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	go build -ldflags '-X ${CONF_PATH}.Version=${VERSION} -X ${CONF_PATH}.Sha1=${SHA1} -X ${CONF_PATH}.BuildTime=${BUILD_TIME}' -o gokas ${MAIN_FILE}

plugins/audit_hooks.so: $(shell find plugins -name "*.go")
	go build -buildmode=plugin -o="plugins/" plugins/**

pkg/access/service_grpc.pb.go pkg/access/service.pb.go pkg/access/service.pb.gw.go pkg/access/service.swagger.yaml: pkg/access/service.proto pkg/buf.lock pkg/buf.gen.yaml
	cd pkg && buf generate

clean:
	rm -f gokas
	find plugins -type f -name '*.so' | xargs rm
	find . -type f -name '*.pb.go' | xargs rm
	find . -type f -name '*.pb.gw.go' | xargs rm
	find . -type f -name '*.swagger.yaml' | xargs rm

test: gokas
	go vet ./...
	go test -bench=. -benchmem ./...
