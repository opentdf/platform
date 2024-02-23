# multi-stage build
# reference https://docs.docker.com/develop/develop-images/multistage-build/
ARG GO_VERSION=latest

# builder - executable for deployment
# reference https://hub.docker.com/_/golang
FROM golang:$GO_VERSION as builder

RUN \
  go install github.com/bufbuild/buf/cmd/buf@v1.28.1 && \
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3 && \
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32

WORKDIR /build/
COPY go.mod ./
COPY go.sum ./
COPY makefile ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
COPY plugins/ plugins/
RUN make gokas
#RUN make go-plugins

# tester
FROM golang:$GO_VERSION as tester

RUN \
  go install github.com/bufbuild/buf/cmd/buf@v1.28.1 && \
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3 && \
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32

WORKDIR /test/
COPY go.mod ./
COPY go.sum ./
COPY makefile ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
COPY plugins/ plugins/
RUN go list -m -u all
RUN touch empty.tmp
RUN make test
# Validate that buf didn't generate new files
RUN find pkg/ -newer empty.tmp -and -type f > new.tmp
RUN diff new.tmp empty.tmp || true

# server-debug - root
FROM ubuntu:latest as server-debug
ENV SERVICE "default"
ENV LOG_LEVEL "DEBUG"
ENV LOG_FORMAT "TEXT"
ENV KAS_URL ""
ENV PKCS11_SLOT_INDEX "0"
ENV AUDIT_ENABLED=false
ENV SERVER_GRPC_PORT 5000
ENV SERVER_HTTP_PORT 8000
RUN apt-get update -y && apt-get install -y softhsm opensc openssl
COPY --from=builder /build/gokas /
COPY scripts/ scripts/
COPY softhsm2-debug.conf /etc/softhsm/softhsm2.conf
RUN chmod +x /etc/softhsm
RUN mkdir -p /secrets
RUN chown 10001 /secrets
ENTRYPOINT ["/scripts/run.sh"]

# server - production
FROM ubuntu:latest as server
ENV SERVICE "default"
# Server
ENV LOG_LEVEL "INFO"
ENV LOG_FORMAT "JSON"
ENV KAS_URL ""
ENV AUDIT_ENABLED=false
ENV SERVER_GRPC_PORT 5000
ENV SERVER_HTTP_PORT 8000
## trailing / is required
ENV OIDC_DISCOVERY_BASE_URL ""
ENV OIDC_ISSUER_URL ""
ENV OIDC_SERVER_URL ""
ENV OIDC_AUTHORIZATION_URL ""
ENV OIDC_TOKEN_URL ""
ENV OIDC_CONFIGURATION_URL ""
# PKCS#11
ENV PKCS11_MODULE_PATH ""
ENV PKCS11_PIN ""
ENV PKCS11_SLOT_INDEX ""
ENV PKCS11_LABEL_PUBKEY_RSA ""
ENV PKCS11_LABEL_PUBKEY_EC ""
RUN apt-get update -y && apt-get install -y softhsm opensc openssl

COPY --from=builder /build/gokas /
COPY scripts/ /scripts/
COPY softhsm2-prod.conf /etc/softhsm/softhsm2.conf
RUN chmod +x /etc/softhsm
RUN mkdir -p /secrets
RUN chown 10001 /secrets
ENTRYPOINT ["/scripts/run.sh"]
