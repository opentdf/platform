FROM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app
# dependencies, add local,dependant package here
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ocrypto lib/ocrypto
COPY lib/flattening lib/flattening
COPY lib/fixtures lib/fixtures
COPY keycloak-entity-resolution/ keycloak-entity-resolution/
COPY service/ service/
COPY examples/ examples/
COPY go.work go.work.sum ./
RUN cd service \
    && go mod download \
    && go mod verify
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

ENTRYPOINT ["/usr/bin/opentdf"]
