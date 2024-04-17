FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app
# dependencies, add local,dependant package here
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ocrypto lib/ocrypto
COPY lib/fixtures lib/fixtures
COPY service/ service/
COPY examples/ examples/
COPY go.work go.work.sum ./
RUN cd service \
    && go mod download \
    && go mod verify
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

CMD ["/usr/bin/opentdf"]
