FROM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app

# Copy and build the Go code
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ocrypto lib/ocrypto
COPY lib/flattening lib/flattening
COPY lib/fixtures lib/fixtures
COPY service/ service/
COPY examples/ examples/
COPY go.work go.work.sum ./
RUN cd service \
    && go mod download \
    && go mod verify
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

# Use the Chainguard Glibc-Dynamic image for the final stage
FROM cgr.dev/chainguard/glibc-dynamic:latest

# Copy the built binary from the builder
COPY --from=builder /app/opentdf /usr/bin/

# Set the entrypoint
ENTRYPOINT ["/usr/bin/opentdf"]

# Optionally switch to bash as a shell
CMD ["/bin/bash"]
