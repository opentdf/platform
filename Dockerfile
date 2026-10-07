FROM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app
COPY .github/scripts/retry.sh /tmp/retry.sh
# Download dependencies before copying sources so code changes preserve this layer.
COPY go.work ./
COPY protocol/go/go.mod protocol/go/go.sum protocol/go/
COPY sdk/go.mod sdk/go.sum sdk/
COPY service/go.mod service/go.sum service/
COPY otdfctl/go.mod otdfctl/go.sum otdfctl/
COPY tests-bdd/go.mod tests-bdd/go.sum tests-bdd/
COPY lib/fixtures/go.mod lib/fixtures/go.sum lib/fixtures/
COPY lib/flattening/go.mod lib/flattening/go.sum lib/flattening/
COPY lib/identifier/go.mod lib/identifier/go.sum lib/identifier/
COPY lib/ocrypto/go.mod lib/ocrypto/go.sum lib/ocrypto/
RUN cd service \
    && sh /tmp/retry.sh go mod download \
    && sh /tmp/retry.sh go mod verify
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ lib/
COPY service/ service/
COPY otdfctl/ otdfctl/
COPY tests-bdd/ tests-bdd/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

ENTRYPOINT ["/usr/bin/opentdf"]
