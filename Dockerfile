FROM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app
COPY .github/scripts/retry.sh /tmp/retry.sh
# dependencies, add local,dependant package here
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ lib/
COPY service/ service/
COPY otdfctl/ otdfctl/
COPY examples/ examples/
COPY tests-bdd/ tests-bdd/
COPY go.work ./
RUN cd service \
    && sh /tmp/retry.sh go mod download \
    && sh /tmp/retry.sh go mod verify
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

ENTRYPOINT ["/usr/bin/opentdf"]
