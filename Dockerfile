FROM cgr.dev/chainguard/go:latest AS builder
ARG TARGETOS TARGETARCH

WORKDIR /app
# dependencies, add local,dependant package here
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY lib/ lib/
COPY service/ service/
COPY examples/ examples/
COPY tests-bdd/ tests-bdd/
COPY go.work ./
RUN cd service \
    && go mod download \
    && go mod verify
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o opentdf ./service

FROM alpine:3.20 AS embedded-postgres-binaries
ARG TARGETOS TARGETARCH
ARG EMBEDDED_POSTGRES_VERSION=15.13.0
RUN apk add --no-cache curl unzip xz tar
RUN test "$TARGETOS" = "linux"
RUN case "$TARGETARCH" in \
      amd64) EMBED_ARCH="amd64" ;; \
      arm64) EMBED_ARCH="arm64v8" ;; \
      *) echo "unsupported TARGETARCH for embedded postgres: $TARGETARCH" && exit 1 ;; \
    esac && \
    BASE_URL="https://repo1.maven.org/maven2/io/zonky/test/postgres" && \
    ARTIFACT="embedded-postgres-binaries-linux-${EMBED_ARCH}" && \
    JAR_URL="${BASE_URL}/${ARTIFACT}/${EMBEDDED_POSTGRES_VERSION}/${ARTIFACT}-${EMBEDDED_POSTGRES_VERSION}.jar" && \
    mkdir -p /tmp/embedded-pg /out && \
    curl -fsSL "$JAR_URL" -o /tmp/embedded-pg/binaries.jar && \
    unzip -q /tmp/embedded-pg/binaries.jar -d /tmp/embedded-pg/jar && \
    TXZ="$(find /tmp/embedded-pg/jar -name '*.txz' | head -n 1)" && \
    test -n "$TXZ" && \
    tar -xJf "$TXZ" -C /out

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/
COPY --from=embedded-postgres-binaries /out /opt/opentdf/embedded-postgres/binaries

ENTRYPOINT ["/usr/bin/opentdf"]
