FROM cgr.dev/chainguard/go@sha256:c894bc454800817b1747c8a1a640ae6d86004b06190f94e791098e7e78dbbc00 AS builder

WORKDIR /app

COPY main.go main.go
COPY go.mod go.mod
COPY go.sum go.sum
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/
COPY gen/ gen/

#cache go deps
RUN go mod download \
    && go mod verify

RUN go build -o opentdf .

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

CMD ["/usr/bin/opentdf"]