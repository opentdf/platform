FROM cgr.dev/chainguard/go@sha256:c894bc454800817b1747c8a1a640ae6d86004b06190f94e791098e7e78dbbc00 AS builder

WORKDIR /app
# dependencies, add local,dependant package here
COPY go.mod go.sum ./
COPY protocol/ protocol/
COPY sdk/ sdk/
RUN go mod download \
    && go mod verify
# copy .go files, add new package here
COPY main.go main.go
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
COPY policies/ policies/
COPY services/ services/
COPY protocol/ protocol/

RUN go build -o opentdf .

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/

CMD ["/usr/bin/opentdf"]
