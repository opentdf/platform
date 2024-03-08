ARG GO_VERSION=latest

FROM golang:$GO_VERSION as builder

WORKDIR /app

COPY examples/ examples/
COPY protocol/ protocol/
COPY sdk/ sdk/
COPY .github/scripts/ /scripts/

COPY go.mod go.sum ./
RUN go mod download \
    && go mod verify

COPY Makefile ./
COPY main.go ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
COPY policies/ policies/
COPY services/ services/
COPY protocol/ protocol/
COPY pkg/ pkg/

RUN make opentdf

FROM builder as tester

RUN apt-get update -y && apt-get install -y softhsm opensc openssl
RUN /scripts/hsm-init-temporary-keys.sh

RUN make test

FROM cgr.dev/chainguard/glibc-dynamic

COPY --from=builder /app/opentdf /usr/bin/
COPY --from=builder /usr/lib/softhsm/ /usr/lib/softhsm/

CMD ["/usr/bin/opentdf"]
