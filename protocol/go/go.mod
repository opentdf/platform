module github.com/opentdf/platform/protocol/go

go 1.25.0

toolchain go1.25.8

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1
	connectrpc.com/connect v1.19.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260209200024-4cfbd4190f57
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
)

require (
	go.opentelemetry.io/otel v1.41.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.41.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260209200024-4cfbd4190f57 // indirect
)
