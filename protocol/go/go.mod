module github.com/opentdf/platform/protocol/go

go 1.25.0

toolchain go1.25.9

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.34.1-20240508200655-46a4cf4ba109.1
	connectrpc.com/connect v1.19.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.10
)

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
