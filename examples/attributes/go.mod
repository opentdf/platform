module github.com/opentdf/opentdf-v2-poc/examples/attributes

go 1.21.5

replace github.com/opentdf/opentdf-v2-poc/sdk => ../../sdk

require (
	github.com/opentdf/opentdf-v2-poc/sdk v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.60.1
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.31.0-20231115204500-e097f827e652.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.1 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231120223509-83a465c0220f // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
