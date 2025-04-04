module github.com/opentdf/platform/lib/cryptoProvider

go 1.24.1

replace github.com/opentdf/platform/protocol/go v0.2.29 => ../../protocol/go

require github.com/opentdf/platform/protocol/go v0.2.29

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.34.1-20240508200655-46a4cf4ba109.1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)
