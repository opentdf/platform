module github.com/opentdf/platform/examples

go 1.21.8

require (
	github.com/opentdf/platform/protocol/go v0.0.0-00010101000000-000000000000
	github.com/opentdf/platform/sdk v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.8.0
	google.golang.org/grpc v1.62.1
	google.golang.org/protobuf v1.33.0
)

replace (
	github.com/opentdf/platform/lib/ocrypto => ../lib/ocrypto
	github.com/opentdf/platform/protocol/go => ../protocol/go
	github.com/opentdf/platform/sdk => ../sdk
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.33.0-20240221180331-f05a6f4403ce.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.0.21 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/opentdf/platform/lib/ocrypto v0.0.0-00010101000000-000000000000 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240311173647-c811ad7063a7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240311173647-c811ad7063a7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
