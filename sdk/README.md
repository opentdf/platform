# OpenTDF Data Security SDK

A Go implementation of the OpenTDF protocol, and access library for services
included in the Data Security Platform.

Note: if you are consuming the SDK as a submodule you may need to add replace directives as follows:

```go
replace (
  github.com/opentdf/platform/service => ./opentdf/service
	github.com/opentdf/platform/lib/fixtures => ./opentdf/lib/fixtures
	github.com/opentdf/platform/protocol/go => ./opentdf/protocol/go
	github.com/opentdf/platform/lib/ocrypto => ./opentdf/lib/ocrypto
	github.com/opentdf/platform/sdk => ./opentdf/sdk
	github.com/opentdf/platform/service => ./opentdf/service
)
```

## Quick Start of the Go SDK

```go
package main

import "fmt"
import "bytes"
import "io"
import "os"
import "strings"
import "github.com/opentdf/platform/sdk"


func main() {
  s, _ := sdk.New(
    sdk.WithAuth(mtls.NewGRPCAuthorizer(creds) /* or OIDC or whatever */),
    sdk.WithDataSecurityConfig(/* attribute schemas, kas multi-attribute mapping */),
  )

  plaintext := strings.NewReader("Hello, world!")
  var ciphertext bytes.Buffer
  _, err := s.CreateTDF(
    ciphertext,
    plaintext,
    sdk.WithDataAttributes("https://example.com/attr/Classification/value/Open"),
  )
  if err != nil {
    panic(err)
  }

  fmt.Printf("Ciphertext is %s bytes long", ciphertext.Len())

  ct2 := make([]byte, ciphertext.Len())
  copy(ct2, ciphertext.Bytes())
  r, err := s.NewTDFReader(bytes.NewReader(ct2))
  f, err := os.Create("output.txt")
  if err != nil {
    panic(err)
  }
  io.Copy(f, r)
}
```

## Base key

The platform may publish a base KAS public key in its well-known configuration. Retrieve it via:

```go
baseKey, err := s.GetBaseKey(ctx)
```

## Development

To test, run 

```sh
go test ./... -short -race -cover
```
