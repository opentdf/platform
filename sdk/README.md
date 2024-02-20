# OpenTDF Data Security SDK

A Go implementation of the OpenTDF protocol, and access library for services
included in the Data Security Platform.

## Quick Start of the Go SDK

```go
package main

import bytes
import io
import os
import strings
import "github.com/opentdf/platform/sdk"


func main() {
  s := sdk.New(
    sdk.WithAuth(mtls.NewGRPCAuthorizer(creds) /* or OIDC or whatever */),
    sdk.WithDataSecurityConfig(/* attribute schemas, kas multi-attribute mapping */),
  )

  plaintext := strings.NewReader("Hello, world!")
  var ciphertext bytes.Buffer
  _, err := s.CreateTDF(
    ciphertext,
    plaintext,
    sdk.WithAttributes("https://example.com/attr/Classification/value/Open"),
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

## Development

To test, run 

```sh
go test ./... -short -race -cover
```
