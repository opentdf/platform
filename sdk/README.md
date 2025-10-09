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

### Registering Custom Assertion Providers

The SDK supports custom signing and validation logic for assertions through a flexible provider model. The recommended way to manage multiple, conditional providers is to use the `ProviderFactory`.

The `ProviderFactory` lets you register different providers for different assertions, matched via regular expressions on the assertion ID. It implements the `AssertionSigningProvider` and `AssertionValidationProvider` interfaces itself, so you can configure it once and pass it directly to the SDK.

This allows you to, for example, use a hardware-based signing provider for assertions with a `piv-` prefix, and a default provider for all others.

**Example:**

First, you need an implementation of the `AssertionSigningProvider` and/or `AssertionValidationProvider` interfaces. For this example, we'll create a simple mock.

```go
// my_custom_provider.go
package main

import (
	"context"
	"github.com/opentdf/platform/sdk"
)

// CustomSigner is a custom implementation of an assertion signing provider.
type CustomSigner struct {
	SignatureValue string
}

func (s *CustomSigner) Sign(ctx context.Context, assertion *sdk.Assertion, hash, sig string) (string, error) {
	// In a real implementation, you would use a hardware token, an external service, etc.
	return s.SignatureValue, nil
}

func (s *CustomSigner) GetSigningKeyReference() string {
	return "custom-signer-key-ref"
}

func (s *CustomSigner) GetAlgorithm() string {
	return "CUSTOM_SIG"
}
```

Next, register this provider with the factory and pass the factory to the SDK during TDF creation.

```go
// main.go
package main

import (
	"fmt"
	"github.com/opentdf/platform/sdk"
)

func main() {
	// 1. Create a new provider factory.
	factory := sdk.NewProviderFactory()

	// 2. Create an instance of your custom provider.
	mySigner := &CustomSigner{SignatureValue: "a-very-special-signature"}

	// 3. Register the provider with a regex pattern.
	// This will match any assertion ID that starts with "custom-".
	err := factory.RegisterSigningProvider(`^custom-`, mySigner)
	if err != nil {
		panic(err)
	}

	// You can also set a default provider for assertions that don't match any pattern.
	// factory.SetDefaultSigningProvider(sdk.NewDefaultSigningProvider(...))

	// 4. When creating a TDF, pass the factory directly as a provider.
	// The factory will dispatch to the correct underlying provider internally.
	_, err = s.CreateTDF(
		ciphertext,
		plaintext,
		sdk.WithDataAttributes("https://example.com/attr/Classification/value/Open"),
		sdk.WithAssertionSigningProvider(factory), // Pass the factory here
	)

	// Similarly, for reading TDFs:
	// reader, err := s.LoadTDF(input, sdk.WithAssertionValidationProvider(factory))

	fmt.Println("SDK configured to use custom provider factory.")
}
```

The factory will test assertion IDs against registered patterns in the order they were registered and use the first one that matches. If no patterns match, a default provider will be used if one has been set.

## Development

To test, run 

```sh
go test ./... -short -race -cover
```
