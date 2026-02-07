# OpenTDF Data Security SDK

A Go implementation of the OpenTDF protocol, and access library for services
included in the Data Security Platform.

**New to the OpenTDF SDK?** See the [OpenTDF SDK Quickstart Guide](https://opentdf.io/category/sdk) for a comprehensive introduction.

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

## Example code

This example demonstrates how to create and read TDF (Trusted Data Format) files using the OpenTDF SDK.

**Prerequisites:** Follow the [OpenTDF Quickstart](https://opentdf.io/quickstart) to get a local platform running, or if you already have a hosted version, replace the values with your OpenTDF platform details.

For more code examples, see:
- [Creating TDFs](https://opentdf.io/sdks/tdf)
- [Managing policy](https://opentdf.io/sdks/policy)

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/opentdf/platform/sdk"
)

func main() {
	// Initialize SDK with platform endpoint and authentication
	// Replace these values with your actual configuration:
	platformEndpoint := "http://localhost:8080"           // Your platform URL
	clientID := "opentdf"                                 // Your OAuth client ID
	clientSecret := "secret"                              // Your OAuth client secret
	keycloakURL := "http://localhost:8888/auth/realms/opentdf" // Your Keycloak realm URL

	s, err := sdk.New(
		platformEndpoint,
		sdk.WithClientCredentials(clientID, clientSecret, []string{"email", "profile"}),
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": keycloakURL,
		}),
		sdk.WithInsecurePlaintextConn(), // Only for local development with HTTP
	)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}
	defer s.Close()

	// Create a TDF
	// This attribute is created in the quickstart guide
	dataAttribute := "https://opentdf.io/attr/department/value/finance"

	plaintext := strings.NewReader("Hello, world!")
	var ciphertext bytes.Buffer
	_, err = s.CreateTDF(
		&ciphertext,
		plaintext,
		sdk.WithDataAttributes(dataAttribute),
	)
	if err != nil {
		log.Fatalf("Failed to create TDF: %v", err)
	}

	fmt.Printf("Ciphertext is %d bytes long\n", ciphertext.Len())

	// Decrypt the TDF
	// LoadTDF contacts the Key Access Service (KAS) to verify that this client
	// has been granted access to the data attributes, then decrypts the TDF.
	// Note: The client must have entitlements configured on the platform first.
	r, err := s.LoadTDF(bytes.NewReader(ciphertext.Bytes()))
	if err != nil {
		log.Fatalf("Failed to load TDF: %v", err)
	}

	// Write the decrypted plaintext to a file
	f, err := os.Create("output.txt")
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer f.Close()

	_, err = io.Copy(f, r)
	if err != nil {
		log.Fatalf("Failed to write decrypted content: %v", err)
	}

	fmt.Println("Successfully created and decrypted TDF")
}
```

### Configuration Values

Replace these placeholder values with your actual configuration:

| Variable | Default (Quickstart) | Description |
|----------|---------------------|-------------|
| `platformEndpoint` | `http://localhost:8080` | Your OpenTDF platform URL |
| `clientID` | `opentdf` | OAuth client ID (from quickstart) |
| `clientSecret` | `secret` | OAuth client secret (from quickstart) |
| `keycloakURL` | `http://localhost:8888/auth/realms/opentdf` | Your Keycloak realm URL |
| `dataAttribute` | `https://opentdf.io/attr/department/value/finance` | Data attribute FQN (created in quickstart) |

**Before running:**
1. Follow the [OpenTDF Quickstart](https://opentdf.io/quickstart) to start the platform
2. Create an OAuth client in Keycloak and note the credentials
3. Grant your client entitlements to the `department` attribute (see [Managing policy](https://opentdf.io/sdks/policy))

**Expected Output:**
```
Ciphertext is 1234 bytes long
Successfully created and decrypted TDF
```

The `output.txt` file will contain the decrypted plaintext: `Hello, world!`

### Authentication Options

The SDK supports multiple authentication methods:

**Client Credentials (OAuth 2.0):**
```go
sdk.WithClientCredentials("client-id", "client-secret", []string{"scope1", "scope2"})
```

**TLS/mTLS Authentication:**
```go
import "crypto/tls"

// Load your client certificate and key
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
	log.Fatal(err)
}

tlsConfig := &tls.Config{
	Certificates: []tls.Certificate{cert},
	MinVersion:   tls.VersionTLS12,
}
sdk.WithTLSCredentials(tlsConfig, []string{"audience1", "audience2"})
```

**Custom OAuth2 Token Source:**
```go
import "golang.org/x/oauth2"

tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "your-token"})
sdk.WithOAuthAccessTokenSource(tokenSource)
```

**Token Exchange:**
```go
sdk.WithTokenExchange("subject-token", []string{"audience1", "audience2"})
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
