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

## Indeterministic Streaming Support (Out-of-Order Chunked Encryption)

The Go SDK supports indeterministic, out-of-order streaming encryption for large files. This allows you to encrypt and upload file chunks in any order, without knowing the total file size or chunk order in advance. Chunks are encrypted and written to disk immediately, and the final TDF is assembled when all chunks are complete.

### Usage Example

```go
// Prepare manifest, payloadKey, and tempDir (see SDK for details)
manifest := ... // sdk.Manifest struct
payloadKey := ... // [sdk.KeySize]byte
tempDir := os.TempDir()
chunkCount := N // total number of chunks expected
segmentSize := int64(4 * 1024 * 1024) // e.g., 4MB
finalFile, _ := os.Create("output.tdf")

cm, err := sdk.NewTDFChunkManager(finalFile, manifest, payloadKey, segmentSize, chunkCount, tempDir)
if err != nil {
    panic(err)
}

// As chunks arrive (in any order):
for idx, chunk := range incomingChunks {
    go func(i int, data []byte) {
        err := cm.WriteChunk(i, data)
        if err != nil {
            log.Printf("Chunk %d failed: %v", i, err)
        }
    }(idx, chunk)
}

// Wait for all chunks to complete (application logic)
// ...

// Finalize the TDF when all chunks are done
if cm.AllChunksComplete() {
    err := cm.Finalize()
    if err != nil {
        panic(err)
    }
    fmt.Println("TDF file assembled successfully!")
}
```

**Notes:**
- Chunks are encrypted and written to disk immediately; plaintext is not retained.
- Chunks can be written in any order and in parallel.
- The manifest and TDF are assembled only after all chunks are complete.
- Temporary files are used for chunk storage; clean up as needed.

### Indeterministic Streaming: Next Steps / TODOs

- [ ] Integrate chunked streaming API with main SDK interface (if needed)
- [ ] Add comprehensive unit and integration tests:
    - Out-of-order chunk writing
    - Large file handling
    - Final TDF assembly and manifest correctness
    - Decryption and integrity verification
- [ ] Ensure robust error handling and logging
- [ ] Ensure temporary files are cleaned up after finalization or on error
- [ ] Expand documentation with advanced usage, troubleshooting, and best practices
- [ ] Gather user feedback and iterate on API ergonomics
