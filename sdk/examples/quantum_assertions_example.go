package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/opentdf/platform/sdk"
)

func main() {
	// Example: Creating a TDF with quantum-resistant assertions

	// Initialize SDK (you would normally pass a real platform endpoint and credentials)
	s, err := sdk.New("http://localhost:8080",
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials("tdf-client", "123-456", []string{}),
	)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}

	// Sample data to encrypt
	data := "This is sensitive data that will be protected with quantum-resistant assertions!"
	reader := strings.NewReader(data)

	// Create a buffer to store the encrypted TDF
	var tdfBuffer bytes.Buffer

	// Create TDF with quantum-resistant assertions enabled
	fmt.Println("Creating TDF with quantum-resistant ML-DSA assertions...")

	tdfObject, err := s.CreateTDF(&tdfBuffer, reader,
		// Enable quantum-resistant assertions
		sdk.WithQuantumResistantAssertions(),
		// Add default system metadata assertion (will use ML-DSA when quantum option is enabled)
		sdk.WithSystemMetadataAssertion(),
		// Add some sample attributes
		sdk.WithDataAttributes("https://example.com/attr/classification/public"),
	)
	if err != nil {
		log.Fatalf("Failed to create TDF: %v", err)
	}

	fmt.Printf("Successfully created TDF with size: %d bytes\n", tdfObject.Size())

	// The TDF now contains quantum-resistant ML-DSA-44 signatures for assertions!
	fmt.Println("TDF contains quantum-resistant assertions using ML-DSA-44 algorithm")

	// You can now save the TDF buffer to a file or transmit it
	fmt.Printf("TDF data length: %d bytes\n", tdfBuffer.Len())
}
