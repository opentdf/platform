package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

const (
	// RSA key size for certificate generation
	rsaKeySize = 2048
	// Number of JWS parts (header.payload.signature)
	jwsParts = 3
	// Statement value display length for truncation
	statementDisplayLength = 100
	// Truncation indicator length
	truncationLength = 3
	// Statement truncation length (100 - 3 = 97)
	statementTruncateLength = statementDisplayLength - truncationLength
	// Separator line length
	separatorLength = 60
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Example Corp"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{"94102"},
			CommonName:    "Example Assertion Signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		// Note: PolicyIdentifiers would be added here for PIV/CAC support
		// but requires Go 1.22+ or custom ASN.1 encoding
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return priv, cert, nil
}

// verifyX5CHeader extracts and verifies the x5c header from a JWS signature
func verifyX5CHeader(signature string) error {
	parts := strings.Split(signature, ".")
	if len(parts) != jwsParts {
		return nil // Skip verification if not a proper JWS
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse JWS header: %w", err)
	}

	if x5c, ok := header["x5c"]; ok {
		if x5cSlice, isSlice := x5c.([]interface{}); isSlice {
			log.Printf("✓ x5c header present with %d certificate(s)\n", len(x5cSlice))
		}
	}

	return nil
}

// validateJWSAssertion handles JWS signature validation with detailed logging
func validateJWSAssertion(assertion sdk.Assertion, validationProvider *sdk.X509ValidationProvider) {
	if assertion.Binding.Signature == "" {
		return
	}

	ctx := context.Background()
	hash, sig, err := validationProvider.Validate(ctx, assertion)
	if err != nil {
		// Try to extract certificates even if validation fails
		certs, certErr := sdk.ExtractX5CCertificates(assertion.Binding.Signature)
		if certErr == nil && len(certs) > 0 {
			log.Printf("  ℹ️  Certificate found in x5c:\n")
			log.Printf("     Subject: %s\n", certs[0].Subject.String())
			log.Printf("     Issuer: %s\n", certs[0].Issuer.String())
		}
		log.Printf("  ❌ Validation failed: %v\n", err)
		return
	}

	log.Printf("  ✅ Signature validated successfully\n")
	log.Printf("     Hash: %.32s...\n", hash)
	log.Printf("     Sig: %.32s...\n", sig)

	// Extract and display certificate info
	certs, err := sdk.ExtractX5CCertificates(assertion.Binding.Signature)
	if err == nil && len(certs) > 0 {
		log.Printf("     Certificate: %s\n", certs[0].Subject.CommonName)
	}
}

// signAssertion demonstrates signing an assertion with X.509 certificates
func signAssertion() (string, *x509.Certificate, error) {
	log.Println("\n=== Signing Assertion with X.509 Certificate ===")

	// Generate a test certificate (in production, load from hardware token or file)
	privKey, cert, err := generateTestCertificate()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	log.Printf("✓ Generated certificate: CN=%s\n", cert.Subject.CommonName)

	// Create signing provider with X.509 certificate
	signingProvider, err := sdk.NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	if err != nil {
		return "", nil, fmt.Errorf("failed to create signing provider: %w", err)
	}

	log.Printf("✓ Created X509SigningProvider with algorithm: %s\n", signingProvider.GetAlgorithm())

	// Create an assertion to sign
	assertion := &sdk.Assertion{
		ID:    "example-assertion-001",
		Type:  sdk.HandlingAssertion,
		Scope: sdk.TrustedDataObjScope,
		Statement: sdk.Statement{
			Format: "plain",
			Value:  "This data requires special handling per company policy XYZ",
		},
	}

	// Sign the assertion
	ctx := context.Background()
	assertionHash := "a1b2c3d4e5f6789abcdef123456789abcdef123456789abcdef123456789abc"
	assertionSig := "signature-binding-to-tdf"

	signature, err := signingProvider.Sign(ctx, assertion, assertionHash, assertionSig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	log.Printf("✓ Signed assertion (JWS length: %d bytes)\n", len(signature))

	// Verify x5c is in the header
	if err := verifyX5CHeader(signature); err != nil {
		return "", nil, err
	}

	return signature, cert, nil
}

// verifyAssertion demonstrates verifying an assertion signed with X.509 certificates
func verifyAssertion(signature string, trustedCert *x509.Certificate) error {
	log.Println("\n=== Verifying Assertion with X.509 Certificate ===")

	// Create certificate pool with trusted certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(trustedCert)

	// Create validation provider
	validationProvider := sdk.NewX509ValidationProvider(sdk.X509ValidationOptions{
		TrustedCAs:      certPool,
		AllowSelfSigned: true, // Allow self-signed for this example
		// RequiredPolicies: []string{"2.16.840.1.101.3.2.1.3.13"}, // Uncomment to require PIV OID
	})

	log.Printf("✓ Created X509ValidationProvider\n")

	// Create an assertion with the signature to validate
	assertion := sdk.Assertion{
		Binding: sdk.Binding{
			Method:    "jws",
			Signature: signature,
		},
	}

	// Validate the assertion
	ctx := context.Background()
	hash, sig, err := validationProvider.Validate(ctx, assertion)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	log.Printf("✓ Signature validated successfully\n")
	log.Printf("  - Assertion Hash: %.32s...\n", hash)
	log.Printf("  - Assertion Signature: %s\n", sig)

	// Check trusted authorities
	authorities := validationProvider.GetTrustedAuthorities()
	log.Printf("✓ Trusted authorities: %v\n", authorities)

	// Extract and display certificate from x5c
	certs, err := sdk.ExtractX5CCertificates(signature)
	if err != nil {
		return fmt.Errorf("failed to extract certificates: %w", err)
	}

	if len(certs) > 0 {
		log.Printf("✓ Extracted %d certificate(s) from x5c header\n", len(certs))
		log.Printf("  - Subject: %s\n", certs[0].Subject.String())
		log.Printf("  - Issuer: %s\n", certs[0].Issuer.String())
		log.Printf("  - Serial: %s\n", certs[0].SerialNumber.String())
	}

	return nil
}

// demonstrateAssertionWorkflow shows the complete assertion signing and verification process
func demonstrateAssertionWorkflow() error {
	log.Println("\n" + strings.Repeat("=", separatorLength))
	log.Println("X.509 Certificate-Based Assertion Example")
	log.Println(strings.Repeat("=", separatorLength))

	// Step 1: Sign an assertion
	signature, cert, err := signAssertion()
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Step 2: Verify the assertion
	err = verifyAssertion(signature, cert)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	log.Println("\n" + strings.Repeat("=", separatorLength))
	log.Println("✅ Assertion signing and verification completed successfully!")
	log.Println(strings.Repeat("=", separatorLength))

	return nil
}

// demonstrateInvalidSignature shows what happens with an invalid signature
func demonstrateInvalidSignature() error {
	log.Println("\n" + strings.Repeat("=", separatorLength))
	log.Println("Invalid Signature Verification Example")
	log.Println(strings.Repeat("=", separatorLength))

	// Create two different certificates
	_, cert1, err := generateTestCertificate()
	if err != nil {
		return err
	}

	privKey2, cert2, err := generateTestCertificate()
	if err != nil {
		return err
	}

	// Sign with cert2
	signingProvider, err := sdk.NewX509SigningProvider(privKey2, []*x509.Certificate{cert2})
	if err != nil {
		return fmt.Errorf("failed to create signing provider: %w", err)
	}
	ctx := context.Background()
	signature, err := signingProvider.Sign(ctx, &sdk.Assertion{}, "hash", "sig")
	if err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}

	log.Println("\n✓ Signed assertion with Certificate 2")

	// Try to verify with cert1 (should fail)
	log.Println("\nAttempting to verify with Certificate 1 (different from signing cert)...")

	certPool := x509.NewCertPool()
	certPool.AddCert(cert1) // Wrong certificate!

	validationProvider := sdk.NewX509ValidationProvider(sdk.X509ValidationOptions{
		TrustedCAs:             certPool,
		AllowSelfSigned:        false, // Strict validation
		RequireChainValidation: true,  // Require chain validation against trusted pool
	})

	assertion := sdk.Assertion{
		Binding: sdk.Binding{
			Method:    "jws",
			Signature: signature,
		},
	}

	_, _, err = validationProvider.Validate(ctx, assertion)
	if err != nil {
		log.Printf("✓ Validation correctly failed: %v\n", err)
		return nil
	}

	return errors.New("validation should have failed but didn't")
}

// TDFManifest represents the structure of a TDF manifest
type TDFManifest struct {
	EncryptionInformation struct {
		IntegrityInformation struct {
			RootSignature struct {
				Algorithm string `json:"alg"`
				Signature string `json:"sig"`
			} `json:"rootSignature"`
		} `json:"integrityInformation"`
		KeyAccess []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"keyAccess"`
	} `json:"encryptionInformation"`
	Assertions []sdk.Assertion `json:"assertions"`
}

// readTDFManifest extracts and parses the manifest from a TDF file
func readTDFManifest(tdfPath string) (*TDFManifest, error) {
	// Read the TDF file
	data, err := os.ReadFile(tdfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TDF file: %w", err)
	}

	// Open as zip archive
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to open TDF as zip: %w", err)
	}

	// Find manifest.json
	var manifestFile *zip.File
	for _, file := range reader.File {
		if file.Name == "0.manifest.json" || file.Name == "manifest.json" {
			manifestFile = file
			break
		}
	}

	if manifestFile == nil {
		return nil, errors.New("manifest.json not found in TDF")
	}

	// Read manifest content
	rc, err := manifestFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest: %w", err)
	}
	defer rc.Close()

	manifestData, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse manifest
	var manifest TDFManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// verifyTDFAssertions reads a TDF file and verifies all assertions
func verifyTDFAssertions(tdfPath string) error {
	log.Print("\n" + strings.Repeat("=", separatorLength) + "\n")
	log.Print("Verifying Assertions from TDF File\n")
	log.Print(strings.Repeat("=", separatorLength) + "\n")
	log.Printf("TDF File: %s\n", tdfPath)

	// Read manifest from TDF
	manifest, err := readTDFManifest(tdfPath)
	if err != nil {
		return fmt.Errorf("failed to read TDF manifest: %w", err)
	}

	log.Printf("\n✓ Successfully read TDF manifest\n")
	log.Printf("  - Found %d assertion(s)\n", len(manifest.Assertions))

	if len(manifest.Assertions) == 0 {
		log.Println("\n⚠️  No assertions found in TDF")
		return nil
	}

	// Create a validation provider that accepts self-signed certificates
	// In production, you would use proper trusted CAs
	validationProvider := sdk.NewX509ValidationProvider(sdk.X509ValidationOptions{
		AllowSelfSigned: true,
	})

	// Verify each assertion
	for i, assertion := range manifest.Assertions {
		log.Printf("\n--- Assertion %d ---\n", i+1)
		log.Printf("  ID: %s\n", assertion.ID)
		log.Printf("  Type: %s\n", assertion.Type)
		log.Printf("  Scope: %s\n", assertion.Scope)

		if assertion.Statement.Format != "" {
			log.Printf("  Statement Format: %s\n", assertion.Statement.Format)
			// Truncate long values for display
			value := assertion.Statement.Value
			if len(value) > statementDisplayLength {
				value = value[:statementTruncateLength] + "..."
			}
			log.Printf("  Statement Value: %s\n", value)
		}

		// Check binding method
		if assertion.Binding.Method == "" {
			log.Printf("  ⚠️  No binding method specified\n")
			continue
		}

		log.Printf("  Binding Method: %s\n", assertion.Binding.Method)

		switch assertion.Binding.Method {
		case "jws":
			validateJWSAssertion(assertion, validationProvider)
		case "hash":
			log.Printf("  ℹ️  Hash binding (signature: %.32s...)\n", assertion.Binding.Signature)
		default:
			log.Printf("  ⚠️  Unsupported or missing binding\n")
		}
	}

	return nil
}

var tdfFileFlag string

// assertionCmd represents the assertion command
var assertionCmd = &cobra.Command{
	Use:   "assertion",
	Short: "Sign and verify assertions with X.509 certificates",
	Long: `Demonstrates signing and verifying assertions using X.509 certificates.
This example shows how to:
- Sign assertions with X.509 certificates (including x5c header)
- Verify assertions using certificate-based validation
- Handle invalid signatures correctly
- Read and verify assertions from TDF files

Usage:
  # Run the demonstration
  examples-cli assertion
  
  # Verify assertions in a TDF file
  examples-cli assertion --tdf-file path/to/file.tdf`,
	Run: func(_ *cobra.Command, _ []string) {
		// If TDF file is specified, verify its assertions
		if tdfFileFlag != "" {
			if err := verifyTDFAssertions(tdfFileFlag); err != nil {
				log.Fatalf("TDF assertion verification failed: %v", err)
			}
			log.Println("\n✅ TDF assertion verification completed!")
			return
		}

		// Otherwise run the demonstration
		// Demonstrate the complete workflow
		if err := demonstrateAssertionWorkflow(); err != nil {
			log.Fatalf("Workflow failed: %v", err)
		}

		// Demonstrate invalid signature handling
		if err := demonstrateInvalidSignature(); err != nil {
			log.Fatalf("Invalid signature demo failed: %v", err)
		}

		log.Println("\n✨ All examples completed successfully!")
	},
}

func init() {
	assertionCmd.Flags().StringVar(&tdfFileFlag, "tdf-file", "", "Path to TDF file to verify assertions from")
	ExamplesCmd.AddCommand(assertionCmd)
}
