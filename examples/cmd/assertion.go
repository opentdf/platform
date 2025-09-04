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

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

// signAssertion demonstrates signing an assertion with X.509 certificates
func signAssertion() (string, *x509.Certificate, error) {
	fmt.Println("\n=== Signing Assertion with X.509 Certificate ===")

	// Generate a test certificate (in production, load from hardware token or file)
	privKey, cert, err := generateTestCertificate()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	fmt.Printf("✓ Generated certificate: CN=%s\n", cert.Subject.CommonName)

	// Create signing provider with X.509 certificate
	signingProvider, err := sdk.NewX509SigningProvider(privKey, []*x509.Certificate{cert})
	if err != nil {
		return "", nil, fmt.Errorf("failed to create signing provider: %w", err)
	}

	fmt.Printf("✓ Created X509SigningProvider with algorithm: %s\n", signingProvider.GetAlgorithm())

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

	fmt.Printf("✓ Signed assertion (JWS length: %d bytes)\n", len(signature))

	// Verify x5c is in the header
	parts := strings.Split(signature, ".")
	if len(parts) == 3 {
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var header map[string]interface{}
		json.Unmarshal(headerJSON, &header)
		if x5c, ok := header["x5c"]; ok {
			fmt.Printf("✓ x5c header present with %d certificate(s)\n", len(x5c.([]interface{})))
		}
	}

	return signature, cert, nil
}

// verifyAssertion demonstrates verifying an assertion signed with X.509 certificates
func verifyAssertion(signature string, trustedCert *x509.Certificate) error {
	fmt.Println("\n=== Verifying Assertion with X.509 Certificate ===")

	// Create certificate pool with trusted certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(trustedCert)

	// Create validation provider
	validationProvider := sdk.NewX509ValidationProvider(sdk.X509ValidationOptions{
		TrustedCAs:      certPool,
		AllowSelfSigned: true, // Allow self-signed for this example
		// RequiredPolicies: []string{"2.16.840.1.101.3.2.1.3.13"}, // Uncomment to require PIV OID
	})

	fmt.Printf("✓ Created X509ValidationProvider\n")

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

	fmt.Printf("✓ Signature validated successfully\n")
	fmt.Printf("  - Assertion Hash: %.32s...\n", hash)
	fmt.Printf("  - Assertion Signature: %s\n", sig)

	// Check trusted authorities
	authorities := validationProvider.GetTrustedAuthorities()
	fmt.Printf("✓ Trusted authorities: %v\n", authorities)

	// Extract and display certificate from x5c
	certs, err := sdk.ExtractX5CCertificates(signature)
	if err != nil {
		return fmt.Errorf("failed to extract certificates: %w", err)
	}

	if len(certs) > 0 {
		fmt.Printf("✓ Extracted %d certificate(s) from x5c header\n", len(certs))
		fmt.Printf("  - Subject: %s\n", certs[0].Subject.String())
		fmt.Printf("  - Issuer: %s\n", certs[0].Issuer.String())
		fmt.Printf("  - Serial: %s\n", certs[0].SerialNumber.String())
	}

	return nil
}

// demonstrateAssertionWorkflow shows the complete assertion signing and verification process
func demonstrateAssertionWorkflow() error {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("X.509 Certificate-Based Assertion Example")
	fmt.Println(strings.Repeat("=", 60))

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

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ Assertion signing and verification completed successfully!")
	fmt.Println(strings.Repeat("=", 60))

	return nil
}

// demonstrateInvalidSignature shows what happens with an invalid signature
func demonstrateInvalidSignature() error {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Invalid Signature Verification Example")
	fmt.Println(strings.Repeat("=", 60))

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
	signingProvider, _ := sdk.NewX509SigningProvider(privKey2, []*x509.Certificate{cert2})
	ctx := context.Background()
	signature, _ := signingProvider.Sign(ctx, &sdk.Assertion{}, "hash", "sig")

	fmt.Println("\n✓ Signed assertion with Certificate 2")

	// Try to verify with cert1 (should fail)
	fmt.Println("\nAttempting to verify with Certificate 1 (different from signing cert)...")

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
		fmt.Printf("✓ Validation correctly failed: %v\n", err)
		return nil
	}

	return fmt.Errorf("validation should have failed but didn't")
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
		return nil, fmt.Errorf("manifest.json not found in TDF")
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

// verifyOtdfctlAssertion verifies assertions created by otdfctl with tdfPolicyHash and keyAccessDigest
func verifyOtdfctlAssertion(assertion sdk.Assertion, manifest *TDFManifest) error {
	if assertion.Binding.Method != "jws" || assertion.Binding.Signature == "" {
		return fmt.Errorf("not a JWS binding")
	}

	// Parse the JWS to extract claims
	parts := strings.Split(assertion.Binding.Signature, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWS format")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	// Check for otdfctl-style claims
	tdfPolicyHash, hasPolicyHash := claims["tdfPolicyHash"]
	keyAccessDigest, hasKeyAccess := claims["keyAccessDigest"]

	if hasPolicyHash && hasKeyAccess {
		fmt.Printf("  ✓ Found otdfctl assertion binding:\n")
		fmt.Printf("     TDF Policy Hash: %.32s...\n", fmt.Sprint(tdfPolicyHash))
		fmt.Printf("     Key Access Digest: %.32s...\n", fmt.Sprint(keyAccessDigest))

		// TODO: In a full implementation, we would:
		// 1. Compute the actual policy hash from manifest
		// 2. Compute the key access digest from manifest
		// 3. Compare them to verify binding

		// Extract certificate info if available
		certs, err := sdk.ExtractX5CCertificates(assertion.Binding.Signature)
		if err == nil && len(certs) > 0 {
			fmt.Printf("     Signer: %s\n", certs[0].Subject.CommonName)
		}

		return nil
	}

	// Check for SDK-style claims (assertionHash, assertionSig)
	assertionHash, hasAssertionHash := claims["assertionHash"]
	assertionSig, hasAssertionSig := claims["assertionSig"]

	if hasAssertionHash && hasAssertionSig {
		fmt.Printf("  ✓ Found SDK assertion binding:\n")
		fmt.Printf("     Assertion Hash: %.32s...\n", fmt.Sprint(assertionHash))
		fmt.Printf("     Assertion Sig: %.32s...\n", fmt.Sprint(assertionSig))
		return nil
	}

	return fmt.Errorf("no recognized assertion binding claims found")
}

// verifyTDFAssertions reads a TDF file and verifies all assertions
func verifyTDFAssertions(tdfPath string) error {
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("Verifying Assertions from TDF File\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	fmt.Printf("TDF File: %s\n", tdfPath)

	// Read manifest from TDF
	manifest, err := readTDFManifest(tdfPath)
	if err != nil {
		return fmt.Errorf("failed to read TDF manifest: %w", err)
	}

	fmt.Printf("\n✓ Successfully read TDF manifest\n")
	fmt.Printf("  - Found %d assertion(s)\n", len(manifest.Assertions))

	if len(manifest.Assertions) == 0 {
		fmt.Println("\n⚠️  No assertions found in TDF")
		return nil
	}

	// Create a validation provider that accepts self-signed certificates
	// In production, you would use proper trusted CAs
	validationProvider := sdk.NewX509ValidationProvider(sdk.X509ValidationOptions{
		AllowSelfSigned: true,
	})

	// Verify each assertion
	for i, assertion := range manifest.Assertions {
		fmt.Printf("\n--- Assertion %d ---\n", i+1)
		fmt.Printf("  ID: %s\n", assertion.ID)
		fmt.Printf("  Type: %s\n", assertion.Type)
		fmt.Printf("  Scope: %s\n", assertion.Scope)

		if assertion.Statement.Format != "" {
			fmt.Printf("  Statement Format: %s\n", assertion.Statement.Format)
			// Truncate long values for display
			value := assertion.Statement.Value
			if len(value) > 100 {
				value = value[:97] + "..."
			}
			fmt.Printf("  Statement Value: %s\n", value)
		}

		// Check binding method
		if assertion.Binding.Method == "" {
			fmt.Printf("  ⚠️  No binding method specified\n")
			continue
		}

		fmt.Printf("  Binding Method: %s\n", assertion.Binding.Method)

		if assertion.Binding.Method == "jws" && assertion.Binding.Signature != "" {
			// Try to verify the JWS signature
			ctx := context.Background()
			hash, sig, err := validationProvider.Validate(ctx, assertion)
			if err != nil {
				// Try to extract certificates even if validation fails
				certs, certErr := sdk.ExtractX5CCertificates(assertion.Binding.Signature)
				if certErr == nil && len(certs) > 0 {
					fmt.Printf("  ℹ️  Certificate found in x5c:\n")
					fmt.Printf("     Subject: %s\n", certs[0].Subject.String())
					fmt.Printf("     Issuer: %s\n", certs[0].Issuer.String())
				}
				fmt.Printf("  ❌ Validation failed: %v\n", err)
			} else {
				fmt.Printf("  ✅ Signature validated successfully\n")
				fmt.Printf("     Hash: %.32s...\n", hash)
				fmt.Printf("     Sig: %.32s...\n", sig)

				// Extract and display certificate info
				certs, err := sdk.ExtractX5CCertificates(assertion.Binding.Signature)
				if err == nil && len(certs) > 0 {
					fmt.Printf("     Certificate: %s\n", certs[0].Subject.CommonName)
				}
			}
		} else if assertion.Binding.Method == "hash" {
			fmt.Printf("  ℹ️  Hash binding (signature: %.32s...)\n", assertion.Binding.Signature)
		} else {
			fmt.Printf("  ⚠️  Unsupported or missing binding\n")
		}
	}

	return nil
}

var (
	tdfFile string
)

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
	Run: func(cmd *cobra.Command, args []string) {
		// If TDF file is specified, verify its assertions
		if tdfFile != "" {
			if err := verifyTDFAssertions(tdfFile); err != nil {
				log.Fatalf("TDF assertion verification failed: %v", err)
			}
			fmt.Println("\n✅ TDF assertion verification completed!")
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

		fmt.Println("\n✨ All examples completed successfully!")
	},
}

func init() {
	assertionCmd.Flags().StringVar(&tdfFile, "tdf-file", "", "Path to TDF file to verify assertions from")
	ExamplesCmd.AddCommand(assertionCmd)
}
