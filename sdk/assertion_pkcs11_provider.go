package sdk

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// PKCS11Provider implements hardware token signing for assertions (PIV/CAC cards)
// This is a template implementation that can be extended with actual PKCS#11 library integration
type PKCS11Provider struct {
	// Configuration for the hardware token
	config HardwareSigningOptions

	// Certificate chain retrieved from the hardware token
	certChain []*x509.Certificate

	// Signer interface that wraps the hardware signing operation
	signer crypto.Signer

	// Algorithm determined from the certificate's public key
	algorithm string
}

// NewPKCS11Provider creates a provider for hardware token signing
// In a real implementation, this would:
// 1. Load the PKCS#11 library (e.g., OpenSC for smart cards)
// 2. Connect to the hardware token
// 3. Authenticate with PIN if required
// 4. Retrieve the certificate chain from the token
func NewPKCS11Provider(config HardwareSigningOptions) (*PKCS11Provider, error) {
	if config.SlotID == "" {
		return nil, errors.New("slot ID is required for PKCS#11 provider")
	}

	// This is where you would initialize the PKCS#11 library
	// Example with github.com/miekg/pkcs11:
	/*
		p := pkcs11.New("/usr/lib/opensc-pkcs11.so")
		err := p.Initialize()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
		}

		// Find slot
		slots, err := p.GetSlotList(true)
		if err != nil {
			return nil, fmt.Errorf("failed to get slot list: %w", err)
		}

		// Open session
		session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			return nil, fmt.Errorf("failed to open session: %w", err)
		}

		// Login with PIN
		err = p.Login(session, pkcs11.CKU_USER, string(config.PIN))
		if err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		// Find certificate and private key objects
		// ... implementation specific to the token
	*/

	provider := &PKCS11Provider{
		config:    config,
		algorithm: config.Algorithm,
	}

	if provider.algorithm == "" {
		provider.algorithm = "RS256" // Default for PIV/CAC cards
	}

	return provider, nil
}

// Sign creates a JWS signature using the hardware token
func (p *PKCS11Provider) Sign(_ context.Context, _ *Assertion, assertionHash, assertionSig string) (string, error) {
	// Create JWT with assertion claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, assertionHash); err != nil {
		return "", fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, assertionSig); err != nil {
		return "", fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// In a real implementation, this would use the hardware token to sign
	// For now, we return an error indicating this needs to be implemented
	if p.signer == nil {
		return "", errors.New("PKCS#11 signing not implemented - extend this provider with actual hardware integration")
	}

	// Sign the token first
	signedTok, err := jwt.Sign(tok,
		jwt.WithKey(jwa.KeyAlgorithmFrom(p.algorithm), p.signer),
	)
	if err != nil {
		return "", fmt.Errorf("hardware signing failed: %w", err)
	}

	// If we need to add x5c, reconstruct the JWS
	if p.config.IncludeCertChain && len(p.certChain) > 0 {
		// Build x5c array
		var x5c []string
		for _, cert := range p.certChain {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}

		// Split the JWS to inject x5c header
		parts := strings.Split(string(signedTok), ".")
		if len(parts) != jwsPartsCount {
			return "", errors.New("invalid JWS format")
		}

		// Decode the header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return "", fmt.Errorf("failed to decode header: %w", err)
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			return "", fmt.Errorf("failed to parse header: %w", err)
		}

		// Add x5c to header
		header["x5c"] = x5c

		// Re-encode header
		newHeaderJSON, err := json.Marshal(header)
		if err != nil {
			return "", fmt.Errorf("failed to marshal header: %w", err)
		}

		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

		// Reconstruct with new header - hardware would re-sign here
		// For now, return the modified token (in real impl, hardware would re-sign)
		return newHeader + "." + parts[1] + "." + parts[2], nil
	}

	return string(signedTok), nil
}

// GetSigningKeyReference returns a reference for the hardware key
func (p *PKCS11Provider) GetSigningKeyReference() string {
	if p.config.KeyLabel != "" {
		return fmt.Sprintf("pkcs11:slot=%s:label=%s", p.config.SlotID, p.config.KeyLabel)
	}
	if len(p.certChain) > 0 {
		return fmt.Sprintf("pkcs11:slot=%s:subject=%s", p.config.SlotID, p.certChain[0].Subject.String())
	}
	return "pkcs11:slot=" + p.config.SlotID
}

// GetAlgorithm returns the signing algorithm
func (p *PKCS11Provider) GetAlgorithm() string {
	return p.algorithm
}

// LoadCertificateFromToken loads the certificate chain from the hardware token
// This is a helper method that would be called during initialization
func (p *PKCS11Provider) LoadCertificateFromToken() error {
	// In a real implementation, this would:
	// 1. Query the token for certificate objects
	// 2. Parse the DER-encoded certificates
	// 3. Build the certificate chain
	// 4. Determine the algorithm from the public key type

	// Example pseudo-code:
	/*
		certDER, err := p.readCertificateFromToken(p.config.SlotID, p.config.KeyLabel)
		if err != nil {
			return fmt.Errorf("failed to read certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		p.certChain = []*x509.Certificate{cert}

		// Determine algorithm from public key
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			p.algorithm = "RS256"
		case *ecdsa.PublicKey:
			key := cert.PublicKey.(*ecdsa.PublicKey)
			switch key.Curve.Params().BitSize {
			case 256:
				p.algorithm = "ES256"
			case 384:
				p.algorithm = "ES384"
			}
		}
	*/

	return nil
}

// PIVProvider is a specialized PKCS11Provider for PIV cards
type PIVProvider struct {
	*PKCS11Provider
}

// NewPIVProvider creates a provider specifically for PIV cards
func NewPIVProvider(pin []byte, slotID string) (*PIVProvider, error) {
	config := HardwareSigningOptions{
		SlotID:           slotID,
		PIN:              pin,
		Algorithm:        "RS256", // PIV typically uses RSA
		IncludeCertChain: true,
		KeyLabel:         "PIV Authentication",
	}

	base, err := NewPKCS11Provider(config)
	if err != nil {
		return nil, err
	}

	return &PIVProvider{
		PKCS11Provider: base,
	}, nil
}

// CACProvider is a specialized PKCS11Provider for CAC cards
type CACProvider struct {
	*PKCS11Provider
}

// NewCACProvider creates a provider specifically for CAC cards
func NewCACProvider(pin []byte, certificateID string) (*CACProvider, error) {
	config := HardwareSigningOptions{
		SlotID:           certificateID,
		PIN:              pin,
		Algorithm:        "RS256", // CAC typically uses RSA
		IncludeCertChain: true,
		KeyLabel:         "ID Certificate",
	}

	base, err := NewPKCS11Provider(config)
	if err != nil {
		return nil, err
	}

	return &CACProvider{
		PKCS11Provider: base,
	}, nil
}
