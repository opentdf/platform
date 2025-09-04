package sdk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// X509SigningProvider implements certificate-based signing with x5c header support.
// This provider is suitable for PIV/CAC cards and other X.509 certificate-based signing.
type X509SigningProvider struct {
	privateKey crypto.Signer
	certChain  []*x509.Certificate
	algorithm  string
}

// NewX509SigningProvider creates a signing provider using X.509 certificates
func NewX509SigningProvider(privateKey crypto.Signer, certChain []*x509.Certificate) (*X509SigningProvider, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if len(certChain) == 0 {
		return nil, errors.New("certificate chain is required")
	}

	// Determine algorithm based on key type
	var algorithm string
	switch privateKey.Public().(type) {
	case *rsa.PublicKey:
		algorithm = "RS256"
	case *ecdsa.PublicKey:
		key := privateKey.Public().(*ecdsa.PublicKey)
		switch key.Curve.Params().BitSize {
		case 256:
			algorithm = "ES256"
		case 384:
			algorithm = "ES384"
		case 521:
			algorithm = "ES512"
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	return &X509SigningProvider{
		privateKey: privateKey,
		certChain:  certChain,
		algorithm:  algorithm,
	}, nil
}

// Sign creates a JWS signature with x5c certificate chain in the header
// Uses standard SDK binding (assertionHash and assertionSig)
func (p *X509SigningProvider) Sign(ctx context.Context, assertion *Assertion, assertionHash, assertionSig string) (string, error) {
	// Create JWT with SDK standard claims
	tok := jwt.New()

	// Use SDK standard binding (now aligned with otdfctl)
	if err := tok.Set(kAssertionHash, assertionHash); err != nil {
		return "", fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, assertionSig); err != nil {
		return "", fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Build x5c array with base64-encoded certificates
	var x5c []string
	for _, cert := range p.certChain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	// Create JWS headers with x5c
	headers := jws.NewHeaders()
	if err := headers.Set(jws.AlgorithmKey, p.algorithm); err != nil {
		return "", fmt.Errorf("failed to set algorithm header: %w", err)
	}
	if err := headers.Set(jws.TypeKey, "JWT"); err != nil {
		return "", fmt.Errorf("failed to set type header: %w", err)
	}

	// Sign the token first
	signedTok, err := jwt.Sign(tok,
		jwt.WithKey(jwa.KeyAlgorithmFrom(p.algorithm), p.privateKey),
	)
	if err != nil {
		return "", fmt.Errorf("signing assertion failed: %w", err)
	}

	// Parse and reconstruct with x5c header
	// Split the JWS to inject x5c header
	parts := strings.Split(string(signedTok), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWS format")
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

	// Reconstruct the JWS with new header but we need to re-sign
	// because the signature is over the protected header + payload
	signingInput := newHeader + "." + parts[1]

	// Sign the new input
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	signature, err := p.privateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to sign with x5c: %w", err)
	}

	// Encode signature
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Construct final JWS
	finalJWS := signingInput + "." + sigB64

	return finalJWS, nil
}

// GetSigningKeyReference returns the certificate subject as reference
func (p *X509SigningProvider) GetSigningKeyReference() string {
	if len(p.certChain) > 0 {
		return p.certChain[0].Subject.String()
	}
	return "x509-certificate"
}

// GetAlgorithm returns the signing algorithm
func (p *X509SigningProvider) GetAlgorithm() string {
	return p.algorithm
}

// X509ValidationProvider implements certificate-based validation with x5c support.
// This provider extracts and validates certificates from the JWS x5c header.
type X509ValidationProvider struct {
	options X509ValidationOptions
	// Store trusted certificate subjects for GetTrustedAuthorities
	trustedSubjects []string
}

// NewX509ValidationProvider creates a validation provider for X.509 certificates
func NewX509ValidationProvider(options X509ValidationOptions) *X509ValidationProvider {
	provider := &X509ValidationProvider{
		options: options,
	}

	// Extract trusted subjects if TrustedCAs is provided
	if options.TrustedCAs != nil {
		// Note: x509.CertPool doesn't expose its certificates directly,
		// so we track them when they're added to the pool externally
		provider.trustedSubjects = append(provider.trustedSubjects, "configured-trusted-cas")
	}

	return provider
}

// NewX509ValidationProviderWithCerts creates a validation provider with specified trusted certificates
func NewX509ValidationProviderWithCerts(certs []*x509.Certificate, options X509ValidationOptions) *X509ValidationProvider {
	// Create certificate pool if not provided
	if options.TrustedCAs == nil {
		options.TrustedCAs = x509.NewCertPool()
	}

	provider := &X509ValidationProvider{
		options:         options,
		trustedSubjects: make([]string, 0, len(certs)),
	}

	// Add certificates to pool and track their subjects
	for _, cert := range certs {
		options.TrustedCAs.AddCert(cert)
		provider.trustedSubjects = append(provider.trustedSubjects, cert.Subject.String())
	}

	return provider
}

// validateWithX5C is a helper to validate JWS with x5c certificates
func (p *X509ValidationProvider) validateWithX5C(x5c []string, signature string) (string, string, error) {
	if len(x5c) == 0 {
		return "", "", errors.New("empty x5c certificate chain")
	}

	// Decode and parse certificates
	var certs []*x509.Certificate
	for i, certB64 := range x5c {
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode certificate %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	// Validate certificate chain if required
	if p.options.RequireChainValidation && p.options.TrustedCAs != nil {
		if err := p.validateCertificateChain(certs); err != nil {
			return "", "", fmt.Errorf("certificate chain validation failed: %w", err)
		}
	}

	// Check certificate policies if required
	if len(p.options.RequiredPolicies) > 0 {
		if err := p.checkCertificatePolicies(certs[0]); err != nil {
			return "", "", fmt.Errorf("certificate policy check failed: %w", err)
		}
	}

	// Parse to get algorithm
	parts := strings.Split(signature, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid JWS format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", "", fmt.Errorf("failed to parse header: %w", err)
	}

	alg, ok := header["alg"].(string)
	if !ok {
		return "", "", errors.New("algorithm not found in header")
	}

	// Verify the signature using the certificate's public key
	_, err = jws.Verify([]byte(signature), jws.WithKey(jwa.KeyAlgorithmFrom(alg), certs[0].PublicKey))
	if err != nil {
		return "", "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse the JWT to extract claims
	tok, err := jwt.Parse([]byte(signature), jwt.WithKey(jwa.KeyAlgorithmFrom(alg), certs[0].PublicKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract the standard SDK binding claims (assertionHash and assertionSig)
	// Now that otdfctl has been aligned with SDK, we only need to support one style
	hashClaim, foundHash := tok.Get(kAssertionHash)
	sigClaim, foundSig := tok.Get(kAssertionSignature)

	if !foundHash || !foundSig {
		return "", "", errors.New("assertion binding claims not found (missing assertionHash or assertionSig)")
	}

	hash, ok := hashClaim.(string)
	if !ok {
		return "", "", errors.New("assertion hash claim is not a string")
	}

	sig, ok := sigClaim.(string)
	if !ok {
		return "", "", errors.New("assertion sig claim is not a string")
	}

	return hash, sig, nil
}

// Validate verifies the assertion signature using the certificate from x5c header
func (p *X509ValidationProvider) Validate(ctx context.Context, assertion Assertion) (string, string, error) {
	if assertion.Binding.Method != "jws" {
		return "", "", fmt.Errorf("unsupported binding method: %s", assertion.Binding.Method)
	}

	// Parse the JWS to extract headers
	msg, err := jws.Parse([]byte(assertion.Binding.Signature))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JWS: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return "", "", errors.New("no signatures found in JWS")
	}

	// Get the protected headers
	headers := signatures[0].ProtectedHeaders()

	// Check if this is our manually created JWS with x5c in header
	// Try to parse it directly from the compact serialization
	parts := strings.Split(assertion.Binding.Signature, ".")
	if len(parts) == 3 {
		// Decode header directly
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err == nil {
			var header map[string]interface{}
			if err := json.Unmarshal(headerJSON, &header); err == nil {
				if x5cRaw, ok := header["x5c"]; ok {
					// Try to extract x5c from our custom format
					var x5c []string
					switch v := x5cRaw.(type) {
					case []interface{}:
						for _, cert := range v {
							if certStr, ok := cert.(string); ok {
								x5c = append(x5c, certStr)
							}
						}
					case []string:
						x5c = v
					}

					if len(x5c) > 0 {
						// Successfully extracted x5c, now validate and extract claims
						return p.validateWithX5C(x5c, assertion.Binding.Signature)
					}
				}
			}
		}
	}

	// Fall back to jwx parsing
	// Extract x5c from headers
	x5cRaw, ok := headers.Get("x5c")
	if !ok {
		return "", "", errors.New("x5c header not found in JWS")
	}

	// Parse x5c array
	var x5c []string
	switch v := x5cRaw.(type) {
	case []interface{}:
		for _, cert := range v {
			certStr, ok := cert.(string)
			if !ok {
				return "", "", errors.New("invalid x5c certificate format")
			}
			x5c = append(x5c, certStr)
		}
	case []string:
		x5c = v
	default:
		// Try other possible formats
		return "", "", fmt.Errorf("unexpected x5c type: %T", x5cRaw)
	}

	if len(x5c) == 0 {
		return "", "", errors.New("empty x5c certificate chain")
	}

	// Decode and parse certificates
	var certs []*x509.Certificate
	for i, certB64 := range x5c {
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode certificate %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	// Validate certificate chain if required
	if p.options.RequireChainValidation && p.options.TrustedCAs != nil {
		if err := p.validateCertificateChain(certs); err != nil {
			return "", "", fmt.Errorf("certificate chain validation failed: %w", err)
		}
	}

	// Check certificate policies if required
	if len(p.options.RequiredPolicies) > 0 {
		if err := p.checkCertificatePolicies(certs[0]); err != nil {
			return "", "", fmt.Errorf("certificate policy check failed: %w", err)
		}
	}

	// Get the algorithm from headers
	algRaw, ok := headers.Get(jws.AlgorithmKey)
	if !ok {
		return "", "", errors.New("algorithm not found in JWS header")
	}

	alg, ok := algRaw.(string)
	if !ok {
		return "", "", errors.New("invalid algorithm format")
	}

	// Verify the signature using the certificate's public key
	_, err = jws.Verify([]byte(assertion.Binding.Signature),
		jws.WithKey(jwa.KeyAlgorithmFrom(alg), certs[0].PublicKey))
	if err != nil {
		return "", "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse the JWT to extract claims
	tok, err := jwt.Parse([]byte(assertion.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(alg), certs[0].PublicKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Try to extract claims based on different binding styles
	// First try secure binding (otdfctl style)
	policyHashClaim, foundPolicy := tok.Get(kTDFPolicyHash)
	keyAccessClaim, foundKeyAccess := tok.Get(kKeyAccessDigest)

	if foundPolicy && foundKeyAccess {
		// Secure binding found
		policyHash, ok := policyHashClaim.(string)
		if !ok {
			return "", "", errors.New("TDF policy hash claim is not a string")
		}
		keyAccessDigest, ok := keyAccessClaim.(string)
		if !ok {
			return "", "", errors.New("key access digest claim is not a string")
		}
		return policyHash, keyAccessDigest, nil
	}

	// Try legacy binding (SDK style)
	hashClaim, foundHash := tok.Get(kAssertionHash)
	sigClaim, foundSig := tok.Get(kAssertionSignature)

	if foundHash && foundSig {
		// Legacy binding found
		hash, ok := hashClaim.(string)
		if !ok {
			return "", "", errors.New("assertion hash claim is not a string")
		}
		sig, ok := sigClaim.(string)
		if !ok {
			return "", "", errors.New("assertion sig claim is not a string")
		}
		return hash, sig, nil
	}

	// No recognized binding found
	return "", "", errors.New("no recognized assertion binding claims found")
}

// validateCertificateChain validates the certificate chain against trusted CAs
func (p *X509ValidationProvider) validateCertificateChain(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("empty certificate chain")
	}

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Verify the chain
	opts := x509.VerifyOptions{
		Roots:         p.options.TrustedCAs,
		Intermediates: intermediates,
	}

	_, err := certs[0].Verify(opts)
	if err != nil {
		// Check if self-signed is allowed
		if p.options.AllowSelfSigned && certs[0].CheckSignatureFrom(certs[0]) == nil {
			return nil
		}
		return err
	}

	return nil
}

// checkCertificatePolicies checks if required policy OIDs are present
func (p *X509ValidationProvider) checkCertificatePolicies(cert *x509.Certificate) error {
	// PIV Authentication OID: 2.16.840.1.101.3.2.1.3.13
	// CAC ID Certificate OID: 2.16.840.1.101.3.2.1.3.13

	for _, requiredPolicy := range p.options.RequiredPolicies {
		found := false
		for _, policy := range cert.PolicyIdentifiers {
			if policy.String() == requiredPolicy {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required policy OID not found: %s", requiredPolicy)
		}
	}

	return nil
}

// IsTrusted checks if the signing certificate is trusted
func (p *X509ValidationProvider) IsTrusted(ctx context.Context, assertion Assertion) error {
	// Parse JWS to get certificate
	msg, err := jws.Parse([]byte(assertion.Binding.Signature))
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return errors.New("no signatures found")
	}

	headers := signatures[0].ProtectedHeaders()
	x5cRaw, ok := headers.Get("x5c")
	if !ok {
		return errors.New("x5c header not found")
	}

	// Extract first certificate
	var certB64 string
	switch v := x5cRaw.(type) {
	case []interface{}:
		if len(v) > 0 {
			certB64, _ = v[0].(string)
		}
	case []string:
		if len(v) > 0 {
			certB64 = v[0]
		}
	}

	if certB64 == "" {
		return errors.New("no certificate in x5c")
	}

	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is in trusted pool
	if p.options.TrustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots: p.options.TrustedCAs,
		}
		_, err = cert.Verify(opts)
		if err != nil && !(p.options.AllowSelfSigned && cert.CheckSignatureFrom(cert) == nil) {
			return fmt.Errorf("certificate not trusted: %w", err)
		}
	}

	return nil
}

// GetTrustedAuthorities returns the list of trusted CA subjects
func (p *X509ValidationProvider) GetTrustedAuthorities() []string {
	authorities := make([]string, 0, len(p.trustedSubjects))

	// Add tracked trusted subjects
	authorities = append(authorities, p.trustedSubjects...)

	// Add configuration-based authorities
	if p.options.AllowSelfSigned {
		authorities = append(authorities, "self-signed-allowed")
	}

	// Add required policy OIDs
	for _, policy := range p.options.RequiredPolicies {
		authorities = append(authorities, fmt.Sprintf("policy:%s", policy))
	}

	return authorities
}

// ExtractX5CCertificates is a utility function to extract certificates from a JWS with x5c header
func ExtractX5CCertificates(jwsSignature string) ([]*x509.Certificate, error) {
	// First try parsing as a compact JWS with our custom x5c format
	parts := strings.Split(jwsSignature, ".")
	if len(parts) == 3 {
		// Decode header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode header: %w", err)
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			return nil, fmt.Errorf("failed to parse header: %w", err)
		}

		// Extract x5c
		if x5cRaw, ok := header["x5c"]; ok {
			var certs []*x509.Certificate

			// Handle different x5c formats
			switch v := x5cRaw.(type) {
			case []interface{}:
				for _, certRaw := range v {
					if certB64, ok := certRaw.(string); ok {
						certDER, err := base64.StdEncoding.DecodeString(certB64)
						if err == nil {
							if cert, err := x509.ParseCertificate(certDER); err == nil {
								certs = append(certs, cert)
							}
						}
					}
				}
			case []string:
				for _, certB64 := range v {
					certDER, err := base64.StdEncoding.DecodeString(certB64)
					if err == nil {
						if cert, err := x509.ParseCertificate(certDER); err == nil {
							certs = append(certs, cert)
						}
					}
				}
			}

			if len(certs) > 0 {
				return certs, nil
			}
		}
	}

	// Try using jwx library parsing
	msg, err := jws.Parse([]byte(jwsSignature))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return nil, errors.New("no signatures found")
	}

	headers := signatures[0].ProtectedHeaders()
	x5cRaw, ok := headers.Get("x5c")
	if !ok {
		return nil, errors.New("x5c header not found")
	}

	var x5c []string
	switch v := x5cRaw.(type) {
	case []interface{}:
		for _, cert := range v {
			certStr, ok := cert.(string)
			if ok {
				x5c = append(x5c, certStr)
			}
		}
	case []string:
		x5c = v
	}

	var certs []*x509.Certificate
	for _, certB64 := range x5c {
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
