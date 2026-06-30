package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Supported DPoP algorithm identifiers (RFC 9449 §4.2).
const (
	dpopAlgES256 = "ES256"
	dpopAlgES384 = "ES384"
	dpopAlgES512 = "ES512"
	dpopAlgRS256 = "RS256"
	dpopAlgRS384 = "RS384"
	dpopAlgRS512 = "RS512"
)

const dpopAllowedAlgs = dpopAlgES256 + ", " + dpopAlgES384 + ", " + dpopAlgES512 + ", " +
	dpopAlgRS256 + ", " + dpopAlgRS384 + ", " + dpopAlgRS512

// generateDPoPKeyForAlg generates an ephemeral DPoP private key for the given algorithm.
// Supported algorithms: ES256, ES384, ES512, RS256, RS384, RS512.
func generateDPoPKeyForAlg(alg string) (jwk.Key, error) {
	switch alg {
	case dpopAlgES256:
		return generateECDSAKey(elliptic.P256(), jwa.ES256)
	case dpopAlgES384:
		return generateECDSAKey(elliptic.P384(), jwa.ES384)
	case dpopAlgES512:
		return generateECDSAKey(elliptic.P521(), jwa.ES512)
	case dpopAlgRS256:
		return generateRSAKey(jwa.RS256)
	case dpopAlgRS384:
		return generateRSAKey(jwa.RS384)
	case dpopAlgRS512:
		return generateRSAKey(jwa.RS512)
	default:
		return nil, fmt.Errorf("unsupported DPoP algorithm %q; allowed: %s", alg, dpopAllowedAlgs)
	}
}

func generateECDSAKey(curve elliptic.Curve, alg jwa.SignatureAlgorithm) (jwk.Key, error) {
	rawKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from ECDSA key: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("failed to set algorithm on ECDSA JWK: %w", err)
	}
	return key, nil
}

func generateRSAKey(alg jwa.SignatureAlgorithm) (jwk.Key, error) {
	const rsaBits = 2048
	rawKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK from RSA key: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("failed to set algorithm on RSA JWK: %w", err)
	}
	return key, nil
}

// loadDPoPKeyFromPEM parses a PEM-encoded private key and returns it as a jwk.Key.
// The DPoP algorithm is inferred from the key type:
//   - EC P-256 → ES256, P-384 → ES384, P-521 → ES512
//   - RSA → RS256
func loadDPoPKeyFromPEM(pemBytes []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(pemBytes, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP key PEM: %w", err)
	}

	// Infer algorithm when not already set in the PEM
	if key.Algorithm() == jwa.NoSignature || key.Algorithm().String() == "" {
		alg, err := inferDPoPAlgorithm(key)
		if err != nil {
			return nil, err
		}
		if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
			return nil, fmt.Errorf("failed to set inferred algorithm on DPoP JWK: %w", err)
		}
	}

	return key, nil
}

func inferDPoPAlgorithm(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	switch key.KeyType() { //nolint:exhaustive // only EC and RSA are valid for DPoP (RFC 9449 §4.2)
	case jwa.EC:
		var rawKey ecdsa.PrivateKey
		if err := key.Raw(&rawKey); err != nil {
			return "", fmt.Errorf("failed to get raw EC key for algorithm inference: %w", err)
		}
		switch rawKey.Curve {
		case elliptic.P256():
			return jwa.ES256, nil
		case elliptic.P384():
			return jwa.ES384, nil
		case elliptic.P521():
			return jwa.ES512, nil
		default:
			return "", errors.New("unsupported EC curve for DPoP")
		}
	case jwa.RSA:
		return jwa.RS256, nil
	default:
		return "", fmt.Errorf("unsupported key type %q for DPoP; only EC and RSA keys are supported", key.KeyType())
	}
}

// validateDPoPKeyAlgorithm ensures a caller-supplied JWK carries a supported DPoP
// signing algorithm. Without this check a missing/invalid algorithm would only
// surface when signing the first proof, far from the misconfiguration.
func validateDPoPKeyAlgorithm(key jwk.Key) error {
	alg := key.Algorithm()
	if alg == nil || alg.String() == "" {
		return errors.New("DPoP JWK is missing required Algorithm field; set it with key.Set(jwk.AlgorithmKey, ...)")
	}
	switch alg.String() {
	case dpopAlgES256, dpopAlgES384, dpopAlgES512, dpopAlgRS256, dpopAlgRS384, dpopAlgRS512:
		return nil
	default:
		return fmt.Errorf("unsupported DPoP JWK algorithm %q; allowed: %s", alg.String(), dpopAllowedAlgs)
	}
}

// resolveDPoPKey returns the jwk.Key to use for DPoP based on the config, using a
// single fixed priority:
//
//	dpopJWK       (WithDPoPJWK)                          → validate algorithm, return
//	dpopKeyPEM    (WithDPoPKeyPEM)                       → load from PEM, apply optional algorithm override
//	dpopAlgorithm (WithDPoPAlgorithm)                    → generate a fresh ephemeral key
//	dpopKey       (WithSessionSignerRSA / auto-generated) → convert the RSA key pair to a JWK
//	none configured                                      → (nil, nil)
//
// The function is pure: it does not mutate the config. Because the dpopAlgorithm
// branch generates a new ephemeral key on every call, callers MUST resolve once
// and share the result between the token source and the DPoP transport.
//
// A (nil, nil) return means no DPoP key is configured; callers auto-generate a
// default RSA key in that case.
//
//nolint:nilnil // nil key signals "no DPoP key configured" — not an error condition
func resolveDPoPKey(c *config) (jwk.Key, error) {
	switch {
	case c.dpopJWK != nil:
		if err := validateDPoPKeyAlgorithm(c.dpopJWK); err != nil {
			return nil, err
		}
		return c.dpopJWK, nil
	case len(c.dpopKeyPEM) > 0:
		key, err := loadDPoPKeyFromPEM(c.dpopKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load DPoP key from PEM: %w", err)
		}
		if c.dpopAlgorithm != "" {
			var algVal jwa.SignatureAlgorithm
			if err := algVal.Accept(c.dpopAlgorithm); err != nil {
				return nil, fmt.Errorf("invalid DPoP algorithm override %q: %w", c.dpopAlgorithm, err)
			}
			if err := key.Set(jwk.AlgorithmKey, algVal); err != nil {
				return nil, fmt.Errorf("failed to apply DPoP algorithm override: %w", err)
			}
		}
		return key, nil
	case c.dpopAlgorithm != "":
		key, err := generateDPoPKeyForAlg(c.dpopAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
		}
		return key, nil
	case c.dpopKey != nil:
		key, err := getDPoPJWK(c.dpopKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create DPoP JWK: %w", err)
		}
		return key, nil
	default:
		return nil, nil
	}
}
