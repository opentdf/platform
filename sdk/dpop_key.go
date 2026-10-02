package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// validDPoPAlgs is the single source of truth for the JWS algorithms permitted
// for DPoP proofs (RFC 9449 §4.2, restricted to the asymmetric families we
// support). generateDPoPKeyForAlg, validateDPoPKey, and the PEM algorithm
// override all consult it via SigningAlgorithm.Valid so the set cannot drift.
var validDPoPAlgs = []SigningAlgorithm{ES256, ES384, ES512, RS256, RS384, RS512}

// Valid reports whether a is a SigningAlgorithm supported for DPoP proofs.
func (a SigningAlgorithm) Valid() bool {
	return slices.Contains(validDPoPAlgs, a)
}

// dpopAllowedAlgs is the human-readable allow-list used in error messages,
// derived from validDPoPAlgs so it can never drift from the enforced set.
var dpopAllowedAlgs = func() string {
	names := make([]string, len(validDPoPAlgs))
	for i, a := range validDPoPAlgs {
		names[i] = string(a)
	}
	return strings.Join(names, ", ")
}()

// generateDPoPKeyForAlg generates an ephemeral DPoP private key for the given algorithm.
// Supported algorithms: ES256, ES384, ES512, RS256, RS384, RS512.
func generateDPoPKeyForAlg(alg SigningAlgorithm) (jwk.Key, error) {
	switch alg {
	case ES256:
		return generateECDSAKey(elliptic.P256(), jwa.ES256)
	case ES384:
		return generateECDSAKey(elliptic.P384(), jwa.ES384)
	case ES512:
		return generateECDSAKey(elliptic.P521(), jwa.ES512)
	case RS256:
		return generateRSAKey(jwa.RS256)
	case RS384:
		return generateRSAKey(jwa.RS384)
	case RS512:
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
// The DPoP algorithm is inferred from the key type when the key does not already
// carry one:
//   - EC P-256 → ES256, P-384 → ES384, P-521 → ES512
//   - RSA → RS256
func loadDPoPKeyFromPEM(pemBytes []byte) (jwk.Key, error) {
	key, err := jwk.ParseKey(pemBytes, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP key PEM: %w", err)
	}

	// A public-only PEM cannot sign proofs; reject it here with a clear message
	// rather than letting inference or signing fail later.
	if isPriv, err := jwk.IsPrivateKey(key); err != nil {
		return nil, fmt.Errorf("failed to inspect DPoP key PEM: %w", err)
	} else if !isPriv {
		return nil, errors.New("DPoP key PEM must contain private signing material; a public-only key cannot sign proofs")
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
		return ecCurveToDPoPAlg(rawKey.Curve)
	case jwa.RSA:
		return jwa.RS256, nil
	default:
		return "", fmt.Errorf("unsupported key type %q for DPoP; only EC and RSA keys are supported", key.KeyType())
	}
}

// ecCurveToDPoPAlg maps an EC curve to its RFC 7518 ECDSA algorithm
// (P-256→ES256, P-384→ES384, P-521→ES512).
func ecCurveToDPoPAlg(curve elliptic.Curve) (jwa.SignatureAlgorithm, error) {
	switch curve {
	case elliptic.P256():
		return jwa.ES256, nil
	case elliptic.P384():
		return jwa.ES384, nil
	case elliptic.P521():
		return jwa.ES512, nil
	default:
		return "", errors.New("unsupported EC curve for DPoP")
	}
}

// validateDPoPKey ensures a resolved DPoP JWK can actually sign proofs, catching
// misconfiguration at resolution time instead of when the first proof is signed.
// It checks, in order: a supported algorithm is set, the key carries private
// signing material, the algorithm family matches the key type (ES* → EC, RS* → RSA),
// and — for EC keys — the curve matches the ES algorithm (P-256↔ES256, etc.).
func validateDPoPKey(key jwk.Key) error {
	alg := key.Algorithm()
	if alg == nil || alg.String() == "" {
		return errors.New("DPoP JWK is missing required Algorithm field; set it with key.Set(jwk.AlgorithmKey, ...)")
	}
	algStr := alg.String()
	if !SigningAlgorithm(algStr).Valid() {
		return fmt.Errorf("unsupported DPoP JWK algorithm %q; allowed: %s", algStr, dpopAllowedAlgs)
	}

	isPriv, err := jwk.IsPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to inspect DPoP JWK: %w", err)
	}
	if !isPriv {
		return errors.New("DPoP JWK must contain private signing material; a public-only key cannot sign proofs")
	}

	switch {
	case strings.HasPrefix(algStr, "ES"):
		if key.KeyType() != jwa.EC {
			return fmt.Errorf("DPoP algorithm %q requires an EC key, got key type %q", algStr, key.KeyType())
		}
		var rawKey ecdsa.PrivateKey
		if err := key.Raw(&rawKey); err != nil {
			return fmt.Errorf("failed to read EC key for DPoP validation: %w", err)
		}
		wantAlg, err := ecCurveToDPoPAlg(rawKey.Curve)
		if err != nil {
			return err
		}
		if wantAlg.String() != algStr {
			return fmt.Errorf("DPoP algorithm %q does not match EC key curve (expected %q for this curve)", algStr, wantAlg.String())
		}
	case strings.HasPrefix(algStr, "RS"):
		if key.KeyType() != jwa.RSA {
			return fmt.Errorf("DPoP algorithm %q requires an RSA key, got key type %q", algStr, key.KeyType())
		}
	}
	return nil
}

// resolveDPoPKey returns the jwk.Key to use for DPoP based on the config, using a
// single fixed priority:
//
//	dpopJWK       (WithDPoPJWK)                          → validate algorithm, return
//	dpopKeyPEM    (WithDPoPKeyPEM)                       → load from PEM, apply optional algorithm override
//	dpopAlgorithm (WithDPoPAlgorithm)                    → generate a fresh ephemeral key
//	dpopKey       (WithSessionSignerRSA)                 → convert the RSA key pair to a JWK
//	none configured                                      → (nil, nil)
//
// The function is pure: it does not mutate the config. Because the dpopAlgorithm
// branch generates a new ephemeral key on every call, callers MUST resolve once
// and share the result between the token source and the DPoP transport.
//
// A (nil, nil) return means no DPoP key is configured; callers auto-generate a
// default ephemeral ES256/P-256 key in that case.
func resolveDPoPKey(c *config) (jwk.Key, error) {
	key, err := selectDPoPKey(c)
	if err != nil || key == nil {
		return key, err
	}
	// Validate every resolved key uniformly so callers get a clear error at
	// resolution time regardless of how the key was supplied (JWK, PEM, alg, or
	// the RSA key pair), rather than a signing failure on the first proof.
	if err := validateDPoPKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// selectDPoPKey picks the DPoP key from the config by fixed priority without
// validating it (see resolveDPoPKey). A (nil, nil) return means none configured.
//
//nolint:nilnil // nil key signals "no DPoP key configured" — not an error condition
func selectDPoPKey(c *config) (jwk.Key, error) {
	switch {
	case c.dpopJWK != nil:
		return c.dpopJWK, nil
	case len(c.dpopKeyPEM) > 0:
		key, err := loadDPoPKeyFromPEM(c.dpopKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load DPoP key from PEM: %w", err)
		}
		if c.dpopAlgorithm != "" {
			// Restrict the override to the DPoP allow-list; jwa.Accept alone would
			// admit any JWX algorithm (e.g. HS256, none).
			if !c.dpopAlgorithm.Valid() {
				return nil, fmt.Errorf("invalid DPoP algorithm override %q; allowed: %s", c.dpopAlgorithm, dpopAllowedAlgs)
			}
			var algVal jwa.SignatureAlgorithm
			if err := algVal.Accept(string(c.dpopAlgorithm)); err != nil {
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
