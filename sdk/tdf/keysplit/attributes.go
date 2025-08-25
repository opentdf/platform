package keysplit

import (
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy"
)

// resolveAttributeGrants follows the hierarchy: value → definition → namespace
// Returns the most specific grants available for the given attribute value
func resolveAttributeGrants(value *policy.Value) (*AttributeGrant, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: value is nil", ErrNoAttributes)
	}

	// 1. Check for grants at VALUE level (most specific)
	if hasValidGrants(value.GetGrants(), value.GetKasKeys()) {
		slog.Debug("found grants at value level", slog.String("fqn", value.GetFqn()))
		grants := extractKASGrants(value.GetGrants(), value.GetKasKeys())
		return &AttributeGrant{
			Level:     ValueLevel,
			Attribute: value.GetAttribute(),
			KASGrants: grants,
		}, nil
	}

	// 2. Check for grants at DEFINITION level
	def := value.GetAttribute()
	if def != nil && hasValidGrants(def.GetGrants(), def.GetKasKeys()) {
		slog.Debug("found grants at definition level",
			slog.String("fqn", value.GetFqn()),
			slog.String("def_fqn", def.GetFqn()))
		grants := extractKASGrants(def.GetGrants(), def.GetKasKeys())
		return &AttributeGrant{
			Level:     DefinitionLevel,
			Attribute: def,
			KASGrants: grants,
		}, nil
	}

	// 3. Check for grants at NAMESPACE level (least specific)
	if def != nil && def.GetNamespace() != nil {
		ns := def.GetNamespace()
		if hasValidGrants(ns.GetGrants(), ns.GetKasKeys()) {
			slog.Debug("found grants at namespace level",
				slog.String("fqn", value.GetFqn()),
				slog.String("ns_fqn", ns.GetFqn()))
			grants := extractKASGrants(ns.GetGrants(), ns.GetKasKeys())
			return &AttributeGrant{
				Level:     NamespaceLevel,
				Attribute: def,
				KASGrants: grants,
			}, nil
		}
	}

	return nil, fmt.Errorf("%w: no grants found for attribute %s", ErrNoKASFound, value.GetFqn())
}

// hasValidGrants checks if there are any usable grants or KAS keys
func hasValidGrants(grants []*policy.KeyAccessServer, kasKeys []*policy.SimpleKasKey) bool {
	// Check for mapped keys first (preferred)
	if len(kasKeys) > 0 {
		for _, k := range kasKeys {
			if k != nil && k.GetKasUri() != "" && k.GetPublicKey() != nil {
				return true
			}
		}
	}

	// Check for legacy grants
	if len(grants) > 0 {
		for _, g := range grants {
			if g != nil && g.GetUri() != "" {
				return true
			}
		}
	}

	return false
}

// extractKASGrants converts policy grants/keys to internal KASGrant structures
func extractKASGrants(grants []*policy.KeyAccessServer, kasKeys []*policy.SimpleKasKey) []KASGrant {
	var result []KASGrant
	seen := make(map[string]bool) // Track unique KAS URLs

	// Process mapped keys first (preferred over legacy grants)
	for _, k := range kasKeys {
		if k == nil || k.GetKasUri() == "" {
			slog.Debug("skipping invalid KAS key", slog.Any("key", k))
			continue
		}

		kasURL := k.GetKasUri()
		if seen[kasURL] {
			continue // Skip duplicates
		}

		pubKey := k.GetPublicKey()
		if pubKey == nil || pubKey.GetKid() == "" || pubKey.GetPem() == "" {
			slog.Debug("skipping KAS key with invalid public key",
				slog.String("kas", kasURL),
				slog.Any("pubkey", pubKey))
			continue
		}

		result = append(result, KASGrant{
			URL:       kasURL,
			PublicKey: pubKey,
		})
		seen[kasURL] = true

		slog.Debug("extracted mapped KAS key",
			slog.String("kas", kasURL),
			slog.String("kid", pubKey.GetKid()),
			slog.String("alg", formatAlgorithm(pubKey.GetAlgorithm())))
	}

	// Process legacy grants if no mapped keys found
	if len(result) == 0 {
		for _, g := range grants {
			if g == nil || g.GetUri() == "" {
				continue
			}

			kasURL := g.GetUri()
			if seen[kasURL] {
				continue
			}

			// For legacy grants, try to extract keys from nested structures
			if len(g.GetKasKeys()) > 0 {
				// Nested KAS keys in grant
				for _, k := range g.GetKasKeys() {
					if k != nil && k.GetPublicKey() != nil {
						result = append(result, KASGrant{
							URL:       kasURL,
							PublicKey: k.GetPublicKey(),
						})
						seen[kasURL] = true
						break // Use first valid key
					}
				}
			} else if g.GetPublicKey() != nil && g.GetPublicKey().GetCached() != nil {
				// Cached keys in grant
				keys := g.GetPublicKey().GetCached().GetKeys()
				for _, ki := range keys {
					if ki.GetKid() != "" && ki.GetPem() != "" {
						// Convert cached key to SimpleKasPublicKey
						pubKey := &policy.SimpleKasPublicKey{
							Algorithm: convertAlgEnum2Simple(ki.GetAlg()),
							Pem:       ki.GetPem(),
							Kid:       ki.GetKid(),
						}
						result = append(result, KASGrant{
							URL:       kasURL,
							PublicKey: pubKey,
						})
						seen[kasURL] = true
						break // Use first valid key
					}
				}
			}

			// If no keys found, create placeholder grant (will need key resolution later)
			if !seen[kasURL] {
				slog.Debug("created placeholder grant without key", slog.String("kas", kasURL))
				result = append(result, KASGrant{
					URL:       kasURL,
					PublicKey: nil, // Will need resolution
				})
				seen[kasURL] = true
			}
		}
	}

	return result
}

// formatAlgorithm converts policy algorithm enum to string
func formatAlgorithm(alg policy.Algorithm) string {
	switch alg {
	case policy.Algorithm_ALGORITHM_EC_P256:
		return "ec:secp256r1"
	case policy.Algorithm_ALGORITHM_EC_P384:
		return "ec:secp384r1"
	case policy.Algorithm_ALGORITHM_EC_P521:
		return "ec:secp521r1"
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return "rsa:2048"
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return "rsa:4096"
	default:
		return "unknown"
	}
}

// convertAlgEnum2Simple converts KAS key algorithm enum to policy algorithm enum
func convertAlgEnum2Simple(a policy.KasPublicKeyAlgEnum) policy.Algorithm {
	switch a {
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1:
		return policy.Algorithm_ALGORITHM_EC_P256
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1:
		return policy.Algorithm_ALGORITHM_EC_P384
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1:
		return policy.Algorithm_ALGORITHM_EC_P521
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048:
		return policy.Algorithm_ALGORITHM_RSA_2048
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096:
		return policy.Algorithm_ALGORITHM_RSA_4096
	case policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	default:
		return policy.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// collectAllPublicKeys gathers all public keys from a set of split assignments
func collectAllPublicKeys(assignments []SplitAssignment) map[string]KASPublicKey {
	allKeys := make(map[string]KASPublicKey)

	for _, assignment := range assignments {
		for kasURL, pubKey := range assignment.Keys {
			if pubKey != nil {
				allKeys[kasURL] = KASPublicKey{
					URL:       kasURL,
					KID:       pubKey.GetKid(),
					PEM:       pubKey.GetPem(),
					Algorithm: formatAlgorithm(pubKey.GetAlgorithm()),
				}
			}
		}
	}

	return allKeys
}
