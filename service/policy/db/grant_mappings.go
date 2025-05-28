package db

import (
	"encoding/base64"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

func mapAlgorithmToKasPublicKeyAlg(alg policy.Algorithm) policy.KasPublicKeyAlgEnum {
	switch alg {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096
	case policy.Algorithm_ALGORITHM_EC_P256: // ALGORITHM_EC_P256 is an alias
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1
	case policy.Algorithm_ALGORITHM_EC_P384: // ALGORITHM_EC_P384 is an alias
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1
	case policy.Algorithm_ALGORITHM_EC_P521: // ALGORITHM_EC_P521 is an alias
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1
	case policy.Algorithm_ALGORITHM_UNSPECIFIED:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED
	default:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED
	}
}

func mapKasKeysToGrants(keys []*policy.KasKey, existingGrants []*policy.KeyAccessServer) ([]*policy.KeyAccessServer, error) {
	kasMap := make(map[string]*policy.KeyAccessServer)

	// Populate the map with existing grants
	for _, grant := range existingGrants {
		if grant != nil && grant.GetUri() != "" {
			kasMap[grant.GetUri()] = grant
		}
	}

	for _, key := range keys {
		if key == nil {
			continue
		}
		kasURI := key.GetKasUri()
		if kasURI == "" {
			// Skip keys without a URI, as it's essential for mapping
			continue
		}

		kasKeyInfo := key.GetKey()
		if kasKeyInfo == nil {
			continue
		}

		newKasPublicKey := &policy.KasPublicKey{
			Kid: kasKeyInfo.GetKeyId(),
			Alg: mapAlgorithmToKasPublicKeyAlg(kasKeyInfo.GetKeyAlgorithm()),
		}

		if pubKeyCtx := kasKeyInfo.GetPublicKeyCtx(); pubKeyCtx != nil {
			// PEM content in PublicKeyCtx is base64 encoded; decode it for KasPublicKey.Pem.
			pem, err := base64.StdEncoding.DecodeString(pubKeyCtx.GetPem())
			if err != nil {
				return nil, fmt.Errorf("failed to decode PEM for key %s: %w", newKasPublicKey.GetKid(), err)
			}
			newKasPublicKey.Pem = string(pem)
		}

		existingKas, found := kasMap[kasURI]
		if found {
			// KAS URI already exists, merge/add the public key
			if existingKas.GetPublicKey() == nil || existingKas.GetPublicKey().GetCached() == nil {
				// Initialize if PublicKey or Cached part is missing
				existingKas.PublicKey = &policy.PublicKey{
					PublicKey: &policy.PublicKey_Cached{
						Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{}},
					},
				}
			}
			// Deduplicate public keys by KID
			kidExists := false
			for _, pk := range existingKas.GetPublicKey().GetCached().GetKeys() {
				if pk.GetKid() == newKasPublicKey.GetKid() {
					kidExists = true
					break
				}
			}
			if !kidExists {
				existingKas.PublicKey.GetCached().Keys = append(existingKas.PublicKey.GetCached().GetKeys(), newKasPublicKey)
			}
		} else {
			// New KAS URI, create a new grant
			grant := &policy.KeyAccessServer{
				Uri: kasURI,
				Id:  key.GetKasId(),
				PublicKey: &policy.PublicKey{
					PublicKey: &policy.PublicKey_Cached{
						Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{newKasPublicKey}},
					},
				},
			}
			kasMap[kasURI] = grant
		}
	}

	// Convert map back to slice
	finalGrants := make([]*policy.KeyAccessServer, 0, len(kasMap))
	for _, grant := range kasMap {
		finalGrants = append(finalGrants, grant)
	}
	return finalGrants, nil
}
