package db

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
)

var errKasInfoIncomplete = errors.New("kas information is incomplete")

func mapAlgorithmToKasPublicKeyAlg(alg policy.Algorithm) policy.KasPublicKeyAlgEnum {
	switch alg {
	case policy.Algorithm_ALGORITHM_RSA_2048:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048
	case policy.Algorithm_ALGORITHM_RSA_4096:
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096
	case policy.Algorithm_ALGORITHM_EC_P256:
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

func mapKasKeysToGrants(keys []*policy.SimpleKasKey, existingGrants []*policy.KeyAccessServer, l *logger.Logger) ([]*policy.KeyAccessServer, error) {
	kasMap := make(map[string]*policy.KeyAccessServer)

	// Populate the map with existing grants
	for _, grant := range existingGrants {
		if grant != nil && grant.GetUri() != "" {
			kasMap[grant.GetUri()] = grant
		}
	}

	for _, key := range keys {
		if key == nil {
			l.Debug("skipping nil key when mapping keys to grants")
			continue
		}
		if key.GetKasUri() == "" || key.GetKasId() == "" {
			return nil, errKasInfoIncomplete
		}

		kasKeyInfo := key.GetPublicKey()
		if kasKeyInfo == nil {
			return nil, fmt.Errorf("kas key info is nil for a key with kas uri %s", key.GetKasUri())
		}

		newKasPublicKey := &policy.KasPublicKey{
			Kid: kasKeyInfo.GetKid(),
			Alg: mapAlgorithmToKasPublicKeyAlg(kasKeyInfo.GetAlgorithm()),
			Pem: kasKeyInfo.GetPem(),
		}

		existingKas, found := kasMap[key.GetKasUri()]
		if found {
			// KAS URI already exists, merge/add the public key
			if existingKas.GetPublicKey().GetCached() == nil {
				// Initialize if PublicKey or Cached part is missing
				//nolint:staticcheck // Using deprecated protobuf field for backward compatibility
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
				existingKas.GetPublicKey().GetCached().Keys = append(existingKas.GetPublicKey().GetCached().GetKeys(), newKasPublicKey)
			}
		} else {
			// New KAS URI, create a new grant
			grant := &policy.KeyAccessServer{
				Uri: key.GetKasUri(),
				Id:  key.GetKasId(),
				PublicKey: &policy.PublicKey{
					PublicKey: &policy.PublicKey_Cached{
						Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{newKasPublicKey}},
					},
				},
			}
			kasMap[key.GetKasUri()] = grant
		}
	}

	// Convert map back to slice
	finalGrants := make([]*policy.KeyAccessServer, 0, len(kasMap))
	for _, grant := range kasMap {
		finalGrants = append(finalGrants, grant)
	}
	return finalGrants, nil
}
