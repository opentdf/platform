package db

import (
	"encoding/base64"
	"fmt"

	"github.com/opentdf/platform/protocol/go/policy"
)

func mapKasKeysToGrants(keys []*policy.KasKey) ([]*policy.KeyAccessServer, error) {
	if keys == nil || len(keys) == 0 {
		return nil, nil
	}

	grants := make([]*policy.KeyAccessServer, 0, len(keys))
	for _, key := range keys {
		grant := &policy.KeyAccessServer{}
		grant.Uri = key.GetKasUri()
		grant.Id = key.GetKasId()

		kasKeyInfo := key.GetKey()

		kasPubKey := &policy.KasPublicKey{
			Kid: kasKeyInfo.GetKeyId(),
			Alg: policy.KasPublicKeyAlgEnum(kasKeyInfo.GetKeyAlgorithm()),
		}

		if pubKeyCtx := kasKeyInfo.GetPublicKeyCtx(); pubKeyCtx != nil {
			// Grant pem isn't expected to be b64 encoded.
			pem, err := base64.StdEncoding.DecodeString(pubKeyCtx.GetPem())
			if err != nil {
				return nil, fmt.Errorf("failed to decode PEM for key %s: %w", kasPubKey.Kid, err)
			}
			kasPubKey.Pem = string(pem)
		}

		grant.PublicKey = &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{kasPubKey},
				},
			},
		}

		grants = append(grants, grant)
	}
	return grants, nil
}
