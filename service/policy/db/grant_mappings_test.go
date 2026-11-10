package db

import (
	"sort"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapKasKeysToGrants(t *testing.T) {
	validPem := "VALID_PEM_CONTENT"

	tests := []struct {
		name           string
		keys           []*policy.SimpleKasKey
		existingGrants []*policy.KeyAccessServer
		expectedGrants []*policy.KeyAccessServer
		wantErr        bool
		errContains    string
	}{
		{
			name:           "empty keys and empty existing grants",
			keys:           []*policy.SimpleKasKey{},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{},
			wantErr:        false,
		},
		{
			name: "new keys only, no existing grants",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
				{KasId: "kas2", KasUri: "http://kas2.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid2", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem}}}}}},
				{Id: "kas2", Uri: "http://kas2.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid2", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem}}}}}},
			},
			wantErr: false,
		},
		{
			name: "existing grants only, no new keys",
			keys: []*policy.SimpleKasKey{},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			wantErr: false,
		},
		{
			name: "add new public key to existing grant",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_new", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"},
					{Kid: "kid_new", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
			},
			wantErr: false,
		},
		{
			name: "add new grant and new public key to existing grant",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_new_for_kas1", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
				{KasId: "kas2", KasUri: "http://kas2.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_for_kas2", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing_for_kas1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_existing_for_kas1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"},
					{Kid: "kid_new_for_kas1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
				{Id: "kas2", Uri: "http://kas2.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_for_kas2", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem}}}}}},
			},
			wantErr: false,
		},
		{
			name: "deduplicate public key by KID",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_existing", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}}, // Same KID as existing
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"},
				}}}}},
			},
			wantErr: false,
		},
		{
			name: "nil key in keys slice",
			keys: []*policy.SimpleKasKey{
				nil,
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem}}}}}},
			},
			wantErr: false,
		},
		{
			name: "key with nil kas uri",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}}, // Nil URI
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{},
			wantErr:        true,
			errContains:    errKasInfoIncomplete.Error(),
		},
		{
			name: "key with nil kas id",
			keys: []*policy.SimpleKasKey{
				{KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{},
			wantErr:        true,
			errContains:    errKasInfoIncomplete.Error(),
		},
		{
			name: "key with nil public key",
			keys: []*policy.SimpleKasKey{
				{KasUri: "http://kas1.example.com", KasId: "kas1"},
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{},
			wantErr:        true,
			errContains:    "kas key info is nil for a key with kas uri http://kas1.example.com",
		},
		{
			name: "existing grant with nil PublicKey",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_new", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: nil},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_new", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
			},
			wantErr: false,
		},
		{
			name: "existing grant with PublicKey but nil Cached part",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_new", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: nil}}, // Simulates PublicKey_Cached being nil
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_new", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
			},
			wantErr: false,
		},
		{
			name: "nil grant in existingGrants slice",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				nil,
				{Id: "kas2", Uri: "http://kas2.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem}}}}}},
				{Id: "kas2", Uri: "http://kas2.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			wantErr: false,
		},
		{
			name: "existing grant with empty URI",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas_empty_uri", Uri: "", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_empty", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "empty_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem}}}}}},
			},
			wantErr: false,
		},
		{
			name: "multiple keys for the same new KAS URI",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid1_kas1", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}},
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid2_kas1", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid1_kas1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: validPem},
					{Kid: "kid2_kas1", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
			},
			wantErr: false,
		},
		{
			name: "multiple keys for the same existing KAS URI, one new, one duplicate KID",
			keys: []*policy.SimpleKasKey{
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_existing", Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Pem: validPem}}, // Duplicate KID
				{KasId: "kas1", KasUri: "http://kas1.example.com", PublicKey: &policy.SimpleKasPublicKey{Kid: "kid_new_for_existing", Algorithm: policy.Algorithm_ALGORITHM_EC_P256, Pem: validPem}},
			},
			existingGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"}}}}}},
			},
			expectedGrants: []*policy.KeyAccessServer{
				{Id: "kas1", Uri: "http://kas1.example.com", PublicKey: &policy.PublicKey{PublicKey: &policy.PublicKey_Cached{Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
					{Kid: "kid_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048, Pem: "existing_pem"},
					{Kid: "kid_new_for_existing", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1, Pem: validPem},
				}}}}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGrants, err := mapKasKeysToGrants(tt.keys, tt.existingGrants, logger.CreateTestLogger())

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				// Sort slices for consistent comparison as map iteration order is not guaranteed
				sortGrants(gotGrants)
				sortGrants(tt.expectedGrants)

				// Custom comparison because proto messages can be tricky with assert.Equal
				require.Len(t, gotGrants, len(tt.expectedGrants), "Number of grants mismatch")

				for i := range tt.expectedGrants {
					expected := tt.expectedGrants[i]
					actual := findGrantByURI(gotGrants, expected.GetUri())
					require.NotNil(t, actual, "Expected grant with URI %s not found", expected.GetUri())

					assert.Equal(t, expected.GetId(), actual.GetId(), "Grant ID mismatch for URI %s", expected.GetUri())
					assert.Equal(t, expected.GetUri(), actual.GetUri(), "Grant URI mismatch")

					expectedPKSet := expected.GetPublicKey().GetCached()
					actualPKSet := actual.GetPublicKey().GetCached()

					if expectedPKSet == nil {
						assert.Nil(t, actualPKSet, "Actual PublicKeySet should be nil if expected is nil for URI %s", expected.GetUri())
					} else {
						require.NotNil(t, actualPKSet, "Actual PublicKeySet should not be nil if expected is not nil for URI %s", expected.GetUri())
						require.Len(t, actualPKSet.GetKeys(), len(expectedPKSet.GetKeys()), "Number of public keys mismatch for URI %s", expected.GetUri())

						sortKasPublicKeys(actualPKSet.GetKeys())
						sortKasPublicKeys(expectedPKSet.GetKeys())

						for j := range expectedPKSet.GetKeys() {
							expPK := expectedPKSet.GetKeys()[j]
							actPK := findKasPublicKeyByKID(actualPKSet.GetKeys(), expPK.GetKid())
							require.NotNil(t, actPK, "Expected public key with KID %s not found for URI %s", expPK.GetKid(), expected.GetUri())

							assert.Equal(t, expPK.GetKid(), actPK.GetKid(), "Public key KID mismatch for URI %s", expected.GetUri())
							assert.Equal(t, expPK.GetAlg(), actPK.GetAlg(), "Public key Alg mismatch for KID %s, URI %s", expPK.GetKid(), expected.GetUri())
							assert.Equal(t, expPK.GetPem(), actPK.GetPem(), "Public key PEM mismatch for KID %s, URI %s", expPK.GetKid(), expected.GetUri())
						}
					}
				}
			}
		})
	}
}

func findGrantByURI(grants []*policy.KeyAccessServer, uri string) *policy.KeyAccessServer {
	for _, g := range grants {
		if g.GetUri() == uri {
			return g
		}
	}
	return nil
}

func findKasPublicKeyByKID(keys []*policy.KasPublicKey, kid string) *policy.KasPublicKey {
	for _, k := range keys {
		if k.GetKid() == kid {
			return k
		}
	}
	return nil
}

func sortGrants(grants []*policy.KeyAccessServer) {
	// Sort by URI for consistent comparison
	sort.SliceStable(grants, func(i, j int) bool {
		return grants[i].GetUri() < grants[j].GetUri()
	})
}

func sortKasPublicKeys(keys []*policy.KasPublicKey) {
	// Sort by KID for consistent comparison
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].GetKid() < keys[j].GetKid()
	})
}
