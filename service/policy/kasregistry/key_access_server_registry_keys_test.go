package kasregistry

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/stretchr/testify/require"
)

const (
	invalidUUID                        = "invalid-uuid"
	validKeyID                         = "a-key"
	errMessageID                       = "id"
	errInvalidUUID                     = "invalid uuid"
	errMessageIdentifier               = "identifier"
	errMessageKeyID                    = "key_id"
	errMessageKasID                    = "kas_id"
	errMessageKeyStatus                = "key_status"
	errMessageKeyKid                   = "key.kid"
	errMessageKeyName                  = "key.name"
	errMessageKeyURI                   = "key.uri"
	errMessageKeyAlgo                  = "key_algorithm"
	errMessageKeyMode                  = "key_mode"
	errMessagePubKeyCtx                = "public_key_ctx"
	errMessagePrivateKeyCtx            = "The wrapped_key is required"
	errMessageProviderConfigID         = "Provider config id is required"
	errMessagePrivateKeyCtxKeyID       = "private_key_ctx.key_id"
	errMessagePrivateKeyCtxWrappedKey  = "private_key_ctx.wrapped_key"
	errMessageKeyIdentifier            = "identifier"
	invalidKeyMode                     = -1
	invalidAlgo                        = -1
	invalidKeyStatus                   = -1
	invalidPageLimit                   = 5001
	validKeyCtx                        = "eyJrZXkiOiJ2YWx1ZSJ9Cg=="
	errPrivateKeyCtxMessageID          = "private_key_ctx_optionally_required"
	errKeystatusUpdateMessageID        = "key_status_cannot_update_to_unspecified"
	errMetadataUpdateBehaviorMessageID = "metadata_update_behavior"
	errMessageNewKeyKid                = "new_key.key_id"
	errMessageNewKeyAlgo               = "new_key.algorithm"
	errMessageNewKeyMode               = "new_key.key_mode"
	errMessageNewKeyPubCtx             = "new_key.public_key_ctx"
)

var (
	validMetadata = &common.MetadataMutable{}
	validPubCtx   = &policy.KasPublicKeyCtx{
		Pem: validKeyCtx,
	}
	validPrivCtx = &policy.KasPrivateKeyCtx{
		KeyId:      validKeyID,
		WrappedKey: validKeyCtx,
	}
	validLocalNewKeyNoProvider = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:         validKeyID,
		Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx:  validPubCtx,
		PrivateKeyCtx: validPrivCtx,
		Metadata:      validMetadata,
	}
	validLocalNewKeyProvider = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:            validKeyID,
		Algorithm:        policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:          policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx:     validPubCtx,
		PrivateKeyCtx:    validPrivCtx,
		Metadata:         validMetadata,
		ProviderConfigId: validUUID,
	}
	validRemoteNewKey = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:        validKeyID,
		Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: validPubCtx,
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId: validKeyID,
		},
		ProviderConfigId: validUUID,
		Metadata:         validMetadata,
	}
)

func Test_GetKeyAccessServer_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.GetKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid Request (empty identifier)",
			req:          &kasregistry.GetKeyRequest{},
			expectError:  true,
			errorMessage: errMessageIdentifier,
		},
		{
			name: "Invalid ID (invalid uuid)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Id{
					Id: invalidUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Key - Key ID (empty)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: validUUID,
						},
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyKid,
		},
		{
			name: "Invalid Key - Kas ID (empty)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Kid: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageIdentifier,
		},
		{
			name: "Invalid Key - Kas Name (empty)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Name{
							Name: "",
						},
						Kid: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyName,
		},
		{
			name: "Invalid Key - Kas Uri (non-uri)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Uri{
							Uri: "not-a-uri",
						},
						Kid: validUUID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyURI,
		},
		{
			name: "Valid ID (valid uuid)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Id{
					Id: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid Key Req",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: validUUID,
						},
						Kid: validKeyID,
					},
				},
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_CreateKeyAccessServer_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.CreateKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "Invalid - KasId required",
			req: &kasregistry.CreateKeyRequest{
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
		{
			name: "Invalid - KeyId required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Invalid - Valid Key Algo required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: invalidAlgo,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyAlgo,
		},
		{
			name: "Invalid - Valid Key Mode required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      invalidKeyMode,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyMode,
		},
		{
			name: "Invalid - PublicKeyCtx required more than 0 bytes",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: "",
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessagePubKeyCtx,
		},
		{
			name: "Invalid - Private Key Ctx required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessagePrivateKeyCtx,
		},
		{
			name: "Invalid - Private Key Ctx Key Id required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errMessagePrivateKeyCtxKeyID,
		},
		{
			name: "Invalid - Private Key Ctx Wrapped Key required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId: validKeyID,
				},
			},
			expectError:  true,
			errorMessage: errMessagePrivateKeyCtx,
		},
		{
			name: "Invalid - Remote Private Key Ctx Wrapped Key should not be set",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid - Provider Config Id should be set when KeyMode is remote",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId: validKeyID,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Valid request required fields only - local key",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
			},
			expectError: false,
		},
		{
			name: "Valid request required fields only - remote key",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId: validKeyID,
				},
				ProviderConfigId: validUUID,
			},
			expectError: false,
		},
		{
			name: "Valid request (optional fields)",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
				ProviderConfigId: validUUID,
				Metadata:         validMetadata,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_UpdateKeyAccessServer_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.UpdateKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid Request (empty id)",
			req:          &kasregistry.UpdateKeyRequest{},
			expectError:  true,
			errorMessage: errMessageID,
		},
		{
			name: "Invalid Request (invalid uuid)",
			req: &kasregistry.UpdateKeyRequest{
				Id: invalidUUID,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Request (invalid key status)",
			req: &kasregistry.UpdateKeyRequest{
				Id:        validUUID,
				KeyStatus: invalidKeyStatus,
			},
			expectError:  true,
			errorMessage: errMessageKeyStatus,
		},
		{
			name: "Invalid Request - updating key status to unspecified",
			req: &kasregistry.UpdateKeyRequest{
				Id: validUUID,
			},
			expectError:  true,
			errorMessage: errKeystatusUpdateMessageID,
		},
		{
			name: "Invalid Request - metadata update behavior is 0 when updating metadata",
			req: &kasregistry.UpdateKeyRequest{
				Id:       validUUID,
				Metadata: &common.MetadataMutable{},
			},
			expectError:  true,
			errorMessage: errMetadataUpdateBehaviorMessageID,
		},
		{
			name: "Valid Request",
			req: &kasregistry.UpdateKeyRequest{
				Id:                     validUUID,
				KeyStatus:              policy.KeyStatus_KEY_STATUS_ACTIVE,
				Metadata:               validMetadata,
				MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
			},
			expectError: false,
		},
		{
			name: "Valid Request - Update Metadata",
			req: &kasregistry.UpdateKeyRequest{
				Id:                     validUUID,
				Metadata:               validMetadata,
				MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_ListKeyAccessServer_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.ListKeysRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid Request (invalid kas uuid)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasId{
					KasId: invalidUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_RotateKeyAccessServer_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.RotateKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "Invalid Request (empty active key)",
			req: &kasregistry.RotateKeyRequest{
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError:  true,
			errorMessage: errMessageRequired,
		},
		{
			name: "Invalid Active Key ID (invalid uuid)",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: invalidUUID,
				},
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Active Key - Missing identifier",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{},
				},
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError:  true,
			errorMessage: errMessageKeyIdentifier,
		},
		{
			name: "Invalid Active KasId",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: invalidUUID,
						},
						Kid: validKeyID,
					},
				},
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
		{
			name: "Invalid Active KeyID - Missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: validUUID,
						},
					},
				},
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError:  true,
			errorMessage: errMessageKeyKid,
		},
		{
			name: "Invalid New Key - KeyID",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyKid,
		},
		{
			name: "Invalid New Key - Algorithm",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     -1,
					KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyAlgo,
		},
		{
			name: "Invalid New Key - KeyMode",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       -1,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyMode,
		},
		{
			name: "Invalid New Key - PublicKeyCtx",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyPubCtx,
		},
		{
			name: "Invalid New Key - PublicKeyCtx - pem missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:     validKeyID,
					Algorithm: policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:   policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx: &policy.KasPublicKeyCtx{
						Pem: "",
					},
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyPubCtx,
		},
		{
			name: "Invalid New Key - PrivateKeyCtx - missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx: validPubCtx,
					Metadata:     validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - PrivateKeyCtx - missing key id",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{
						WrappedKey: validKeyCtx,
					},
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessagePrivateKeyCtxKeyID,
		},
		{
			name: "Invalid New Key - WrappedKey - missing for local key",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{
						KeyId: validKeyID,
					},
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - Wrapped Key - present for remote key",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{
						KeyId:      validKeyID,
						WrappedKey: validPrivCtx.GetWrappedKey(),
					},
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - Provider Config - not present for remote key",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{
						KeyId: validKeyID,
					},
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Valid Rotate Request - Local Key No Provider",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validLocalNewKeyNoProvider,
			},
			expectError: false,
		},
		{
			name: "Valid Rotate Request - Local Key Provider",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validLocalNewKeyProvider,
			},
			expectError: false,
		},
		{
			name: "Valid Rotate Request - Remote Key",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validRemoteNewKey,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}
