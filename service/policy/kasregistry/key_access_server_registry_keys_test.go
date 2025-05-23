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
	errMessageKeyMode                  = "key_mode_defined" // Updated for CEL rule ID
	errMessagePubKeyCtx                = "public_key_ctx"
	errMessagePrivateKeyCtx            = "The wrapped_key is required"            // This seems to be a generic message, CEL rules are more specific
	errMessageProviderConfigID         = "provider_config_id_optionally_required" // Updated for CEL rule ID
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
	errMessageNewKeyMode               = "new_key_mode_defined" // Updated for CEL rule ID
	errMessageNewKeyPubCtx             = "new_key.public_key_ctx"
	errMessageOneOfRequired            = "exactly one field is required in oneof" // For missing oneof fields
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
	validNewKeyConfigKEK = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:         validKeyID,
		Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  validPubCtx,
		PrivateKeyCtx: validPrivCtx,
		Metadata:      validMetadata,
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
	// Add correctly configured valid keys for RotateKeyRequest tests
	validRotateLocalConfigKEKNewKey = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:         validKeyID,
		Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  validPubCtx,
		PrivateKeyCtx: validPrivCtx, // Has WrappedKey (correct)
		Metadata:      validMetadata,
		// ProviderConfigId is empty (correct for this mode)
	}

	validRotateLocalProviderKEKNewKey = &kasregistry.RotateKeyRequest_NewKey{
		KeyId:            validKeyID,
		Algorithm:        policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:          policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
		PublicKeyCtx:     validPubCtx,
		PrivateKeyCtx:    validPrivCtx, // Has WrappedKey (correct)
		Metadata:         validMetadata,
		ProviderConfigId: validUUID, // Required for this mode
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
		{
			name: "Invalid Key - Kas ID (invalid uuid)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: invalidUUID,
						},
						Kid: validKeyID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
		{
			name: "Invalid Key - Kas ID (empty string)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_KasId{
							KasId: "",
						},
						Kid: validKeyID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
		{
			name: "Invalid Key - Kas Uri (empty string)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Uri{
							Uri: "",
						},
						Kid: validKeyID,
					},
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyURI,
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
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
			name: "Invalid - KasId (invalid uuid)",
			req: &kasregistry.CreateKeyRequest{
				KasId:         invalidUUID, // Invalid UUID
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx:  validPubCtx,
				PrivateKeyCtx: validPrivCtx,
			},
			expectError:  true,
			errorMessage: errMessageKasID, // Expecting validation error for kas_id
		},
		{
			name: "Invalid - KasId (empty string)",
			req: &kasregistry.CreateKeyRequest{
				KasId:         "", // Empty string, should fail UUID validation
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx:  validPubCtx,
				PrivateKeyCtx: validPrivCtx,
			},
			expectError:  true,
			errorMessage: errMessageKasID, // Expecting validation error for kas_id
		},
		{
			name: "Invalid - KeyId required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
			name: "Invalid - Key Algo unspecified",
			req: &kasregistry.CreateKeyRequest{
				KasId:         validUUID,
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_UNSPECIFIED, // Unspecified Algo
				KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx:  validPubCtx,
				PrivateKeyCtx: validPrivCtx,
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
			name: "Invalid - Key Mode unspecified",
			req: &kasregistry.CreateKeyRequest{
				KasId:         validUUID,
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       policy.KeyMode_KEY_MODE_UNSPECIFIED, // Unspecified Mode
				PublicKeyCtx:  validPubCtx,
				PrivateKeyCtx: validPrivCtx,
			},
			expectError:  true,
			errorMessage: errMessageKeyMode, // CEL rule: this >= 1 && this <= 4
		},
		{
			name: "Invalid - PublicKeyCtx required more than 0 bytes",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId: validKeyID,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid - KEY_MODE_REMOTE - WrappedKey should not be set",
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
					WrappedKey: validKeyCtx, // Should be empty
				},
				ProviderConfigId: validUUID, // Required
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID, // Expects "private_key_ctx_optionally_required"
		},
		{
			name: "Invalid - KEY_MODE_REMOTE - ProviderConfigId should be set",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey is empty (correct)
					KeyId: validKeyID,
				},
				// ProviderConfigId is missing (incorrect)
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID, // Expects "provider_config_id_optionally_required"
		},
		{
			name: "Invalid - KEY_MODE_CONFIG_ROOT_KEY - WrappedKey required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey is missing
					KeyId: validKeyID,
				},
				// ProviderConfigId is empty (correct)
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid - KEY_MODE_CONFIG_ROOT_KEY - ProviderConfigId must be empty",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx, // Correct
				},
				ProviderConfigId: validUUID, // Incorrect, should be empty
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Invalid - KEY_MODE_PROVIDER_ROOT_KEY - WrappedKey required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey is missing
					KeyId: validKeyID,
				},
				ProviderConfigId: validUUID, // Correct
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid - KEY_MODE_PROVIDER_ROOT_KEY - ProviderConfigId required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx, // Correct
				},
				// ProviderConfigId is missing (incorrect)
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Invalid - KEY_MODE_PUBLIC_KEY_ONLY - WrappedKey must be empty",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx, // Incorrect, should be empty
				},
				// ProviderConfigId is empty (correct)
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid - KEY_MODE_PUBLIC_KEY_ONLY - ProviderConfigId must be empty",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				PublicKeyCtx: validPubCtx,
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey is empty (correct)
					KeyId: validKeyID,
				},
				ProviderConfigId: validUUID, // Incorrect, should be empty
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Valid request - KEY_MODE_CONFIG_ROOT_KEY",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
				// ProviderConfigId is empty (correct)
			},
			expectError: false,
		},
		{
			name: "Valid request - KEY_MODE_PROVIDER_ROOT_KEY",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId:      validKeyID,
					WrappedKey: validKeyCtx,
				},
				ProviderConfigId: validUUID, // Correct
				Metadata:         validMetadata,
			},
			expectError: false,
		},
		{
			name: "Valid request - KEY_MODE_REMOTE",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey is empty (correct)
					KeyId: validKeyID,
				},
				ProviderConfigId: validUUID, // Correct
			},
			expectError: false,
		},
		{
			name: "Valid request - KEY_MODE_PUBLIC_KEY_ONLY",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				// ProviderConfigId is empty (correct)
			},
			expectError: false,
		},
		// New: KEY_MODE_PUBLIC_KEY_ONLY - PrivateKeyCtx must not be set at all
		{
			name: "Invalid - KEY_MODE_PUBLIC_KEY_ONLY - PrivateKeyCtx set (with valid key_id)",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				PublicKeyCtx: &policy.KasPublicKeyCtx{
					Pem: validKeyCtx,
				},
				PrivateKeyCtx: &policy.KasPrivateKeyCtx{
					KeyId: validKeyID,
				},
			},
			expectError:  true,
			errorMessage: "private_key_ctx must not be set",
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
		{
			name: "Valid Request (with unspecified key algorithm)",
			req: &kasregistry.ListKeysRequest{
				KeyAlgorithm: policy.Algorithm_ALGORITHM_UNSPECIFIED,
			},
			expectError: false, // Changed to false since it's optional
		},
		{
			name: "Invalid Request (empty kas name)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasName{
					KasName: "",
				},
			},
			expectError:  true,
			errorMessage: "kas_name", // Default message for string min_len
		},
		{
			name: "Invalid Request (empty kas uri)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasUri{
					KasUri: "",
				},
			},
			expectError:  true,
			errorMessage: "kas_uri", // Default message for string min_len
		},
		{
			name: "Invalid Request (invalid kas uri format)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasUri{
					KasUri: "not-a-valid-uri",
				},
			},
			expectError:  true,
			errorMessage: "kas_uri", // Default message for uri format
		},
		{
			name: "Valid Request (with kas_id filter)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasId{
					KasId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid Request (with kas_name filter)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasName{
					KasName: "test-kas",
				},
			},
			expectError: false,
		},
		{
			name: "Valid Request (with kas_uri filter)",
			req: &kasregistry.ListKeysRequest{
				KasFilter: &kasregistry.ListKeysRequest_KasUri{
					KasUri: "https://example.com/kas",
				},
			},
			expectError: false,
		},
		{
			name: "Valid Request (with key_algorithm filter)",
			req: &kasregistry.ListKeysRequest{
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
			},
			expectError: false,
		},
		{
			name:        "Valid Request (no filters)",
			req:         &kasregistry.ListKeysRequest{},
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
				NewKey: validNewKeyConfigKEK,
			},
			expectError:  true,
			errorMessage: errMessageOneOfRequired, // More specific for oneof requirement
		},
		{
			name: "Invalid Active Key ID (invalid uuid)",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: invalidUUID,
				},
				NewKey: validNewKeyConfigKEK,
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
				NewKey: validNewKeyConfigKEK,
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
				NewKey: validNewKeyConfigKEK,
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
				NewKey: validNewKeyConfigKEK,
			},
			expectError:  true,
			errorMessage: errMessageKeyKid,
		},
		{
			name: "Invalid Active Key - Kas Name (empty)",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Name{
							Name: "",
						},
						Kid: validKeyID,
					},
				},
				NewKey: validNewKeyConfigKEK,
			},
			expectError:  true,
			errorMessage: errMessageKeyName,
		},
		{
			name: "Invalid Active Key - Kas Uri (empty)",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Uri{
							Uri: "",
						},
						Kid: validKeyID,
					},
				},
				NewKey: validNewKeyConfigKEK,
			},
			expectError:  true,
			errorMessage: errMessageKeyURI,
		},
		{
			name: "Invalid Active Key - Kas Uri (invalid format)",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Key{
					Key: &kasregistry.KasKeyIdentifier{
						Identifier: &kasregistry.KasKeyIdentifier_Uri{
							Uri: "not-a-valid-uri",
						},
						Kid: validKeyID,
					},
				},
				NewKey: validNewKeyConfigKEK,
			},
			expectError:  true,
			errorMessage: errMessageKeyURI,
		},
		{
			name: "Invalid New Key - KeyID",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
					KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyAlgo,
		},
		{
			name: "Invalid New Key - Algorithm Unspecified",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     policy.Algorithm_ALGORITHM_UNSPECIFIED,
					KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
			name: "Invalid New Key - KeyMode Unspecified",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       policy.KeyMode_KEY_MODE_UNSPECIFIED,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx,
					Metadata:      validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageNewKeyMode, // CEL rule: this >= 1 && this <= 4
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
					KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
					KeyMode:   policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
					KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
					KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
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
			name: "Invalid New Key - KEY_MODE_CONFIG_ROOT_KEY - WrappedKey missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey missing
						KeyId: validKeyID,
					},
					Metadata: validMetadata,
					// ProviderConfigId is empty (correct)
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID, // Expects "private_key_ctx_optionally_required"
		},
		{
			name: "Invalid New Key - KEY_MODE_CONFIG_ROOT_KEY - ProviderConfigId must be empty",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{Id: validUUID},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:            validKeyID,
					Algorithm:        policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:          policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
					PublicKeyCtx:     validPubCtx,
					PrivateKeyCtx:    validPrivCtx, // Has WrappedKey (correct)
					ProviderConfigId: validUUID,    // Incorrect
					Metadata:         validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID, // Expects "provider_config_id_optionally_required"
		},
		{
			name: "Invalid New Key - KEY_MODE_PROVIDER_ROOT_KEY - WrappedKey missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{Id: validUUID},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey missing
						KeyId: validKeyID,
					},
					ProviderConfigId: validUUID, // Correct
					Metadata:         validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - KEY_MODE_PROVIDER_ROOT_KEY - ProviderConfigId missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{Id: validUUID},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:         validKeyID,
					Algorithm:     policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:       policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
					PublicKeyCtx:  validPubCtx,
					PrivateKeyCtx: validPrivCtx, // Has WrappedKey (correct)
					// ProviderConfigId missing (incorrect)
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Invalid New Key - KEY_MODE_REMOTE - WrappedKey present",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey present (incorrect)
						KeyId:      validKeyID,
						WrappedKey: validPrivCtx.GetWrappedKey(),
					},
					ProviderConfigId: validUUID, // Correct
					Metadata:         validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - KEY_MODE_REMOTE - ProviderConfigId missing",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey empty (correct)
						KeyId: validKeyID,
					},
					// ProviderConfigId missing (incorrect)
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Invalid New Key - KEY_MODE_PUBLIC_KEY_ONLY - WrappedKey present",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{Id: validUUID},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey present (incorrect)
						KeyId:      validKeyID,
						WrappedKey: validKeyCtx,
					},
					// ProviderConfigId empty (correct)
					Metadata: validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errPrivateKeyCtxMessageID,
		},
		{
			name: "Invalid New Key - KEY_MODE_PUBLIC_KEY_ONLY - ProviderConfigId present",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{Id: validUUID},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
					PublicKeyCtx: validPubCtx,
					PrivateKeyCtx: &policy.KasPrivateKeyCtx{ // WrappedKey empty (correct)
						KeyId: validKeyID,
					},
					ProviderConfigId: validUUID, // Incorrect
					Metadata:         validMetadata,
				},
			},
			expectError:  true,
			errorMessage: errMessageProviderConfigID,
		},
		{
			name: "Valid Rotate Request - NewKey is KEY_MODE_CONFIG_ROOT_KEY",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validRotateLocalConfigKEKNewKey, // Use the correctly configured valid key
			},
			expectError: false,
		},
		{
			name: "Valid Rotate Request - NewKey is KEY_MODE_PROVIDER_ROOT_KEY",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validRotateLocalProviderKEKNewKey, // Use the correctly configured valid key
			},
			expectError: false,
		},
		{
			name: "Valid Rotate Request - NewKey is KEY_MODE_REMOTE",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: validRemoteNewKey,
			},
			expectError: false,
		},
		{
			name: "Valid Rotate Request - NewKey is KEY_MODE_PUBLIC_KEY_ONLY",
			req: &kasregistry.RotateKeyRequest{
				ActiveKey: &kasregistry.RotateKeyRequest_Id{
					Id: validUUID,
				},
				NewKey: &kasregistry.RotateKeyRequest_NewKey{
					KeyId:        validKeyID,
					Algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
					KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
					PublicKeyCtx: validPubCtx,
					// PrivateKeyCtx omitted for KEY_MODE_PUBLIC_KEY_ONLY
					Metadata: validMetadata,
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

func Test_SetDefault_Keys(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.SetBaseKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid Request (empty)",
			req:          &kasregistry.SetBaseKeyRequest{},
			expectError:  true,
			errorMessage: errMessageRequired,
		},
		{
			name: "Valid Request (nano)",
			req: &kasregistry.SetBaseKeyRequest{
				ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
					Id: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid Request (ztdf)",
			req: &kasregistry.SetBaseKeyRequest{
				ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
					Id: validUUID,
				},
			},
			expectError: false,
		},
	}

	v := getValidator()

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
