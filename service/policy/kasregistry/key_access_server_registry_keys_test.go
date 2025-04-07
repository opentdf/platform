package kasregistry

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/stretchr/testify/require"
)

const (
	invalidUUID          = "invalid-uuid"
	validKeyID           = "a-key"
	errMessageID         = "id"
	errInvalidUUID       = "invalid uuid"
	errMessageIdentifier = "identifier"
	errMessageKeyID      = "key_id"
	errMessageKasID      = "kas_id"
	errMessageKeyStatus  = "key_status"
	errMessageKeyAlgo    = "key_algorithm"
	errMessageKeyMode    = "key_mode"
	errMessagePubKeyCtx  = "public_key_ctx"
	invalidKeyMode       = -1
	invalidAlgo          = -1
	invalidKeyStatus     = -1
	invalidPageLimit     = 5001
)

var (
	validKeyCtx   = []byte(`{"key": "value"}`)
	validMetadata = &common.MetadataMutable{}
)

func Test_GetKeyAccessServer_Keys_Request(t *testing.T) {
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
			name: "Invalid Key ID (empty string)",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_KeyId{
					KeyId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyID,
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
			name: "Valid Key ID",
			req: &kasregistry.GetKeyRequest{
				Identifier: &kasregistry.GetKeyRequest_KeyId{
					KeyId: validKeyID,
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
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
				PrivateKeyCtx: validKeyCtx,
			},
			expectError:  true,
			errorMessage: errMessageKasID,
		},
		{
			name: "Invalid - KeyId required",
			req: &kasregistry.CreateKeyRequest{
				KasId:         validUUID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
				PrivateKeyCtx: validKeyCtx,
			},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Invalid - Valid Key Algo required",
			req: &kasregistry.CreateKeyRequest{
				KasId:         validUUID,
				KeyId:         validKeyID,
				KeyAlgorithm:  invalidAlgo,
				KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
				PrivateKeyCtx: validKeyCtx,
			},
			expectError:  true,
			errorMessage: errMessageKeyAlgo,
		},
		{
			name: "Invalid - Valid Key Mode required",
			req: &kasregistry.CreateKeyRequest{
				KasId:         validUUID,
				KeyId:         validKeyID,
				KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:       invalidKeyMode,
				PrivateKeyCtx: validKeyCtx,
			},
			expectError:  true,
			errorMessage: errMessageKeyMode,
		},
		{
			name: "Invalid - PublicKeyCtx required",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
			},
			expectError:  true,
			errorMessage: errMessagePubKeyCtx,
		},
		{
			name: "Invalid - PublicKeyCtx required more than 0 bytes",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: make([]byte, 0),
			},
			expectError:  true,
			errorMessage: errMessagePubKeyCtx,
		},
		{
			name: "Valid request required fields only",
			req: &kasregistry.CreateKeyRequest{
				KasId:        validUUID,
				KeyId:        validKeyID,
				KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx: validKeyCtx,
			},
			expectError: false,
		},
		{
			name: "Valid request (optional fields)",
			req: &kasregistry.CreateKeyRequest{
				KasId:            validUUID,
				KeyId:            validKeyID,
				KeyAlgorithm:     policy.Algorithm_ALGORITHM_EC_P256,
				KeyMode:          policy.KeyMode_KEY_MODE_LOCAL,
				PublicKeyCtx:     validKeyCtx,
				PrivateKeyCtx:    validKeyCtx,
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
		errorMessage string // Optional: expected error message substring
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
			name: "Valid Request",
			req: &kasregistry.UpdateKeyRequest{
				Id:                     validUUID,
				KeyStatus:              policy.KeyStatus_KEY_STATUS_ACTIVE,
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
				}},
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
