package unsafe

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/stretchr/testify/require"
)

var (
	errMessageUUID = "string.uuid"
	validUUID      = "00000000-0000-0000-0000-000000000000"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_UnsafeDeletePublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *unsafe.UnsafeDeletePublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid UnsafeDeletePublicKey (empty)",
			req:          &unsafe.UnsafeDeletePublicKeyRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (empty string)",
			req: &unsafe.UnsafeDeletePublicKeyRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (invalid UUID)",
			req: &unsafe.UnsafeDeletePublicKeyRequest{
				Id: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId",
			req: &unsafe.UnsafeDeletePublicKeyRequest{
				Id: validUUID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
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
