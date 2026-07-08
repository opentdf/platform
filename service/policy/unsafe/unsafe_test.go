package unsafe

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy"
	unsafepb "github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/stretchr/testify/require"
)

const (
	validUUID              = "00000000-0000-0000-0000-000000000000"
	ruleIDStringUUID       = "string.uuid"
	ruleIDKeyModeSupported = "key_mode_supported"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func TestUnsafeUpdateKeyRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *unsafepb.UnsafeUpdateKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name: "valid update to remote mode key",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
				ProviderConfigId: validUUID,
			},
			expectError: false,
		},
		{
			name: "valid update to public key only mode",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:      validUUID,
				KeyMode: policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			},
			expectError: false,
		},
		{
			name: "valid provider config update with unspecified mode",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_UNSPECIFIED,
				ProviderConfigId: validUUID,
			},
			expectError: false,
		},
		{
			name: "invalid id",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               "not-a-uuid",
				KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
				ProviderConfigId: validUUID,
			},
			expectError:  true,
			errorMessage: ruleIDStringUUID,
		},
		{
			name: "invalid provider config id",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
				ProviderConfigId: "not-a-uuid",
			},
			expectError:  true,
			errorMessage: ruleIDStringUUID,
		},
		{
			name: "invalid provider config id with spaces only",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
				ProviderConfigId: "  ",
			},
			expectError:  true,
			errorMessage: ruleIDStringUUID,
		},
		{
			name: "remote mode provider config requirement is service-owned",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:      validUUID,
				KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
			},
			expectError: false,
		},
		{
			name: "public key only provider config prohibition is service-owned",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				ProviderConfigId: validUUID,
			},
			expectError: false,
		},
		{
			name: "unsupported key mode",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:      validUUID,
				KeyMode: policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
			},
			expectError:  true,
			errorMessage: ruleIDKeyModeSupported,
		},
	}

	v := getValidator()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMessage)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateUnsafeUpdateKeyRequest(t *testing.T) {
	testCases := []struct {
		name string
		req  *unsafepb.UnsafeUpdateKeyRequest
		err  error
	}{
		{
			name: "remote requires provider config",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:      validUUID,
				KeyMode: policy.KeyMode_KEY_MODE_REMOTE,
			},
			err: errUnsafeUpdateKeyProviderConfigRequired,
		},
		{
			name: "unspecified requires provider config",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id: validUUID,
			},
			err: errUnsafeUpdateKeyProviderConfigUpdateRequired,
		},
		{
			name: "public key only rejects provider config",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
				ProviderConfigId: validUUID,
			},
			err: errUnsafeUpdateKeyProviderConfigNotAllowed,
		},
		{
			name: "remote accepts provider config",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:               validUUID,
				KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
				ProviderConfigId: validUUID,
			},
		},
		{
			name: "public key only accepts empty provider config",
			req: &unsafepb.UnsafeUpdateKeyRequest{
				Id:      validUUID,
				KeyMode: policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUnsafeUpdateKeyRequest(tc.req)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
		})
	}
}
