package db

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	servicedb "github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/require"
)

const unsafeUpdateKeyTestUUID = "00000000-0000-0000-0000-000000000000"

func TestValidateUnsafeUpdateKey(t *testing.T) {
	tests := []struct {
		name           string
		existingMode   policy.KeyMode
		requestMode    policy.KeyMode
		providerConfig string
		wantMode       pgtype.Int4
		wantProvider   pgtype.UUID
		wantErr        error
	}{
		{
			name:           "remote from public key only",
			existingMode:   policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			requestMode:    policy.KeyMode_KEY_MODE_REMOTE,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantMode:       pgtypeInt4(int32(policy.KeyMode_KEY_MODE_REMOTE), true),
			wantProvider:   pgtypeUUID(unsafeUpdateKeyTestUUID),
		},
		{
			name:           "remote from remote",
			existingMode:   policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:    policy.KeyMode_KEY_MODE_REMOTE,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantMode:       pgtypeInt4(int32(policy.KeyMode_KEY_MODE_REMOTE), true),
			wantProvider:   pgtypeUUID(unsafeUpdateKeyTestUUID),
		},
		{
			name:         "public key only from remote",
			existingMode: policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:  policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			wantMode:     pgtypeInt4(int32(policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY), true),
		},
		{
			name:           "provider config only from remote",
			existingMode:   policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:    policy.KeyMode_KEY_MODE_UNSPECIFIED,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantProvider:   pgtypeUUID(unsafeUpdateKeyTestUUID),
		},
		{
			name:         "public key only from public key only",
			existingMode: policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			requestMode:  policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			wantMode:     pgtypeInt4(int32(policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY), true),
		},
		{
			name:           "provider config only from public key only rejected",
			existingMode:   policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			requestMode:    policy.KeyMode_KEY_MODE_UNSPECIFIED,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantErr:        servicedb.ErrUnsafeUpdateKeyProviderConfigExistingMode,
		},
		{
			name:         "remote requires provider config",
			existingMode: policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			requestMode:  policy.KeyMode_KEY_MODE_REMOTE,
			wantErr:      servicedb.ErrUnsafeUpdateKeyProviderConfigRequired,
		},
		{
			name:         "provider config only update requires provider config",
			existingMode: policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:  policy.KeyMode_KEY_MODE_UNSPECIFIED,
			wantErr:      servicedb.ErrUnsafeUpdateKeyProviderConfigRequired,
		},
		{
			name:           "public key only rejects provider config",
			existingMode:   policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:    policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantErr:        servicedb.ErrUnsafeUpdateKeyProviderConfigNotAllowed,
		},
		{
			name:           "existing config root key rejected before request validation",
			existingMode:   policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
			requestMode:    policy.KeyMode_KEY_MODE_REMOTE,
			providerConfig: unsafeUpdateKeyTestUUID,
			wantErr:        servicedb.ErrUnsafeUpdateKeyExistingModeUnsupported,
		},
		{
			name:         "unsupported target mode rejected",
			existingMode: policy.KeyMode_KEY_MODE_REMOTE,
			requestMode:  policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
			wantErr:      servicedb.ErrUnsafeUpdateKeyTargetModeUnsupported,
		},
		// TODO: Add a test about the invalid provider config id for remote mode
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotParams, err := validateUnsafeUpdateKey(&policy.KasKey{
				Key: &policy.AsymmetricKey{
					KeyMode: tt.existingMode,
				},
			}, &unsafe.UnsafeUpdateKeyRequest{
				Id:               unsafeUpdateKeyTestUUID,
				TargetKeyMode:    tt.requestMode,
				ProviderConfigId: tt.providerConfig,
			})

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, unsafeUpdateKeyTestUUID, gotParams.ID)
			require.Equal(t, tt.wantMode, gotParams.KeyMode)
			require.Equal(t, tt.wantProvider, gotParams.ProviderConfigID)
		})
	}
}
