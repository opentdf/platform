package db

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetListLimit(t *testing.T) {
	var defaultListLimit int32 = 1000
	cases := []struct {
		limit    int32
		expected int32
	}{
		{
			0,
			1000,
		},
		{
			1,
			1,
		},
		{
			10000,
			10000,
		},
	}

	for _, test := range cases {
		result := getListLimit(test.limit, defaultListLimit)
		assert.Equal(t, test.expected, result)
	}
}

func Test_GetNextOffset(t *testing.T) {
	var defaultTestListLimit int32 = 250
	cases := []struct {
		currOffset int32
		limit      int32
		total      int32
		expected   int32
		scenario   string
	}{
		{
			currOffset: 0,
			limit:      defaultTestListLimit,
			total:      1000,
			expected:   defaultTestListLimit,
			scenario:   "defaulted limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      1000,
			expected:   200,
			scenario:   "custom limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      200,
			expected:   0,
			scenario:   "custom limit with none remaining",
		},
		{
			currOffset: 100,
			limit:      defaultTestListLimit,
			total:      200,
			expected:   0,
			scenario:   "default limit with none remaining",
		},
		{
			currOffset: 350 - defaultTestListLimit - 1,
			limit:      defaultTestListLimit,
			total:      350,
			expected:   349,
			scenario:   "default limit with exactly one remaining",
		},
		{
			currOffset: 1000 - 500 - 1,
			limit:      500,
			total:      1000,
			expected:   1000 - 1,
			scenario:   "custom limit with exactly one remaining",
		},
	}

	for _, test := range cases {
		result := getNextOffset(test.currOffset, test.limit, test.total)
		assert.Equal(t, test.expected, result, test.scenario)
	}
}

func Test_UnmarshalAllActionsProto(t *testing.T) {
	tests := []struct {
		name              string
		stdActionsJSON    []byte
		customActionsJSON []byte
		wantLen           int
	}{
		{
			name:              "Only Standard Actions",
			stdActionsJSON:    []byte(`[{"id":"std1", "name":"Standard One"}, {"id":"std2", "name":"Standard Two"}]`),
			customActionsJSON: []byte(`[]`),
			wantLen:           2,
		},
		{
			name:              "Only Custom Actions",
			stdActionsJSON:    []byte(`[]`),
			customActionsJSON: []byte(`[{"id":"custom1", "name":"Custom One"}, {"id":"custom2", "name":"Custom Two"}]`),
			wantLen:           2,
		},
		{
			name:              "Both Standard and Custom Actions",
			stdActionsJSON:    []byte(`[{"id":"std1", "name":"Standard One"}, {"id":"std2", "name":"Standard Two"}]`),
			customActionsJSON: []byte(`[{"id":"custom1", "name":"Custom One"}, {"id":"custom2", "name":"Custom Two"}]`),
			wantLen:           4,
		},
		{
			name:              "Empty Actions",
			stdActionsJSON:    []byte(`[]`),
			customActionsJSON: []byte(`[]`),
			wantLen:           0,
		},
		{
			name:              "Nil Actions",
			stdActionsJSON:    nil,
			customActionsJSON: nil,
			wantLen:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := []*policy.Action{}

			err := unmarshalAllActionsProto(tt.stdActionsJSON, tt.customActionsJSON, &actions)
			if err != nil {
				t.Errorf("unmarshalAllActionsProto() unexpected error = %v", err)
			}

			if len(actions) != tt.wantLen {
				t.Errorf("unmarshalAllActionsProto() len(actions) = %v, wantLen %v", len(actions), tt.wantLen)
			}
		})
	}
}

func Test_UnmarshalPrivatePublicKeyContext(t *testing.T) {
	tests := []struct {
		name    string
		pubCtx  []byte
		privCtx []byte
		wantErr bool
	}{
		{
			name:    "Successful unmarshal of both public and private keys",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Successful unmarshal of only public key",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "Successful unmarshal of only private key",
			pubCtx:  []byte(`{}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Invalid public key JSON",
			pubCtx:  []byte(`{"pem": "invalid`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: true,
		},
		{
			name:    "Invalid private key JSON",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "invalid`),
			wantErr: true,
		},
		{
			name:    "Empty public context",
			pubCtx:  []byte(`{}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Empty private context",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "Nil public and private key pointers",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Nil public key pointer",
			pubCtx:  nil,
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Nil private key pointer",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: nil,
			wantErr: false,
		},
		{
			name:    "Nil public and private key pointers",
			pubCtx:  nil,
			privCtx: nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKeyCtx, privKeyCtx, err := unmarshalPrivatePublicKeyContext(tt.pubCtx, tt.privCtx)

			if tt.wantErr {
				require.Error(t, err)
				return // Exit early if an error was expected
			}

			// If we reach here, no error was expected
			require.NoError(t, err)

			if tt.pubCtx == nil {
				assert.Nil(t, pubKeyCtx, "pubKeyCtx should be nil when tt.pubCtx is nil for test: %s", tt.name)
			} else {
				assert.NotNil(t, pubKeyCtx, "pubKeyCtx should not be nil when tt.pubCtx is not nil for test: %s", tt.name)
				// Only check GetPem if input tt.pubCtx was not empty and not an empty JSON object,
				// implying it was intended to contain the "PUBLIC_KEY_PEM".
				if len(tt.pubCtx) > 0 && string(tt.pubCtx) != `{}` {
					assert.Equal(t, "PUBLIC_KEY_PEM", pubKeyCtx.GetPem(), "Mismatch in pubKeyCtx.GetPem() for test: %s", tt.name)
				}
			}

			if tt.privCtx == nil {
				assert.Nil(t, privKeyCtx, "privKeyCtx should be nil when tt.privCtx is nil for test: %s", tt.name)
			} else {
				assert.NotNil(t, privKeyCtx, "privKeyCtx should not be nil when tt.privCtx is not nil for test: %s", tt.name)
				// Only check GetKeyId and GetWrappedKey if input tt.privCtx was not empty and not an empty JSON object,
				// implying it was intended to contain the "PRIVATE_KEY_ID" and "WRAPPED_PRIVATE_KEY".
				if len(tt.privCtx) > 0 && string(tt.privCtx) != `{}` {
					assert.Equal(t, "PRIVATE_KEY_ID", privKeyCtx.GetKeyId(), "Mismatch in privKeyCtx.GetKeyId() for test: %s", tt.name)
					assert.Equal(t, "WRAPPED_PRIVATE_KEY", privKeyCtx.GetWrappedKey(), "Mismatch in privKeyCtx.GetWrappedKey() for test: %s", tt.name)
				}
			}
		})
	}
}
