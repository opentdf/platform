package handlers

import (
	"testing"

	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two integrity flags are deliberately asymmetric: segments accept either
// algorithm because a GMAC segment hash really is the AES-GCM tag over that
// segment's ciphertext, while the root signature covers the aggregate hash,
// which the AEAD never touched, so only HS256 authenticates anything there.
func TestIntegrityAlgorithmsValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		algs    IntegrityAlgorithms
		wantErr string
	}{
		{name: "defaults/unset"},
		{name: "root hs256", algs: IntegrityAlgorithms{Root: "hs256"}},
		{name: "root HS256 uppercase", algs: IntegrityAlgorithms{Root: "HS256"}},
		{name: "segment gmac", algs: IntegrityAlgorithms{Segment: "gmac"}},
		{name: "segment hs256", algs: IntegrityAlgorithms{Segment: "hs256"}},
		{name: "segment GMAC uppercase", algs: IntegrityAlgorithms{Segment: "GMAC"}},
		{name: "both", algs: IntegrityAlgorithms{Root: "hs256", Segment: "hs256"}},

		// xtest greps stderr for this exact lowercase substring.
		{
			name:    "root gmac",
			algs:    IntegrityAlgorithms{Root: "gmac"},
			wantErr: "unsupported root integrity algorithm",
		},
		{
			name:    "root GMAC uppercase",
			algs:    IntegrityAlgorithms{Root: "GMAC"},
			wantErr: "unsupported root integrity algorithm",
		},
		{
			name:    "root GMac mixed case",
			algs:    IntegrityAlgorithms{Root: "GMac"},
			wantErr: "unsupported root integrity algorithm",
		},
		{
			name:    "root unknown",
			algs:    IntegrityAlgorithms{Root: "hs512"},
			wantErr: `unrecognized algorithm "hs512"`,
		},
		{
			name:    "segment unknown",
			algs:    IntegrityAlgorithms{Segment: "sha1"},
			wantErr: `unrecognized algorithm "sha1"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.algs.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	require.ErrorIs(t, IntegrityAlgorithms{Root: "gmac"}.Validate(), sdk.ErrUnsupportedRootIntegrityAlgorithm)
}

// An unset flag must not add an option at all, so the SDK defaults (HS256 root,
// GMAC segments) stay in force.
func TestIntegrityAlgorithmsOptions(t *testing.T) {
	opts, err := IntegrityAlgorithms{}.tdfOptions()
	require.NoError(t, err)
	assert.Empty(t, opts)

	opts, err = IntegrityAlgorithms{Root: "hs256", Segment: "gmac"}.tdfOptions()
	require.NoError(t, err)
	assert.Len(t, opts, 2)
}
