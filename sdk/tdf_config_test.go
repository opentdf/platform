package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeConfig(t *testing.T, cfgFunc TDFOption) *TDFConfig {
	tdfConfig, err := newTDFConfig(cfgFunc)
	require.NoError(t, err)
	return tdfConfig
}

func TestWithDataAttributes(t *testing.T) {
	val1 := "https://example.com/attr/Classification/value/S"
	val2 := "https://example.com/attr/Classification/value/X"
	cfg := makeConfig(t, WithDataAttributes(val1, val2))

	require.Len(t, cfg.attributes, 2)
	assert.Equal(t, val1, cfg.attributes[0].url)
	assert.Equal(t, val2, cfg.attributes[1].url)
}

func TestWithKasInformation(t *testing.T) {
	val1 := "https://example.com/1"
	val2 := "https://example.com/2"
	cfg := makeConfig(t, WithKasInformation(KASInfo{URL: val1}, KASInfo{URL: val2}))

	require.Len(t, cfg.kasInfoList, 2)
	assert.Equal(t, val1, cfg.kasInfoList[0].URL)
	assert.Equal(t, val2, cfg.kasInfoList[1].URL)
}

func TestWithMetaData(t *testing.T) {
	md := "foo"
	cfg := makeConfig(t, WithMetaData(md))

	assert.Equal(t, md, cfg.metaData)
}

func TestWithMimeType(t *testing.T) {
	mt := "foo"
	cfg := makeConfig(t, WithMimeType(mt))

	assert.Equal(t, mt, cfg.mimeType)
}

func TestWithSegmentSize(t *testing.T) {
	tests := []struct {
		name         string
		optFunc      TDFOption
		expectedSize int64
	}{
		{
			name: "defaultSize",
			optFunc: func(_ *TDFConfig) error {
				return nil // no op
			},
			expectedSize: defaultSegmentSize,
		},
		{
			name:         "inRangeSize",
			optFunc:      WithSegmentSize(1024 * 1024),
			expectedSize: 1024 * 1024,
		},
		{
			name:         "tooSmallSize",
			optFunc:      WithSegmentSize(1),
			expectedSize: minSegmentSize,
		},
		{
			name:         "tooLargeSize",
			optFunc:      WithSegmentSize(maxSegmentSize + 1),
			expectedSize: maxSegmentSize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := makeConfig(t, test.optFunc)

			assert.Equal(t, test.expectedSize, cfg.defaultSegmentSize)
		})
	}
}

func TestWithAssertions(t *testing.T) {
	id1 := "1"
	id2 := "2"
	cfg := makeConfig(t, WithAssertions(AssertionConfig{ID: id1}, AssertionConfig{ID: id2}))

	require.Len(t, cfg.assertions, 2)
	assert.Equal(t, id1, cfg.assertions[0].ID)
	assert.Equal(t, id2, cfg.assertions[1].ID)
}

func TestWithTargetMode(t *testing.T) {
	tests := []struct {
		name           string
		targetMode     string
		useHex         bool
		excludeVersion bool
		expectError    bool
	}{
		{
			name:           "mode 0.0.0",
			targetMode:     "0.0.0",
			useHex:         true,
			excludeVersion: true,
			expectError:    false,
		},
		{
			name:           "mode v0.0.0",
			targetMode:     "v0.0.0",
			useHex:         true,
			excludeVersion: true,
			expectError:    false,
		},
		{
			name:           "equal mode 4.3.0",
			targetMode:     "4.3.0",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "greater mode 4.3.1",
			targetMode:     "4.3.1",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "greater mode v4.3.1",
			targetMode:     "v4.3.1",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "mode v2.3",
			targetMode:     "v2.3",
			useHex:         true,
			excludeVersion: true,
			expectError:    false,
		},
		{
			name:           "mode v4.3",
			targetMode:     "v4.3",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "mode v2",
			targetMode:     "v2",
			useHex:         true,
			excludeVersion: true,
			expectError:    false,
		},
		{
			name:           "mode v5",
			targetMode:     "v5",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "empty mode input",
			targetMode:     "",
			useHex:         false,
			excludeVersion: false,
			expectError:    false,
		},
		{
			name:           "invalid whitespace mode input",
			targetMode:     " ",
			useHex:         false,
			excludeVersion: false,
			expectError:    true,
		},
		{
			name:           "invalid mode input",
			targetMode:     "NotSemver",
			useHex:         false,
			excludeVersion: false,
			expectError:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var cfg *TDFConfig
			var err error

			cfg, err = newTDFConfig(WithTargetMode(test.targetMode))

			if test.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.useHex, cfg.useHex)
			assert.Equal(t, test.excludeVersion, cfg.excludeVersionFromManifest)
		})
	}
}
