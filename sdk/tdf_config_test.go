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
	cfg := makeConfig(t, WithTargetMode("0.0.0"))
	assert.True(t, cfg.useHex)
	assert.True(t, cfg.excludeVersionFromManifest)

	cfg = makeConfig(t, WithTargetMode("v0.0.0"))
	assert.True(t, cfg.useHex)
	assert.True(t, cfg.excludeVersionFromManifest)

	cfg = makeConfig(t, WithTargetMode("4.3.0"))
	assert.False(t, cfg.useHex)
	assert.False(t, cfg.excludeVersionFromManifest)

	cfg = makeConfig(t, WithTargetMode("v4.3.1"))
	assert.False(t, cfg.useHex)
	assert.False(t, cfg.excludeVersionFromManifest)
}
