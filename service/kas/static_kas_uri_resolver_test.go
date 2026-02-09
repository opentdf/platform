package kas

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStaticRegisteredKasURIResolver(t *testing.T) {
	resolver, err := NewStaticRegisteredKasURIResolver("")
	require.ErrorIs(t, err, errKasURIEmpty)
	require.Nil(t, resolver)

	resolver, err = NewStaticRegisteredKasURIResolver(testKasURI)
	require.NoError(t, err)
	require.NotNil(t, resolver)
}

func TestStaticRegisteredKasURIResolverResolveURI(t *testing.T) {
	resolver, err := NewStaticRegisteredKasURIResolver(testKasURI)
	require.NoError(t, err)

	uri, err := resolver.ResolveURI()
	require.NoError(t, err)
	require.Equal(t, testKasURI, uri)

	resolver = &StaticRegisteredKasURIResolver{}
	uri, err = resolver.ResolveURI()
	require.Error(t, err)
	require.Empty(t, uri)
}

func TestStaticRegisteredKasURIResolverString(t *testing.T) {
	resolver, err := NewStaticRegisteredKasURIResolver(testKasURI)
	require.NoError(t, err)

	expected := resolverNameKey + ": " + staticResolverName + ", " + kasURIKey + ": " + testKasURI
	require.Equal(t, expected, resolver.String())
}

func TestStaticRegisteredKasURIResolverLogValue(t *testing.T) {
	resolver, err := NewStaticRegisteredKasURIResolver(testKasURI)
	require.NoError(t, err)

	require.Equal(t, slog.StringValue(resolver.String()), resolver.LogValue())
}
