package sdk_test

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	goodPlatformEndpoint = "localhost:8080"
	badPlatformEndpoint  = "localhost:9999"
)

func GetMethods(i interface{}) []string {
	r := reflect.TypeOf(i)
	m := make([]string, 0)
	for i := 0; i < r.NumMethod(); i++ {
		m = append(m, r.Method(i).Name)
	}
	return m
}

func TestNew_ShouldCreateSDK(t *testing.T) {
	s, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": "https://example.org",
		}),
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Check platform issuer
	assert.Equal(t, "https://example.org", s.PlatformIssuer())

	// check if the clients are available
	assert.NotNil(t, s.Attributes)
	assert.NotNil(t, s.ResourceMapping)
	assert.NotNil(t, s.SubjectMapping)
	assert.NotNil(t, s.KeyAccessServerRegistry)
}

func Test_ShouldCreateNewSDK_NoCredentials(t *testing.T) {
	// When
	s, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": "https://example.org",
		}),
	)
	// Then
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNew_ShouldCloseConnections(t *testing.T) {
	s, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": "https://example.org",
		}),
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)
	require.NoError(t, s.Close())
}

func TestNew_ShouldHaveSameMethods(t *testing.T) {
	s, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": "https://example.org",
		}),
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		expected []string
		actual   []string
	}{
		{
			name:     "Attributes",
			expected: GetMethods(reflect.TypeOf(attributes.NewAttributesServiceClient(s.Conn()))),
			actual:   GetMethods(reflect.TypeOf(s.Attributes)),
		},
		{
			name:     "ResourceEncoding",
			expected: GetMethods(reflect.TypeOf(resourcemapping.NewResourceMappingServiceClient(s.Conn()))),
			actual:   GetMethods(reflect.TypeOf(s.ResourceMapping)),
		},
		{
			name:     "SubjectEncoding",
			expected: GetMethods(reflect.TypeOf(subjectmapping.NewSubjectMappingServiceClient(s.Conn()))),
			actual:   GetMethods(reflect.TypeOf(s.SubjectMapping)),
		},
		{
			name:     "KeyAccessGrants",
			expected: GetMethods(reflect.TypeOf(kasregistry.NewKeyAccessServerRegistryServiceClient(s.Conn()))),
			actual:   GetMethods(reflect.TypeOf(s.KeyAccessServerRegistry)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.actual)
		})
	}
}

func Test_ShouldCreateNewSDKWithBadEndpoint(t *testing.T) {
	// Bad endpoints are not detected until the first call to the platform
	t.Skip("Skipping test since this is expected but not great behavior")
	// When
	s, err := sdk.New(badPlatformEndpoint)
	// Then
	require.NoError(t, err)
	assert.NotNil(t, s)
}
