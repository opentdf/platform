package sdk_test

import (
	"reflect"
	"testing"

	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
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
	sdk, err := sdk.New(goodPlatformEndpoint,
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)
	require.NotNil(t, sdk)

	// check if the clients are available
	if sdk.Attributes == nil {
		t.Errorf("Expected Attributes client, got nil")
	}
	if sdk.ResourceMapping == nil {
		t.Errorf("Expected ResourceEncoding client, got nil")
	}
	if sdk.SubjectMapping == nil {
		t.Errorf("Expected SubjectEncoding client, got nil")
	}
	if sdk.KeyAccessServerRegistry == nil {
		t.Errorf("Expected KeyAccessGrants client, got nil")
	}
}

func Test_ShouldCreateNewSDK_NoCredentials(t *testing.T) {
	// When
	sdk, err := sdk.New(goodPlatformEndpoint)
	// Then
	require.NoError(t, err)
	assert.NotNil(t, sdk)
}

func TestNew_ShouldCloseConnections(t *testing.T) {
	sdk, err := sdk.New(goodPlatformEndpoint,
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)
	require.NoError(t, sdk.Close())
}

func TestNew_ShouldHaveSameMethods(t *testing.T) {
	sdk, err := sdk.New(goodPlatformEndpoint,
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	tests := []struct {
		name     string
		expected []string
		actual   []string
	}{
		{
			name:     "Attributes",
			expected: GetMethods(reflect.TypeOf(attributes.NewAttributesServiceClient(sdk.Conn()))),
			actual:   GetMethods(reflect.TypeOf(sdk.Attributes)),
		},
		{
			name:     "ResourceEncoding",
			expected: GetMethods(reflect.TypeOf(resourcemapping.NewResourceMappingServiceClient(sdk.Conn()))),
			actual:   GetMethods(reflect.TypeOf(sdk.ResourceMapping)),
		},
		{
			name:     "SubjectEncoding",
			expected: GetMethods(reflect.TypeOf(subjectmapping.NewSubjectMappingServiceClient(sdk.Conn()))),
			actual:   GetMethods(reflect.TypeOf(sdk.SubjectMapping)),
		},
		{
			name:     "KeyAccessGrants",
			expected: GetMethods(reflect.TypeOf(kasregistry.NewKeyAccessServerRegistryServiceClient(sdk.Conn()))),
			actual:   GetMethods(reflect.TypeOf(sdk.KeyAccessServerRegistry)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.expected, tt.actual) {
				t.Errorf("Expected Attributes client to have methods %v, got %v", tt.actual, tt.expected)
			}
		})
	}
}

func Test_ShouldCreateNewSDKWithBadEndpoint(t *testing.T) {
	// Bad endpoints are not detected until the first call to the platform
	t.Skip("Skipping test since this is expected but not great behavior")
	// When
	sdk, err := sdk.New(badPlatformEndpoint)
	// Then
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if sdk == nil {
		t.Errorf("Expected sdk, got nil")
	}
}
