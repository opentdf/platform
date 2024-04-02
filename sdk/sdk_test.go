package sdk

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
)

var (
	goodPlatformEndpoint = "localhost:9000"
	badPlatformEndpoint  = "localhost:9999"
)

func setupMockServer(responseBody string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(responseBody)) // nolint:errcheck
	}))
}

func GetMethods(i interface{}) (m []string) {
	r := reflect.TypeOf(i)
	for i := 0; i < r.NumMethod(); i++ {
		m = append(m, r.Method(i).Name)
	}
	return m
}

func TestNew_ShouldCreateSDK(t *testing.T) {
	sdk, err := New(goodPlatformEndpoint,
		WithClientCredentials("myid", "mysecret", nil),
	)
	assert.NoError(t, err)
	assert.NotNil(t, sdk)
	if t.Failed() {
		return
	}

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
	if sdk.WellknownConfiguration == nil {
		t.Errorf("Expected WellknownConfiguration client, got nil")
	}
}

func Test_ShouldCreateNewSDK_NoCredentials(t *testing.T) {
	// When
	sdk, err := New(goodPlatformEndpoint)
	// Then
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
}

func TestNew_ShouldCloseConnections(t *testing.T) {
	sdk, err := New(goodPlatformEndpoint,
		WithClientCredentials("myid", "mysecret", nil),
		WithTokenEndpoint("https://example.org/token"),
	)
	assert.NoError(t, err)
	if !t.Failed() {
		assert.NoError(t, sdk.Close())
	}
}

func TestNew_ShouldHaveSameMethods(t *testing.T) {
	sdk, err := New(goodPlatformEndpoint,
		WithClientCredentials("myid", "mysecret", nil),
		WithTokenEndpoint("https://example.org/token"),
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
	sdk, err := New(badPlatformEndpoint)
	// Then
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if sdk == nil {
		t.Errorf("Expected sdk, got nil")
	}
}

func TestFetchTokenEndpoint_Success(t *testing.T) {
	mockResponse := `{"token_endpoint": "https://example.com/oauth2/token"}`
	mockServer := setupMockServer(mockResponse, http.StatusOK)
	defer mockServer.Close()

	endpoint, err := fetchTokenEndpoint(mockServer.URL)
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/oauth2/token", endpoint)
}

func TestFetchTokenEndpoint_InvalidJSON(t *testing.T) {
	mockResponse := `{"invalid_json": }`
	mockServer := setupMockServer(mockResponse, http.StatusOK)
	defer mockServer.Close()

	_, err := fetchTokenEndpoint(mockServer.URL)
	assert.Error(t, err)
}

func TestFetchTokenEndpoint_HttpError(t *testing.T) {
	mockServer := setupMockServer("", http.StatusNotFound) // Simulate 404 error
	defer mockServer.Close()

	_, err := fetchTokenEndpoint(mockServer.URL)
	assert.Error(t, err)
}
