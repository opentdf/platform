package sdk_test

import (
	"bytes"
	"encoding/base64"
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
			"idp": map[string]interface{}{
				"issuer":                 "https://example.org",
				"authorization_endpoint": "https://example.org/auth",
				"token_endpoint":         "https://example.org/token",
				"public_client_id":       "myclient",
			},
		}),
		sdk.WithClientCredentials("myid", "mysecret", nil),
		sdk.WithTokenEndpoint("https://example.org/token"),
	)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Check platform issuer
	iss, err := s.PlatformConfiguration.Issuer()
	assert.Equal(t, "https://example.org", iss)
	require.NoError(t, err)

	// Check platform authz endpoint
	authzEndpoint, err := s.PlatformConfiguration.AuthzEndpoint()
	assert.Equal(t, "https://example.org/auth", authzEndpoint)
	require.NoError(t, err)

	// Check platform token endpoint
	tokenEndpoint, err := s.PlatformConfiguration.TokenEndpoint()
	assert.Equal(t, "https://example.org/token", tokenEndpoint)
	require.NoError(t, err)

	// Check platform public client id
	publicClientID, err := s.PlatformConfiguration.PublicClientID()
	assert.Equal(t, "myclient", publicClientID)
	require.NoError(t, err)

	// check if the clients are available
	assert.NotNil(t, s.Attributes)
	assert.NotNil(t, s.ResourceMapping)
	assert.NotNil(t, s.SubjectMapping)
	assert.NotNil(t, s.KeyAccessServerRegistry)
}

func Test_PlatformConfiguration_BadCases(t *testing.T) {
	assertions := func(t *testing.T, s *sdk.SDK) {
		iss, err := s.PlatformConfiguration.Issuer()
		assert.Equal(t, "", iss)
		require.ErrorIs(t, err, sdk.ErrPlatformIssuerNotFound)

		authzEndpoint, err := s.PlatformConfiguration.AuthzEndpoint()
		assert.Equal(t, "", authzEndpoint)
		require.ErrorIs(t, err, sdk.ErrPlatformAuthzEndpointNotFound)

		tokenEndpoint, err := s.PlatformConfiguration.TokenEndpoint()
		assert.Equal(t, "", tokenEndpoint)
		require.ErrorIs(t, err, sdk.ErrPlatformTokenEndpointNotFound)

		publicClientID, err := s.PlatformConfiguration.PublicClientID()
		assert.Equal(t, "", publicClientID)
		require.ErrorIs(t, err, sdk.ErrPlatformTokenEndpointNotFound)
	}

	noIdpValsSDK, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"idp": map[string]interface{}{},
		}),
	)
	require.NoError(t, err)
	assert.NotNil(t, noIdpValsSDK)

	assertions(t, noIdpValsSDK)

	noIdpCfgSDK, err := sdk.New(goodPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{}),
	)
	require.NoError(t, err)
	assert.NotNil(t, noIdpCfgSDK)

	assertions(t, noIdpCfgSDK)
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

func TestNew_ShouldValidateGoodNanoTdf(t *testing.T) {
	goodNanoTdfStr := "TDFMABJsb2NhbGhvc3Q6ODA4MC9rYXOAAQIA2qvjMRfg7b27lT2kf9SwHRkDIg8ZXtfRoiIvdMUHq/gL5AUMfmv4Di8sKCyLkmUm/WITVj5hDeV/z4JmQ0JL7ZxqSmgZoK6TAHvkKhUly4zMEWMRXH8IktKhFKy1+fD+3qwDopqWAO5Nm2nYQqi75atEFckstulpNKg3N+Ul22OHr/ZuR127oPObBDYNRfktBdzoZbEQcPlr8q1B57q6y5SPZFjEzL9weK+uS5bUJWkF3nsHASo2bZw7IPhTZxoFVmCDjwvj6MbxNa7zG6aClHJ162zKxLLnD9TtIHuZ59R7LgiSieipXeExj+ky9OgIw5DfwyUuxsQLtKpMIAFPmLY9Hy2naUJxke0MT1EUBgastCq+YtFGslV9LJo/A8FtrRqludwtM0O+Z9FlAkZ1oNL7M7uOkLrh7eRrv+C1AAAX6FaBQoOtqnmyu6Jp+VzkxDddEeLRUyI="
	goodDecodedData, err := base64.StdEncoding.DecodeString(goodNanoTdfStr)
	in := bytes.NewReader(goodDecodedData)

	require.NoError(t, err)
	// Decode the base64 string
	isValid, err := sdk.IsValidNanoTdf(in)
	require.NoError(t, err)

	assert.True(t, isValid)
}

func TestNew_ShouldNotValidateBadNanoTdf(t *testing.T) {
	badNanoTdfStr := "TDFMABfg7b27lT2kf9SwHRkDIg8ZXtfRoiIvdMUHq/gL5AUMfmv4Di8sKCyLkmUm/WITVj5hDeV/z4JmQ0JL7ZxqSmgZoK6TAHvkKhUly4zMEWMRXH8IktKhFKy1+fD+3qwDopqWAO5Nm2nYQqi75atEFckstulpNKg3N+Ul22OHr/ZuR127oPObBDYNRfktBdzoZbEQcPlr8q1B57q6y5SPZFjEzL9weK+uS5bUJWkF3nsHASo2bZw7IPhTZxoFVmCDjwvj6MbxNa7zG6aClHJ162zKxLLnD9TtIHuZ59R7LgiSieipXeExj+ky9OgIw5DfwyUuxsQLtKpMIAFPmLY9Hy2naUJxke0MT1EUBgastCq+YtFGslV9LJo/A8FtrRqludwtM0O+Z9FlAkZ1oNL7M7uOkLrh7eRrv+C1AAAX6FaBQoOtqnmyu6Jp+VzkxDddEeLRUyI="
	badDecodedData, err := base64.StdEncoding.DecodeString(badNanoTdfStr)
	in := bytes.NewReader(badDecodedData)

	require.NoError(t, err)
	// Decode the base64 string
	isValid, _ := sdk.IsValidNanoTdf(in)
	// Error is ok here, as it acts as a sort of reason for the nanotdf not being valid
	assert.False(t, isValid)
}

func TestNew_ShouldValidateStandardTdf(t *testing.T) {
	goodStandardTdf := "UEsDBC0ACAAAAJ2TFTEAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2Fktu4m+vdwl0mtjhY3U5e7TG2o1s8ifK+RAhFNjRjGTLJ7V3w5UEsHCGiY7skkAAAAJAAAAFBLAwQtAAgAAACdkxUxAAAAAAAAAAAAAAAADwAAADAubWFuaWZlc3QuanNvbnsiZW5jcnlwdGlvbkluZm9ybWF0aW9uIjp7InR5cGUiOiJzcGxpdCIsInBvbGljeSI6ImV5SjFkV2xrSWpvaU1HTTFORGsyWlRZdE5EYzRaaTB4TVdWbUxXSXlOakV0WWpJMVl6UmhORE14TjJFM0lpd2lZbTlrZVNJNmV5SmtZWFJoUVhSMGNtbGlkWFJsY3lJNlczc2lZWFIwY21saWRYUmxJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbU52YlM5aGRIUnlMMkYwZEhJeEwzWmhiSFZsTDNaaGJIVmxNU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lJaXdpYVhORVpXWmhkV3gwSWpwbVlXeHpaU3dpY0hWaVMyVjVJam9pSWl3aWEyRnpWVkpNSWpvaUluMWRMQ0prYVhOelpXMGlPbHRkZlgwPSIsImtleUFjY2VzcyI6W3sidHlwZSI6IndyYXBwZWQiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJwcm90b2NvbCI6ImthcyIsIndyYXBwZWRLZXkiOiJ0VVMvUE9TaVBtOGV6OGhyL2dMVGN6Y1lOT0trcUNEclZiQTBWdHZna29QbHB0M1BDZVpTdDNndnlQNVZKZXBNMmNqdVBhUWJJUGlyMjlWdVJ2T1RXZmQzRUh1KzgyVCtFNEVZbEpBM25VbDdGQTRMUGZhUEtXWk1zTExHUkJJVUxZT0VhMWJma1MvUm9Xb0EwK283WlFFVkNhYmdJN2JFRDJKV2Q2aG1yam1iUnM2d0lwOVFXNUs4Q3dJWjZVZjlGMXEwRDViTmlrbGxHaCtiaVJsV1NucEwxbHBPaFdva1gxdUJsU0VRSDNvM2JtVXFTNVVaUjRmYUxuTW5xOGR0bS8wYnJjTjUwaFNiK0xTTlZkd2daTEszTTRHTmxEeGdzcDkxY0VuYjZoZktLemdSY0VCS0tMQTF1b3BXNHdCRG9BamFuWWplQlZVT3ZBZEI5ek45T3c9PSIsInBvbGljeUJpbmRpbmciOnsiYWxnIjoiSFMyNTYiLCJoYXNoIjoiWmpBek1HWXlZekl4WlRCbU16Tm1NamhoTWpGalpqSTJaRE5oWlRrMk5ERTNaREJoWlRrM05ESTJNREExTnpVMU1UVTFNV0ZpTTJSak9EUTFabU0yWWc9PSJ9LCJraWQiOiJyMSJ9XSwibWV0aG9kIjp7ImFsZ29yaXRobSI6IkFFUy0yNTYtR0NNIiwiaXYiOiIiLCJpc1N0cmVhbWFibGUiOnRydWV9LCJpbnRlZ3JpdHlJbmZvcm1hdGlvbiI6eyJyb290U2lnbmF0dXJlIjp7ImFsZyI6IkhTMjU2Iiwic2lnIjoiWkdWaFltRmtNRGhsTURCbU1UVm1ZekJtTVdFME0ySmhOamhrTmpBMVpUazFNVGRtWmpoa1pETmtNekk0Tldaa01XUXhOVFZsWXpjME1EVXhPRE13Tmc9PSJ9LCJzZWdtZW50SGFzaEFsZyI6IkdNQUMiLCJzZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxNTIsImVuY3J5cHRlZFNlZ21lbnRTaXplRGVmYXVsdCI6MjA5NzE4MCwic2VnbWVudHMiOlt7Imhhc2giOiJNakkzWTJGbU9URXdNakV4TkdRNFpERTRZelkwWTJJeU4ySTFOemRqTXprPSIsInNlZ21lbnRTaXplIjo4LCJlbmNyeXB0ZWRTZWdtZW50U2l6ZSI6MzZ9XX19LCJwYXlsb2FkIjp7InR5cGUiOiJyZWZlcmVuY2UiLCJ1cmwiOiIwLnBheWxvYWQiLCJwcm90b2NvbCI6InppcCIsIm1pbWVUeXBlIjoiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiwiaXNFbmNyeXB0ZWQiOnRydWV9fVBLBwgwpFOlrwUAAK8FAABQSwECLQAtAAgAAACdkxUxaJjuySQAAAAkAAAACQAAAAAAAAAAAAAAAAAAAAAAMC5wYXlsb2FkUEsBAi0ALQAIAAAAnZMVMTCkU6WvBQAArwUAAA8AAAAAAAAAAAAAAAAAWwAAADAubWFuaWZlc3QuanNvblBLBQYAAAAAAgACAHQAAABHBgAAAAA="
	goodDecodedData, err := base64.StdEncoding.DecodeString(goodStandardTdf)
	require.NoError(t, err)

	in := bytes.NewReader(goodDecodedData)
	isValid, err := sdk.IsValidTdf(in)
	require.NoError(t, err)

	assert.True(t, isValid)
}

func TestNew_ShouldNotValidateBadStandardTdf(t *testing.T) {
	// This TDF is missing the "type" field in the key access object, making it invalid.
	badStandardTdf := "UEsDBC0ACAAAAJ2TFTEAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2Fktu4m+vdwl0mtjhY3U5e7TG2o1s8ifK+RAhFNjRjGTLJ7V3w5UEsHCGiY7skkAAAAJAAAAFBLAwQtAAgAAACdkxUxAAAAAAAAAAAAAAAADwAAADAubWFuaWZlc3QuanNvbnsiZW5jcnlwdGlvbkluZm9ybWF0aW9uIjp7InR5cGUiOiJzcGxpdCIsInBvbGljeSI6ImV5SjFkV2xrSWpvaU1HTTFORGsyWlRZdE5EYzRaaTB4TVdWbUxXSXlOakV0WWpJMVl6UmhORE14TjJFM0lpd2lZbTlrZVNJNmV5SmtZWFJoUVhSMGNtbGlkWFJsY3lJNlczc2lZWFIwY21saWRYUmxJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbU52YlM5aGRIUnlMMkYwZEhJeEwzWmhiSFZsTDNaaGJIVmxNU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lJaXdpYVhORVpXWmhkV3gwSWpwbVlXeHpaU3dpY0hWaVMyVjVJam9pSWl3aWEyRnpWVkpNSWpvaUluMWRMQ0prYVhOelpXMGlPbHRkZlgwPSIsImtleUFjY2VzcyI6W3sidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoidFVTL1BPU2lQbThlejhoci9nTFRjemNZTk9La3FDRHJWYkEwVnR2Z2tvUGxwdDNQQ2VaU3QzZ3Z5UDVWSmVwTTJjanVQYVFiSVBpcjI5VnVSdk9UV2ZkM0VIdSs4MlQrRTRFWWxKQTNuVWw3RkE0TFBmYVBLV1pNc0xMR1JCSVVMWU9FYTFiZmtTL1JvV29BMCtvN1pRRVZDYWJnSTdiRUQySldkNmhtcmptYlJzNndJcDlRVzVLOEN3SVo2VWY5RjFxMEQ1Yk5pa2xsR2grYmlSbFdTbnBMMWxwT2hXb2tYMXVCbFNFUUgzbzNibVVxUzVVWlI0ZmFMbk1ucThkdG0vMGJyY041MGhTYitMU05WZHdnWkxLM000R05sRHhnc3A5MWNFbmI2aGZLS3pnUmNFQktLTEExdW9wVzR3QkRvQWphbllqZUJWVU92QWRCOXpOOU93PT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6IlpqQXpNR1l5WXpJeFpUQm1Nek5tTWpoaE1qRmpaakkyWkROaFpUazJOREUzWkRCaFpUazNOREkyTURBMU56VTFNVFUxTVdGaU0yUmpPRFExWm1NMllnPT0ifSwia2lkIjoicjEifV0sIm1ldGhvZCI6eyJhbGdvcml0aG0iOiJBRVMtMjU2LUdDTSIsIml2IjoiIiwiaXNTdHJlYW1hYmxlIjp0cnVlfSwiaW50ZWdyaXR5SW5mb3JtYXRpb24iOnsicm9vdFNpZ25hdHVyZSI6eyJhbGciOiJIUzI1NiIsInNpZyI6IlpHVmhZbUZrTURobE1EQm1NVFZtWXpCbU1XRTBNMkpoTmpoa05qQTFaVGsxTVRkbVpqaGtaRE5rTXpJNE5XWmtNV1F4TlRWbFl6YzBNRFV4T0RNd05nPT0ifSwic2VnbWVudEhhc2hBbGciOiJHTUFDIiwic2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTUyLCJlbmNyeXB0ZWRTZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxODAsInNlZ21lbnRzIjpbeyJoYXNoIjoiTWpJM1kyRm1PVEV3TWpFeE5HUTRaREU0WXpZMFkySXlOMkkxTnpkak16az0iLCJzZWdtZW50U2l6ZSI6OCwiZW5jcnlwdGVkU2VnbWVudFNpemUiOjM2fV19fSwicGF5bG9hZCI6eyJ0eXBlIjoicmVmZXJlbmNlIiwidXJsIjoiMC5wYXlsb2FkIiwicHJvdG9jb2wiOiJ6aXAiLCJtaW1lVHlwZSI6ImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSIsImlzRW5jcnlwdGVkIjp0cnVlfX1QSwcIMKRTpa8FAACvBQAAUEsBAi0ALQAIAAAAnZMVMWiY7skkAAAAJAAAAAkAAAAAAAAAAAAAAAAAAAAAADAucGF5bG9hZFBLAQItAC0ACAAAAJ2TFTEwpFOlrwUAAK8FAAAPAAAAAAAAAAAAAAAAAFsAAAAwLm1hbmlmZXN0Lmpzb25QSwUGAAAAAAIAAgB0AAAARwYAAAAA"
	badDecodedData, err := base64.StdEncoding.DecodeString(badStandardTdf)
	in := bytes.NewReader(badDecodedData)

	require.NoError(t, err)
	// Decode the base64 string
	isValid, _ := sdk.IsValidTdf(in)
	// Error is ok here, as it acts as a sort of reason for the nanotdf not being valid
	assert.False(t, isValid)
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

func Test_ShouldSanitizePlatformEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected string
	}{
		{
			name:     "No scheme",
			endpoint: "localhost:8080",
			expected: "localhost:8080",
		},
		{
			name:     "HTTP scheme with port",
			endpoint: "http://localhost:8080",
			expected: "localhost:8080",
		},
		{
			name:     "HTTPS scheme with port",
			endpoint: "https://localhost:8080",
			expected: "localhost:8080",
		},
		{
			name:     "HTTP scheme no port",
			endpoint: "http://localhost",
			expected: "localhost:80",
		},
		{
			name:     "HTTPS scheme no port",
			endpoint: "https://localhost",
			expected: "localhost:443",
		},
		{
			name:     "Malformed url",
			endpoint: "http://localhost:8080:8080",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "http://localhost:8080:",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "http//localhost:8080:",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "//localhost",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "://localhost",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "http/localhost",
			expected: "",
		},
		{
			name:     "Malformed url",
			endpoint: "http:localhost",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := sdk.SanitizePlatformEndpoint(tt.endpoint)
			if tt.expected == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}
