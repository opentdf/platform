package sdk_test

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnect"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping/subjectmappingconnect"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	goodPlatformEndpoint = "http://localhost:8080"
	badPlatformEndpoint  = "http://localhost:9999"
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

	// check if the clients are available
	assert.NotNil(t, s.Attributes)
	assert.NotNil(t, s.ResourceMapping)
	assert.NotNil(t, s.SubjectMapping)
	assert.NotNil(t, s.KeyAccessServerRegistry)
}

func Test_PlatformConfiguration_BadCases(t *testing.T) {
	assertions := func(t *testing.T, s *sdk.SDK) {
		iss, err := s.PlatformConfiguration.Issuer()
		assert.Empty(t, iss)
		require.ErrorIs(t, err, sdk.ErrPlatformIssuerNotFound)

		authzEndpoint, err := s.PlatformConfiguration.AuthzEndpoint()
		assert.Empty(t, authzEndpoint)
		require.ErrorIs(t, err, sdk.ErrPlatformAuthzEndpointNotFound)

		tokenEndpoint, err := s.PlatformConfiguration.TokenEndpoint()
		assert.Empty(t, tokenEndpoint)
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

func TestNew_ShouldValidateStandardTdf(t *testing.T) {
	goodStandardTdf := "UEsDBC0ACAAAAJ2TFTEAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2Fktu4m+vdwl0mtjhY3U5e7TG2o1s8ifK+RAhFNjRjGTLJ7V3w5UEsHCGiY7skkAAAAJAAAAFBLAwQtAAgAAACdkxUxAAAAAAAAAAAAAAAADwAAADAubWFuaWZlc3QuanNvbnsiZW5jcnlwdGlvbkluZm9ybWF0aW9uIjp7InR5cGUiOiJzcGxpdCIsInBvbGljeSI6ImV5SjFkV2xrSWpvaU1HTTFORGsyWlRZdE5EYzRaaTB4TVdWbUxXSXlOakV0WWpJMVl6UmhORE14TjJFM0lpd2lZbTlrZVNJNmV5SmtZWFJoUVhSMGNtbGlkWFJsY3lJNlczc2lZWFIwY21saWRYUmxJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbU52YlM5aGRIUnlMMkYwZEhJeEwzWmhiSFZsTDNaaGJIVmxNU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lJaXdpYVhORVpXWmhkV3gwSWpwbVlXeHpaU3dpY0hWaVMyVjVJam9pSWl3aWEyRnpWVkpNSWpvaUluMWRMQ0prYVhOelpXMGlPbHRkZlgwPSIsImtleUFjY2VzcyI6W3sidHlwZSI6IndyYXBwZWQiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJwcm90b2NvbCI6ImthcyIsIndyYXBwZWRLZXkiOiJ0VVMvUE9TaVBtOGV6OGhyL2dMVGN6Y1lOT0trcUNEclZiQTBWdHZna29QbHB0M1BDZVpTdDNndnlQNVZKZXBNMmNqdVBhUWJJUGlyMjlWdVJ2T1RXZmQzRUh1KzgyVCtFNEVZbEpBM25VbDdGQTRMUGZhUEtXWk1zTExHUkJJVUxZT0VhMWJma1MvUm9Xb0EwK283WlFFVkNhYmdJN2JFRDJKV2Q2aG1yam1iUnM2d0lwOVFXNUs4Q3dJWjZVZjlGMXEwRDViTmlrbGxHaCtiaVJsV1NucEwxbHBPaFdva1gxdUJsU0VRSDNvM2JtVXFTNVVaUjRmYUxuTW5xOGR0bS8wYnJjTjUwaFNiK0xTTlZkd2daTEszTTRHTmxEeGdzcDkxY0VuYjZoZktLemdSY0VCS0tMQTF1b3BXNHdCRG9BamFuWWplQlZVT3ZBZEI5ek45T3c9PSIsInBvbGljeUJpbmRpbmciOnsiYWxnIjoiSFMyNTYiLCJoYXNoIjoiWmpBek1HWXlZekl4WlRCbU16Tm1NamhoTWpGalpqSTJaRE5oWlRrMk5ERTNaREJoWlRrM05ESTJNREExTnpVMU1UVTFNV0ZpTTJSak9EUTFabU0yWWc9PSJ9LCJraWQiOiJyMSJ9XSwibWV0aG9kIjp7ImFsZ29yaXRobSI6IkFFUy0yNTYtR0NNIiwiaXYiOiIiLCJpc1N0cmVhbWFibGUiOnRydWV9LCJpbnRlZ3JpdHlJbmZvcm1hdGlvbiI6eyJyb290U2lnbmF0dXJlIjp7ImFsZyI6IkhTMjU2Iiwic2lnIjoiWkdWaFltRmtNRGhsTURCbU1UVm1ZekJtTVdFME0ySmhOamhrTmpBMVpUazFNVGRtWmpoa1pETmtNekk0Tldaa01XUXhOVFZsWXpjME1EVXhPRE13Tmc9PSJ9LCJzZWdtZW50SGFzaEFsZyI6IkdNQUMiLCJzZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxNTIsImVuY3J5cHRlZFNlZ21lbnRTaXplRGVmYXVsdCI6MjA5NzE4MCwic2VnbWVudHMiOlt7Imhhc2giOiJNakkzWTJGbU9URXdNakV4TkdRNFpERTRZelkwWTJJeU4ySTFOemRqTXprPSIsInNlZ21lbnRTaXplIjo4LCJlbmNyeXB0ZWRTZWdtZW50U2l6ZSI6MzZ9XX19LCJwYXlsb2FkIjp7InR5cGUiOiJyZWZlcmVuY2UiLCJ1cmwiOiIwLnBheWxvYWQiLCJwcm90b2NvbCI6InppcCIsIm1pbWVUeXBlIjoiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiwiaXNFbmNyeXB0ZWQiOnRydWV9fVBLBwgwpFOlrwUAAK8FAABQSwECLQAtAAgAAACdkxUxaJjuySQAAAAkAAAACQAAAAAAAAAAAAAAAAAAAAAAMC5wYXlsb2FkUEsBAi0ALQAIAAAAnZMVMTCkU6WvBQAArwUAAA8AAAAAAAAAAAAAAAAAWwAAADAubWFuaWZlc3QuanNvblBLBQYAAAAAAgACAHQAAABHBgAAAAA="
	goodDecodedData, err := base64.StdEncoding.DecodeString(goodStandardTdf)
	require.NoError(t, err)

	in := bytes.NewReader(goodDecodedData)
	isValid, err := sdk.IsValidTdf(in)
	require.NoError(t, err)

	assert.True(t, isValid)

	// Try again to see if the reader has been reset
	isValid, err = sdk.IsValidTdf(in)
	require.NoError(t, err)

	assert.True(t, isValid)
}

func TestNew_ShouldNotValidateBadStandardTdf(t *testing.T) {
	// This zip file is invalid, with a bad central directory header.
	badStandardTdf := "UEsDBC0ACAAAAJ2TFTEAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2Fktu4m+vdwl0mtjhY3U5e7TG2o1s8ifK+RAhFNjRjGTLJ7V3w5UEsHCGiY7skkAAAAJAAAAFBLAwQtAAgAAACdkxUxAAAAAAAAAAAAAAAADwAAADAubWFuaWZlc3QuanNvbnsiZW5jcnlwdGlvbkluZm9ybWF0aW9uIjp7InR5cGUiOiJzcGxpdCIsInBvbGljeSI6ImV5SjFkV2xrSWpvaU1HTTFORGsyWlRZdE5EYzRaaTB4TVdWbUxXSXlOakV0WWpJMVl6UmhORE14TjJFM0lpd2lZbTlrZVNJNmV5SmtZWFJoUVhSMGNtbGlkWFJsY3lJNlczc2lZWFIwY21saWRYUmxJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbU52YlM5aGRIUnlMMkYwZEhJeEwzWmhiSFZsTDNaaGJIVmxNU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lJaXdpYVhORVpXWmhkV3gwSWpwbVlXeHpaU3dpY0hWaVMyVjVJam9pSWl3aWEyRnpWVkpNSWpvaUluMWRMQ0prYVhOelpXMGlPbHRkZlgwPSIsImtleUFjY2VzcyI6W3sidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoidFVTL1BPU2lQbThlejhoci9nTFRjemNZTk9La3FDRHJWYkEwVnR2Z2tvUGxwdDNQQ2VaU3QzZ3Z5UDVWSmVwTTJjanVQYVFiSVBpcjI5VnVSdk9UV2ZkM0VIdSs4MlQrRTRFWWxKQTNuVWw3RkE0TFBmYVBLV1pNc0xMR1JCSVVMWU9FYTFiZmtTL1JvV29BMCtvN1pRRVZDYWJnSTdiRUQySldkNmhtcmptYlJzNndJcDlRVzVLOEN3SVo2VWY5RjFxMEQ1Yk5pa2xsR2grYmlSbFdTbnBMMWxwT2hXb2tYMXVCbFNFUUgzbzNibVVxUzVVWlI0ZmFMbk1ucThkdG0vMGJyY041MGhTYitMU05WZHdnWkxLM000R05sRHhnc3A5MWNFbmI2aGZLS3pnUmNFQktLTEExdW9wVzR3QkRvQWphbllqZUJWVU92QWRCOXpOOU93PT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6IlpqQXpNR1l5WXpJeFpUQm1Nek5tTWpoaE1qRmpaakkyWkROaFpUazJOREUzWkRCaFpUazNOREkyTURBMU56VTFNVFUxTVdGaU0yUmpPRFExWm1NMllnPT0ifSwia2lkIjoicjEifV0sIm1ldGhvZCI6eyJhbGdvcml0aG0iOiJBRVMtMjU2LUdDTSIsIml2IjoiIiwiaXNTdHJlYW1hYmxlIjp0cnVlfSwiaW50ZWdyaXR5SW5mb3JtYXRpb24iOnsicm9vdFNpZ25hdHVyZSI6eyJhbGciOiJIUzI1NiIsInNpZyI6IlpHVmhZbUZrTURobE1EQm1NVFZtWXpCbU1XRTBNMkpoTmpoa05qQTFaVGsxTVRkbVpqaGtaRE5rTXpJNE5XWmtNV1F4TlRWbFl6YzBNRFV4T0RNd05nPT0ifSwic2VnbWVudEhhc2hBbGciOiJHTUFDIiwic2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTUyLCJlbmNyeXB0ZWRTZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxODAsInNlZ21lbnRzIjpbeyJoYXNoIjoiTWpJM1kyRm1PVEV3TWpFeE5HUTRaREU0WXpZMFkySXlOMkkxTnpkak16az0iLCJzZWdtZW50U2l6ZSI6OCwiZW5jcnlwdGVkU2VnbWVudFNpemUiOjM2fV19fSwicGF5bG9hZCI6eyJ0eXBlIjoicmVmZXJlbmNlIiwidXJsIjoiMC5wYXlsb2FkIiwicHJvdG9jb2wiOiJ6aXAiLCJtaW1lVHlwZSI6ImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSIsImlzRW5jcnlwdGVkIjp0cnVlfX1QSwcIMKRTpa8FAACvBQAAUEsBAi0ALQAIAAAAnZMVMWiY7skkAAAAJAAAAAkAAAAAAAAAAAAAAAAAAAAAADAucGF5bG9hZFBLAQItAC0ACAAAAJ2TFTEwpFOlrwUAAK8FAAAPAAAAAAAAAAAAAAAAAFsAAAAwLm1hbmlmZXN0Lmpzb25QSwUGAAAAAAIAAgB0AAAARwYAAAAA"
	badDecodedData, err := base64.StdEncoding.DecodeString(badStandardTdf)
	in := bytes.NewReader(badDecodedData)

	require.NoError(t, err)
	// Decode the base64 string
	isValid, err := sdk.IsValidTdf(in)
	// Error is ok here; it documents why the input is invalid.
	assert.False(t, isValid)
	require.Error(t, err)
}

func TestIsInvalid_MissingRequiredManifestPayloadField(t *testing.T) {
	// This is a valid ZTDF, but missing the manifest.payload.type entry.
	badStandardTdf := "UEsDBC0ACAAAAN2oTzIAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2FkD/U+BGl0DU+fwM4j8f6FgpXSaKlOvzGgSK/AnAzDUiID+S97s7fGqV7ajuc9uFBLBwgYUH8dLgAAAC4AAABQSwMELQAIAAAA3ahPMgAAAAAAAAAAAAAAAA8AAAAwLm1hbmlmZXN0Lmpzb257ImVuY3J5cHRpb25JbmZvcm1hdGlvbiI6eyJ0eXBlIjoic3BsaXQiLCJwb2xpY3kiOiJleUoxZFdsa0lqb2lPRFpqTW1ZNU16SXRaRE00TkMweE1XVm1MV0V3Tm1JdFpXRmtNR1F3TjJJeFpHUm1JaXdpWW05a2VTSTZleUprWVhSaFFYUjBjbWxpZFhSbGN5STZXM3NpWVhSMGNtbGlkWFJsSWpvaWFIUjBjSE02THk5bGVHRnRjR3hsTG1OdmJTOWhkSFJ5TDJGMGRISXhMM1poYkhWbEwzWmhiSFZsTVNJc0ltUnBjM0JzWVhsT1lXMWxJam9pSWl3aWFYTkVaV1poZFd4MElqcG1ZV3h6WlN3aWNIVmlTMlY1SWpvaUlpd2lhMkZ6VlZKTUlqb2lJbjFkTENKa2FYTnpaVzBpT2x0ZGZYMD0iLCJrZXlBY2Nlc3MiOlt7InR5cGUiOiJ3cmFwcGVkIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwicHJvdG9jb2wiOiJrYXMiLCJ3cmFwcGVkS2V5IjoiazR4ci9UZkpMbGpkOUM4VXR5Q3pQaG5JUkRBek9RUzA0bTZreDVlUmh1VEtmZkErNEIxajJIWjBTUDRwb2tRSGo2bDAycU1aalBkVEd4eDRnNm5wemN2QkdoeFhyQyt4Q3dCTHcrWjViTVI4VG1uOVpsOUhrUmJWUXNpb01QbWk2NURaY0RwOHZPTUxob0ZrblA4WlNsQ3ZuNHBXMWN2eEpGN3N5MGpvNDBlZDhhUVp6RnU1b0J4alpCbDhUcnpSZ1NGK3VwTGp1cEdKUHF0VVpmd0FQZ3JGTFdRMmFXQ0laQ2VkTDlCSXozTFhRS3lGU1VEUmZiTyszT3dPZHV6aWpNbVUrWnJPSGFkNXRqRklxS0swZHlRMkFDR3RoajNIUEJDUGc0UDJoZ0tGeEgzQWUrMTVFVnV5QWpGOVk4NDlDU2Q4NGJMS0NzTjZ4Mjl0L2dpVGJnPT0iLCJwb2xpY3lCaW5kaW5nIjp7ImFsZyI6IkhTMjU2IiwiaGFzaCI6Ik1UWTFZelExTjJRNU5qRTVPREprWXpjM056QTRaVFZpWlRWaE56QTNNMlpoWldNNU16azVaR1U1WmpVd1kySmhNakJsTVRBeE5HWmhaRGhrWlRFMk5RPT0ifSwia2lkIjoicjEifV0sIm1ldGhvZCI6eyJhbGdvcml0aG0iOiJBRVMtMjU2LUdDTSIsIml2IjoiIiwiaXNTdHJlYW1hYmxlIjp0cnVlfSwiaW50ZWdyaXR5SW5mb3JtYXRpb24iOnsicm9vdFNpZ25hdHVyZSI6eyJhbGciOiJIUzI1NiIsInNpZyI6Ik1ESTNaREUyTmpBek1qUXhOMkUxWlRRNU1qVTFPREF5WW1abE5UQmtaak5rTWpBeU1qa3pNbUkwTUdRd01EWTNNakkzTm1VeFptTmhPRGd4TlRVellnPT0ifSwic2VnbWVudEhhc2hBbGciOiJHTUFDIiwic2VnbWVudFNpemVEZWZhdWx0IjoyMDk3MTUyLCJlbmNyeXB0ZWRTZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxODAsInNlZ21lbnRzIjpbeyJoYXNoIjoiTlRJeU1qQXpaamt5WmpkaVlqTmlOMk0yWVRrMVpXUmhPR1ZsTnpOa1lqZz0iLCJzZWdtZW50U2l6ZSI6MTgsImVuY3J5cHRlZFNlZ21lbnRTaXplIjo0Nn1dfX0sInBheWxvYWQiOnsidXJsIjoiMC5wYXlsb2FkIiwicHJvdG9jb2wiOiJ6aXAiLCJtaW1lVHlwZSI6ImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSIsImlzRW5jcnlwdGVkIjp0cnVlfX1QSwcI2lLjxJ0FAACdBQAAUEsBAi0ALQAIAAAA3ahPMhhQfx0uAAAALgAAAAkAAAAAAAAAAAAAAAAAAAAAADAucGF5bG9hZFBLAQItAC0ACAAAAN2oTzLaUuPEnQUAAJ0FAAAPAAAAAAAAAAAAAAAAAGUAAAAwLm1hbmlmZXN0Lmpzb25QSwUGAAAAAAIAAgB0AAAAPwYAAAAA"
	badDecodedData, err := base64.StdEncoding.DecodeString(badStandardTdf)
	in := bytes.NewReader(badDecodedData)

	require.NoError(t, err)
	// Decode the base64 string
	isValid, err := sdk.IsValidTdf(in)
	// Error is ok here; it documents why the input is invalid.
	assert.False(t, isValid)
	require.ErrorIs(t, err, sdk.ErrInvalidPerSchema)
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
			expected: GetMethods(reflect.TypeOf(attributesconnect.NewAttributesServiceClient(s.Conn().Client, s.Conn().Endpoint))),
			actual:   GetMethods(reflect.TypeOf(s.Attributes)),
		},
		{
			name:     "ResourceEncoding",
			expected: GetMethods(reflect.TypeOf(resourcemappingconnect.NewResourceMappingServiceClient(s.Conn().Client, s.Conn().Endpoint))),
			actual:   GetMethods(reflect.TypeOf(s.ResourceMapping)),
		},
		{
			name:     "SubjectEncoding",
			expected: GetMethods(reflect.TypeOf(subjectmappingconnect.NewSubjectMappingServiceClient(s.Conn().Client, s.Conn().Endpoint))),
			actual:   GetMethods(reflect.TypeOf(s.SubjectMapping)),
		},
		{
			name:     "KeyAccessGrants",
			expected: GetMethods(reflect.TypeOf(kasregistryconnect.NewKeyAccessServerRegistryServiceClient(s.Conn().Client, s.Conn().Endpoint))),
			actual:   GetMethods(reflect.TypeOf(s.KeyAccessServerRegistry)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.actual)
		})
	}
}

func Test_New_ShouldFailWithDisconnectedPlatform(t *testing.T) {
	s, err := sdk.New(badPlatformEndpoint,
		sdk.WithConnectionValidation(),
	)
	require.ErrorIs(t, err, sdk.ErrPlatformUnreachable)
	assert.Nil(t, s)

	// validates even with platform configuration provided
	s, err = sdk.New(badPlatformEndpoint,
		sdk.WithPlatformConfiguration(sdk.PlatformConfiguration{
			"platform_issuer": "https://example.org",
		}),
		sdk.WithConnectionValidation(),
	)
	require.ErrorIs(t, err, sdk.ErrPlatformUnreachable)
	assert.Nil(t, s)
}

func TestIsPlatformEndpointMalformed(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    bool
		description string
	}{
		{
			name:        "Valid URL with scheme and host",
			input:       "https://example.com",
			expected:    false,
			description: "A valid URL with scheme and host should not be considered malformed.",
		},
		{
			name:        "Valid URL with scheme, host, and port",
			input:       "https://example.com:8080",
			expected:    false,
			description: "A valid URL with scheme, host, and port should not be considered malformed.",
		},
		{
			name:        "Valid URL with path",
			input:       "https://example.com/path",
			expected:    false,
			description: "A valid URL with a path should not be considered malformed.",
		},
		{
			name:        "Invalid URL with missing host",
			input:       "https://:8080",
			expected:    true,
			description: "A URL with a missing host should be considered malformed.",
		},
		{
			name:        "Invalid URL with missing scheme",
			input:       "example.com",
			expected:    true,
			description: "A URL without a scheme should be considered malformed.",
		},
		{
			name:        "Invalid URL with invalid characters",
			input:       "https://exa mple.com",
			expected:    true,
			description: "A URL with invalid characters should be considered malformed.",
		},
		{
			name:        "Invalid URL with colon in hostname",
			input:       "https://example:com",
			expected:    true,
			description: "A URL with a colon in the hostname should be considered malformed.",
		},
		{
			name:        "Empty input",
			input:       "",
			expected:    true,
			description: "An empty input should be considered malformed.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sdk.IsPlatformEndpointMalformed(tt.input)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func Test_GetType_TDF(t *testing.T) {
	tdf := "UEsDBC0ACAAAAJ2TFTEAAAAAAAAAAAAAAAAJAAAAMC5wYXlsb2Fktu4m+vdwl0mtjhY3U5e7TG2o1s8ifK+RAhFNjRjGTLJ7V3w5UEsHCGiY7skkAAAAJAAAAFBLAwQtAAgAAACdkxUxAAAAAAAAAAAAAAAADwAAADAubWFuaWZlc3QuanNvbnsiZW5jcnlwdGlvbkluZm9ybWF0aW9uIjp7InR5cGUiOiJzcGxpdCIsInBvbGljeSI6ImV5SjFkV2xrSWpvaU1HTTFORGsyWlRZdE5EYzRaaTB4TVdWbUxXSXlOakV0WWpJMVl6UmhORE14TjJFM0lpd2lZbTlrZVNJNmV5SmtZWFJoUVhSMGNtbGlkWFJsY3lJNlczc2lZWFIwY21saWRYUmxJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbU52YlM5aGRIUnlMMkYwZEhJeEwzWmhiSFZsTDNaaGJIVmxNU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lJaXdpYVhORVpXWmhkV3gwSWpwbVlXeHpaU3dpY0hWaVMyVjVJam9pSWl3aWEyRnpWVkpNSWpvaUluMWRMQ0prYVhOelpXMGlPbHRkZlgwPSIsImtleUFjY2VzcyI6W3sidHlwZSI6IndyYXBwZWQiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJwcm90b2NvbCI6ImthcyIsIndyYXBwZWRLZXkiOiJ0VVMvUE9TaVBtOGV6OGhyL2dMVGN6Y1lOT0trcUNEclZiQTBWdHZna29QbHB0M1BDZVpTdDNndnlQNVZKZXBNMmNqdVBhUWJJUGlyMjlWdVJ2T1RXZmQzRUh1KzgyVCtFNEVZbEpBM25VbDdGQTRMUGZhUEtXWk1zTExHUkJJVUxZT0VhMWJma1MvUm9Xb0EwK283WlFFVkNhYmdJN2JFRDJKV2Q2aG1yam1iUnM2d0lwOVFXNUs4Q3dJWjZVZjlGMXEwRDViTmlrbGxHaCtiaVJsV1NucEwxbHBPaFdva1gxdUJsU0VRSDNvM2JtVXFTNVVaUjRmYUxuTW5xOGR0bS8wYnJjTjUwaFNiK0xTTlZkd2daTEszTTRHTmxEeGdzcDkxY0VuYjZoZktLemdSY0VCS0tMQTF1b3BXNHdCRG9BamFuWWplQlZVT3ZBZEI5ek45T3c9PSIsInBvbGljeUJpbmRpbmciOnsiYWxnIjoiSFMyNTYiLCJoYXNoIjoiWmpBek1HWXlZekl4WlRCbU16Tm1NamhoTWpGalpqSTJaRE5oWlRrMk5ERTNaREJoWlRrM05ESTJNREExTnpVMU1UVTFNV0ZpTTJSak9EUTFabU0yWWc9PSJ9LCJraWQiOiJyMSJ9XSwibWV0aG9kIjp7ImFsZ29yaXRobSI6IkFFUy0yNTYtR0NNIiwiaXYiOiIiLCJpc1N0cmVhbWFibGUiOnRydWV9LCJpbnRlZ3JpdHlJbmZvcm1hdGlvbiI6eyJyb290U2lnbmF0dXJlIjp7ImFsZyI6IkhTMjU2Iiwic2lnIjoiWkdWaFltRmtNRGhsTURCbU1UVm1ZekJtTVdFME0ySmhOamhrTmpBMVpUazFNVGRtWmpoa1pETmtNekk0Tldaa01XUXhOVFZsWXpjME1EVXhPRE13Tmc9PSJ9LCJzZWdtZW50SGFzaEFsZyI6IkdNQUMiLCJzZWdtZW50U2l6ZURlZmF1bHQiOjIwOTcxNTIsImVuY3J5cHRlZFNlZ21lbnRTaXplRGVmYXVsdCI6MjA5NzE4MCwic2VnbWVudHMiOlt7Imhhc2giOiJNakkzWTJGbU9URXdNakV4TkdRNFpERTRZelkwWTJJeU4ySTFOemRqTXprPSIsInNlZ21lbnRTaXplIjo4LCJlbmNyeXB0ZWRTZWdtZW50U2l6ZSI6MzZ9XX19LCJwYXlsb2FkIjp7InR5cGUiOiJyZWZlcmVuY2UiLCJ1cmwiOiIwLnBheWxvYWQiLCJwcm90b2NvbCI6InppcCIsIm1pbWVUeXBlIjoiYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiwiaXNFbmNyeXB0ZWQiOnRydWV9fVBLBwgwpFOlrwUAAK8FAABQSwECLQAtAAgAAACdkxUxaJjuySQAAAAkAAAACQAAAAAAAAAAAAAAAAAAAAAAMC5wYXlsb2FkUEsBAi0ALQAIAAAAnZMVMTCkU6WvBQAArwUAAA8AAAAAAAAAAAAAAAAAWwAAADAubWFuaWZlc3QuanNvblBLBQYAAAAAAgACAHQAAABHBgAAAAA="
	tdfDecoded, err := base64.StdEncoding.DecodeString(tdf)
	require.NoError(t, err)

	in := bytes.NewReader(tdfDecoded)
	tdfType := sdk.GetTdfType(in)

	assert.Equal(t, sdk.Standard, tdfType)
}

func Test_GetType_InvalidTDF(t *testing.T) {
	tdf := ""
	in := bytes.NewReader([]byte(tdf))

	tdfType := sdk.GetTdfType(in)

	assert.Equal(t, sdk.Invalid, tdfType)
}

func Test_GetType_Invalid2Bytes(t *testing.T) {
	tdf := "UE"
	in := bytes.NewReader([]byte(tdf))

	tdfType := sdk.GetTdfType(in)

	assert.Equal(t, sdk.Invalid, tdfType)
}
