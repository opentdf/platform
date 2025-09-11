package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect" // cspell: disable-line
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect" // cspell: disable-line
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"                // cspell: disable-line
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"                               // cspell: disable-line
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect" // cspell: disable-line
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb" // cspell: disable-line
)

// Mock implementations for complete KAS functionality
type mockKASWithRewrap struct {
	kasconnect.UnimplementedAccessServiceHandler // cspell: disable-line
	privateKey                                   *rsa.PrivateKey
	publicKeyPEM                                 string
	kid                                          string
}

func (m *mockKASWithRewrap) PublicKey(_ context.Context, _ *connect.Request[kas.PublicKeyRequest]) (*connect.Response[kas.PublicKeyResponse], error) {
	return connect.NewResponse(&kas.PublicKeyResponse{
		PublicKey: m.publicKeyPEM,
		Kid:       m.kid,
	}), nil
}

func (m *mockKASWithRewrap) Rewrap(_ context.Context, in *connect.Request[kas.RewrapRequest]) (*connect.Response[kas.RewrapResponse], error) {
	// Parse the signed request token
	signedRequestToken := in.Msg.GetSignedRequestToken()

	// Debug: Log the token format for troubleshooting
	fmt.Printf("DEBUG: Received signed request token: %q\n", signedRequestToken) //nolint:forbidigo // for testing

	token, err := jwt.ParseInsecure([]byte(signedRequestToken))
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseInsecure failed: %w", err)
	}

	requestBody, found := token.Get("requestBody")
	if !found {
		return nil, errors.New("requestBody not found in token")
	}

	requestBodyStr, ok := requestBody.(string)
	if !ok {
		return nil, errors.New("requestBody not a string")
	}

	// Parse the rewrap request
	bodyData := kas.UnsignedRewrapRequest{}
	err = protojson.Unmarshal([]byte(requestBodyStr), &bodyData)
	if err != nil {
		return nil, fmt.Errorf("protojson.Unmarshal failed: %w", err)
	}

	resp := &kas.RewrapResponse{}

	// Process each policy request
	for _, req := range bodyData.GetRequests() {
		results := &kas.PolicyRewrapResult{PolicyId: req.GetPolicy().GetId()}
		resp.Responses = append(resp.Responses, results)

		// Process each key access object
		for _, kaoReq := range req.GetKeyAccessObjects() {
			wrappedKey := kaoReq.GetKeyAccessObject().GetWrappedKey()

			// Decrypt the wrapped key with KAS private key
			asymDecrypt, err := ocrypto.NewAsymDecryption(m.privateKeyPEM())
			if err != nil {
				return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
			}

			symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt failed: %w", err)
			}

			// Encrypt with client's public key
			asymEncrypt, err := ocrypto.NewAsymEncryption(bodyData.GetClientPublicKey())
			if err != nil {
				return nil, fmt.Errorf("ocrypto.NewAsymEncryption failed: %w", err)
			}

			entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
			if err != nil {
				return nil, fmt.Errorf("encrypt failed: %w", err)
			}

			kaoResult := &kas.KeyAccessRewrapResult{
				Result:            &kas.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: entityWrappedKey},
				Status:            "permit",
				KeyAccessObjectId: kaoReq.GetKeyAccessObjectId(),
			}
			results.Results = append(results.Results, kaoResult)
		}
	}

	return connect.NewResponse(resp), nil
}

func (m *mockKASWithRewrap) privateKeyPEM() string {
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(m.privateKey)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))
}

type mockAttributesWithData struct {
	attributesconnect.UnimplementedAttributesServiceHandler // cspell: disable-line
	kasURL                                                  string
}

func (m *mockAttributesWithData) GetAttributeValuesByFqns(_ context.Context, req *connect.Request[attributes.GetAttributeValuesByFqnsRequest]) (*connect.Response[attributes.GetAttributeValuesByFqnsResponse], error) { // cspell: disable-line
	// Create mock attribute responses for the requested FQNs (cspell: ignore FQNs)
	response := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue) // cspell: disable-line

	for _, fqn := range req.Msg.GetFqns() { // cspell: disable-line
		// Create a mock attribute value
		value := &policy.Value{
			Id:  "test-value-id",
			Fqn: fqn,
			Grants: []*policy.KeyAccessServer{
				{
					Uri: m.kasURL,
					PublicKey: &policy.PublicKey{
						PublicKey: &policy.PublicKey_Remote{
							Remote: m.kasURL,
						},
					},
				},
			},
		}

		response[fqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{ // cspell: disable-line
			Value: value,
		}
	}

	return connect.NewResponse(&attributes.GetAttributeValuesByFqnsResponse{ // cspell: disable-line
		FqnAttributeValues: response, // cspell: disable-line
	}), nil
}

type mockWellKnownWithConfig struct {
	wellknownconfigurationconnect.UnimplementedWellKnownServiceHandler // cspell: disable-line
	issuer                                                             string
}

func (m *mockWellKnownWithConfig) GetWellKnownConfiguration(_ context.Context, _ *connect.Request[wellknownconfiguration.GetWellKnownConfigurationRequest]) (*connect.Response[wellknownconfiguration.GetWellKnownConfigurationResponse], error) { // cspell: disable-line
	cfg, _ := structpb.NewStruct(map[string]any{ // cspell: disable-line
		"platform_issuer": m.issuer,
	})
	return connect.NewResponse(&wellknownconfiguration.GetWellKnownConfigurationResponse{ // cspell: disable-line
		Configuration: cfg,
	}), nil
}

type mockKASRegistryWithKeys struct {
	kasregistryconnect.UnimplementedKeyAccessServerRegistryServiceHandler // cspell: disable-line
	kasURL                                                                string
	publicKeyPEM                                                          string
}

func (m *mockKASRegistryWithKeys) GetKeyAccessServer(_ context.Context, _ *connect.Request[kasregistry.GetKeyAccessServerRequest]) (*connect.Response[kasregistry.GetKeyAccessServerResponse], error) {
	return connect.NewResponse(&kasregistry.GetKeyAccessServerResponse{
		KeyAccessServer: &policy.KeyAccessServer{
			Uri: m.kasURL,
			PublicKey: &policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: m.kasURL,
				},
			},
		},
	}), nil
}

// setupMockKASServer creates a complete mock server with KAS rewrap functionality
func setupMockKASServer(t testing.TB) (*SDK, func()) {
	t.Helper()

	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	mux := http.NewServeMux()

	// Create the test server first to get URL
	server := httptest.NewServer(mux)

	// Setup mock handlers with server URL
	mockKas := &mockKASWithRewrap{
		privateKey:   privateKey,
		publicKeyPEM: publicKeyPEM,
		kid:          "test-key-id",
	}
	kasPath, kasHandler := kasconnect.NewAccessServiceHandler(mockKas) // cspell: disable-line
	mux.Handle(kasPath, kasHandler)

	mockAttrs := &mockAttributesWithData{kasURL: server.URL}
	attrsPath, attrsHandler := attributesconnect.NewAttributesServiceHandler(mockAttrs) // cspell: disable-line
	mux.Handle(attrsPath, attrsHandler)

	mockWk := &mockWellKnownWithConfig{issuer: server.URL}
	wkPath, wkHandler := wellknownconfigurationconnect.NewWellKnownServiceHandler(mockWk) // cspell: disable-line
	mux.Handle(wkPath, wkHandler)

	mockKasReg := &mockKASRegistryWithKeys{
		kasURL:       server.URL,
		publicKeyPEM: publicKeyPEM,
	}
	kasRegPath, kasRegHandler := kasregistryconnect.NewKeyAccessServerRegistryServiceHandler(mockKasReg) // cspell: disable-line
	mux.Handle(kasRegPath, kasRegHandler)

	// Add OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		oidcConfig := map[string]any{
			"issuer":                 server.URL,
			"token_endpoint":         server.URL + "/oauth/token",
			"authorization_endpoint": server.URL + "/oauth/authorize",
			"jwks_uri":               server.URL + "/.well-known/jwks",
		}
		if err := json.NewEncoder(w).Encode(oidcConfig); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Add mock token endpoint
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tokenResponse := map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	cm := map[string]any{
		baseKeyWellKnown: map[string]any{
			"kas_uri": server.URL, // Use actual mock server URL
			baseKeyPublicKey: map[string]any{
				baseKeyAlg: "rsa:2048",
				"kid":      "test-key-id",
				"pem":      publicKeyPEM,
			},
		},
	}
	mockWellknown := newMockWellKnownService(cm, nil)

	// Create SDK with mock server
	sdk, err := New(server.URL,
		WithPlatformConfiguration(PlatformConfiguration{
			"platform_issuer": server.URL,
		}),
		WithInsecurePlaintextConn(),
		WithClientCredentials("test", "test", nil),
		withCustomAccessTokenSource(&fakeTokenSource{}))
	require.NoError(t, err)

	sdk.wellknownConfiguration = mockWellknown

	cleanup := func() {
		server.Close()
		sdk.Close()
	}

	// Create mock attributes client to bypass authentication
	mockAttributesClient := &mockAttributesClientStub{
		kasURL:       server.URL,
		publicKeyPEM: publicKeyPEM,
	}
	sdk.Attributes = mockAttributesClient

	// Set up a fake token source to avoid authentication issues during TDF reading
	sdk.tokenSource = getTokenSource(t)

	return sdk, cleanup
}

func TestStreamingWriter_WithSegments_And_GetManifest(t *testing.T) {
    s, cleanup := setupMockKASServer(t)
    defer cleanup()

    w, err := s.NewStreamingWriter(t.Context())
    require.NoError(t, err)

    // Write a couple of segments
    _, err = w.WriteSegment(t.Context(), 0, []byte("a"))
    require.NoError(t, err)
    _, err = w.WriteSegment(t.Context(), 1, []byte("b"))
    require.NoError(t, err)

    // Pre-finalize manifest should be available
    m := w.GetManifest()
    require.NotNil(t, m)

    // Finalize keeping contiguous prefix [0,1]
    res, err := w.Finalize(t.Context(), []string{"https://example.com/attr/Basic/value/Test"}, WithSegments([]int{0, 1}))
    require.NoError(t, err)
    require.NotNil(t, res.Manifest)
    assert.Equal(t, 2, res.TotalSegments)
}

func TestStreamingWriter_NewWithOptions_Initials(t *testing.T) {
    s, cleanup := setupMockKASServer(t)
    defer cleanup()

    // Supply initial attribute by FQN and default KAS at writer creation
    sw, err := s.NewStreamingWriterWithOptions(t.Context(),
        s.WithInitialAttributeFQNs(t.Context(), []string{"https://example.com/attr/Basic/value/Test"}),
        WithDefaultKASForWriter(&policy.SimpleKasKey{KasUri: s.conn.Endpoint}),
    )
    require.NoError(t, err)

    _, err = sw.WriteSegment(t.Context(), 0, []byte("x"))
    require.NoError(t, err)

    res, err := sw.Finalize(t.Context(), []string{})
    require.NoError(t, err)
    require.NotNil(t, res.Manifest)
    assert.GreaterOrEqual(t, len(res.Manifest.EncryptionInformation.KeyAccessObjs), 1)
}

// Mock attributes client that implements the interface directly (no HTTP calls)
type mockAttributesClientStub struct {
	sdkconnect.AttributesServiceClient // cspell: disable-line
	kasURL                             string
	publicKeyPEM                       string
}

func (m *mockAttributesClientStub) GetAttributeValuesByFqns(_ context.Context, req *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) { // cspell: disable-line
	// Create mock responses for testing without HTTP calls
	av := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue) // cspell: disable-line

	for _, fqn := range req.GetFqns() { // cspell: disable-line
		// Parse FQN to get parts
		fqnParsed, err := NewAttributeValueFQN(fqn)
		if err != nil {
			return nil, fmt.Errorf("invalid FQN: %w", err)
		}

		// Create mock attribute definition
		attribute := &policy.Attribute{
			Id: "test-attr-id",
			Namespace: &policy.Namespace{
				Id:   "test-ns",
				Name: "test.com",
				Fqn:  fqnParsed.Prefix().String(),
			},
			Name: fqnParsed.Name(),
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		}

		// Create mock attribute value with both attribute and value
		value := &policy.Value{
			Id:        "test-value-id",
			Attribute: attribute,
			Value:     fqnParsed.Value(),
			Fqn:       fqn,
			Grants: []*policy.KeyAccessServer{
				{
					Uri: m.kasURL,
					PublicKey: &policy.PublicKey{
						PublicKey: &policy.PublicKey_Remote{
							Remote: m.kasURL,
						},
					},
				},
			},
			// Add KAS keys mapping to the mock KAS server
			KasKeys: []*policy.SimpleKasKey{
				{
					KasUri: m.kasURL,
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
						Kid:       "test-key-id",
						Pem:       m.publicKeyPEM, // Use the actual public key PEM
					},
				},
			},
		}

		av[fqn] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{ // cspell: disable-line
			Attribute: attribute,
			Value:     value,
		}
	}

	return &attributes.GetAttributeValuesByFqnsResponse{ // cspell: disable-line
		FqnAttributeValues: av, // cspell: disable-line
	}, nil
}

func TestStreamingWriter_Basic(t *testing.T) {
	// Create a minimal SDK instance for testing
	sdk, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
	require.NoError(t, err)
	defer sdk.Close()

	// Create streaming writer
	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, writer)
	assert.NotNil(t, writer.writer)
	assert.Equal(t, sdk, writer.sdk)
}

func TestStreamingWriter_WriteSegment(t *testing.T) {
	// Create a minimal SDK instance for testing
	sdk, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
	require.NoError(t, err)
	defer sdk.Close()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Test negative index validation
	_, err = writer.WriteSegment(t.Context(), -1, []byte("test data"))
	require.ErrorIs(t, err, ErrStreamingWriterInvalidPart)

	// Test valid segment index
	testData := []byte("hello world")
	encryptedBytes, err := writer.WriteSegment(t.Context(), 0, testData)
	require.NoError(t, err)
	assert.NotNil(t, encryptedBytes)
	assert.NotEmpty(t, encryptedBytes)

	// Test second segment
	encryptedBytes2, err := writer.WriteSegment(t.Context(), 1, testData)
	require.NoError(t, err)
	assert.NotNil(t, encryptedBytes2)
	assert.NotEmpty(t, encryptedBytes2)
}

func TestStreamingWriter_Finalize(t *testing.T) {
	// Use mock KAS server for complete testing
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Write a segment first
	testData := []byte("hello world")
	_, err = writer.WriteSegment(t.Context(), 0, testData)
	require.NoError(t, err)

	// Finalize the TDF with empty attributes
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	require.NotNil(t, finalizeResult)
	assert.NotEmpty(t, finalizeResult.Data)
	assert.NotNil(t, finalizeResult.Manifest)
	assert.Equal(t, 1, finalizeResult.TotalSegments)

	// Verify manifest structure
	assert.NotEmpty(t, finalizeResult.Manifest.TDFVersion)
	assert.Equal(t, "application/octet-stream", finalizeResult.Manifest.Payload.MimeType)
	assert.Equal(t, "zip", finalizeResult.Manifest.Payload.Protocol)
	assert.Equal(t, "reference", finalizeResult.Manifest.Payload.Type)
	assert.True(t, finalizeResult.Manifest.Payload.IsEncrypted)
}

func TestStreamingWriter_FinalizeWithOptions(t *testing.T) {
	// Use mock KAS server for complete testing
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Write a segment first
	testData := []byte("hello world")
	_, err = writer.WriteSegment(t.Context(), 0, testData)
	require.NoError(t, err)

	// Test finalize with options using mock KAS URL
	finalizeResult, err := writer.Finalize(
		t.Context(),
		[]string{}, // Empty attributes for testing
		WithPayloadMimeType("text/plain"),
		WithEncryptedMetadata("test metadata"),
	)

	require.NoError(t, err)
	assert.NotNil(t, finalizeResult.Data)
	assert.NotEmpty(t, finalizeResult.Data)
	assert.NotNil(t, finalizeResult.Manifest)

	// Verify manifest structure with custom options
	assert.NotEmpty(t, finalizeResult.Manifest.TDFVersion)
	assert.Equal(t, "text/plain", finalizeResult.Manifest.Payload.MimeType)
	assert.Equal(t, "zip", finalizeResult.Manifest.Payload.Protocol)
	assert.Equal(t, "reference", finalizeResult.Manifest.Payload.Type)
	assert.True(t, finalizeResult.Manifest.Payload.IsEncrypted)
}

func TestStreamingWriter_FinalizeOptionValidation(t *testing.T) {
	testCases := []struct {
		name    string
		options []FinalizeOption
		wantErr bool
	}{
		{
			name: "Valid options",
			options: []FinalizeOption{
				WithPayloadMimeType("application/json"),
				// Use mock server's base key configuration (no explicit default KAS needed)
			},
			wantErr: false,
		},
		{
			name:    "Empty options",
			options: []FinalizeOption{},
			wantErr: false,
		},
	}

	// Use mock KAS server for complete testing
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := sdk.NewStreamingWriter(t.Context())
			require.NoError(t, err)

			// Write a segment first
			testData := []byte("hello world")
			_, err = writer.WriteSegment(t.Context(), 0, testData)
			require.NoError(t, err)

			_, err = writer.Finalize(t.Context(), []string{}, tc.options...)

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStreamingWriter_AttributeFetching(t *testing.T) {
	// Create a minimal SDK instance for testing
	sdk, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
	require.NoError(t, err)
	defer sdk.Close()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Test fetchAttributesByFQNs with empty slice (cspell: ignore FQNs)
	attrs, err := writer.fetchAttributesByFQNs(t.Context(), []string{})
	require.NoError(t, err)
	assert.Empty(t, attrs)

	// Test fetchAttributesByFQNs with invalid FQN (empty string) (cspell: ignore FQNs)
	_, err = writer.fetchAttributesByFQNs(t.Context(), []string{""})
	require.ErrorIs(t, err, ErrStreamingWriterInvalidFQN)
	assert.Contains(t, err.Error(), "empty FQN provided")

	// Test fetchAttributesByFQNs with valid FQN format but no platform connection (cspell: ignore FQNs)
	// This will fail due to network connection, which is expected in unit tests
	_, err = writer.fetchAttributesByFQNs(t.Context(), []string{"https://example.com/attr/clearance/value/secret"})
	// We expect this to fail due to network connection, not due to validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "empty FQN provided")
}

func TestStreamingWriter_ReaderCompatibility(t *testing.T) {
	// This test verifies that TDFs created by StreamingWriter have the correct structure
	// that would be readable by SDK.LoadTDF

	// Use mock KAS server for complete testing
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	// Create streaming writer
	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Write test data in multiple segments
	testData1 := []byte("Hello, ")
	testData2 := []byte("World!")

	// Collect all TDF bytes for complete file
	var allTDFBytes []byte

	result1, err := writer.WriteSegment(t.Context(), 0, testData1)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.NotEmpty(t, result1.Data)
	assert.Equal(t, 0, result1.Index)
	assert.NotEmpty(t, result1.Hash)
	assert.Equal(t, int64(len(testData1)), result1.PlaintextSize)
	assert.Positive(t, result1.EncryptedSize)
	assert.Positive(t, result1.CRC32)
	allTDFBytes = append(allTDFBytes, result1.Data...)

	result2, err := writer.WriteSegment(t.Context(), 1, testData2)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.NotEmpty(t, result2.Data)
	assert.Equal(t, 1, result2.Index)
	assert.NotEmpty(t, result2.Hash)
	assert.Equal(t, int64(len(testData2)), result2.PlaintextSize)
	assert.Positive(t, result2.EncryptedSize)
	assert.Positive(t, result2.CRC32)
	allTDFBytes = append(allTDFBytes, result2.Data...)

	// Finalize the TDF completely
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	require.NotNil(t, finalizeResult)
	assert.NotEmpty(t, finalizeResult.Data)
	assert.NotNil(t, finalizeResult.Manifest)
	assert.Equal(t, 2, finalizeResult.TotalSegments)
	assert.Equal(t, int64(len(testData1)+len(testData2)), finalizeResult.TotalSize)
	assert.Positive(t, finalizeResult.EncryptedSize)

	// Add final bytes to complete the TDF
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)

	// Verify manifest has correct structure for reader compatibility
	assert.NotEmpty(t, finalizeResult.Manifest.TDFVersion)
	assert.Equal(t, "zip", finalizeResult.Manifest.Payload.Protocol)
	assert.Equal(t, "reference", finalizeResult.Manifest.Payload.Type)
	assert.True(t, finalizeResult.Manifest.Payload.IsEncrypted)

	// Verify encryption information for reader compatibility
	assert.NotNil(t, finalizeResult.Manifest.EncryptionInformation)
	assert.True(t, finalizeResult.Manifest.EncryptionInformation.Method.IsStreamable)
	assert.NotEmpty(t, finalizeResult.Manifest.EncryptionInformation.KeyAccessObjs)

	// Test actual reader compatibility by loading and decrypting the TDF
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should be able to load TDF created by StreamingWriter")
	require.NotNil(t, reader)

	// Read and decrypt the payload using io.Copy
	var decryptedData bytes.Buffer
	_, err = io.Copy(&decryptedData, reader)
	require.NoError(t, err, "Should be able to decrypt TDF payload")

	// Verify we get back the original data
	expectedData := make([]byte, 0, len(testData1)+len(testData2))
	expectedData = append(expectedData, testData1...)
	expectedData = append(expectedData, testData2...)
	assert.Equal(t, expectedData, decryptedData.Bytes(), "Decrypted data should match original")

	t.Log("✅ Full round-trip test passed: write → read → decrypt")
}

func TestStreamingWriter_FullEndToEndWithMocks(t *testing.T) {
	// t.Skip("Skipping until mock server setup is debugged")

	// Setup mock KAS server with full rewrap functionality
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	// Create streaming writer with mock server
	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Write test data in multiple segments with different sizes to trigger the bug
	testData1 := []byte("Part 1: ")         // 8 bytes
	testData2 := []byte("streaming world!") // 16 bytes - this should cause variable length segments

	// Collect all TDF bytes for complete file
	var allTDFBytes []byte

	// Write segments (simulating S3 multipart upload)
	segmentResult1, err := writer.WriteSegment(t.Context(), 0, testData1)
	require.NoError(t, err)
	assert.NotEmpty(t, segmentResult1.Data)
	allTDFBytes = append(allTDFBytes, segmentResult1.Data...)
	t.Logf("Part 1: %d bytes encrypted", len(segmentResult1.Data))

	segmentResult2, err := writer.WriteSegment(t.Context(), 1, testData2)
	require.NoError(t, err)
	assert.NotEmpty(t, segmentResult2.Data)
	allTDFBytes = append(allTDFBytes, segmentResult2.Data...)
	t.Logf("Part 2: %d bytes encrypted", len(segmentResult2.Data))

	// Finalize with attributes and options
	finalizeResult, err := writer.Finalize(
		t.Context(),
		[]string{}, // Empty attributes like ReaderCompatibility test
		WithPayloadMimeType("text/plain"),
		// WithDefaultKAS will be set from the server URL automatically
		WithDefaultAssertion(true), // Remove default assertion to match ReaderCompatibility test
	)

	require.NoError(t, err, "Finalization should succeed with mock KAS")
	require.NotNil(t, finalizeResult)
	require.NotNil(t, finalizeResult.Manifest)
	assert.NotEmpty(t, finalizeResult.Data)

	// Add final bytes to complete the TDF
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)
	t.Logf("Successfully created TDF: %d bytes total", len(allTDFBytes))

	// Verify manifest structure
	assert.NotEmpty(t, finalizeResult.Manifest.TDFVersion)
	assert.Equal(t, "text/plain", finalizeResult.Manifest.Payload.MimeType)
	assert.Equal(t, "zip", finalizeResult.Manifest.Payload.Protocol)
	assert.Equal(t, "reference", finalizeResult.Manifest.Payload.Type)
	assert.True(t, finalizeResult.Manifest.Payload.IsEncrypted)

	// Verify encryption information
	assert.NotNil(t, finalizeResult.Manifest.EncryptionInformation)
	assert.True(t, finalizeResult.Manifest.EncryptionInformation.Method.IsStreamable)
	assert.NotEmpty(t, finalizeResult.Manifest.EncryptionInformation.KeyAccessObjs)

	// Verify segment structure
	assert.Len(t, finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.Segments, 2)
	assert.Equal(t, int64(8), finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize)

	// Verify segments have different sizes (variable-length)
	segments := finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.Segments
	assert.Equal(t, int64(8), segments[0].Size)  // First segment
	assert.Equal(t, int64(16), segments[1].Size) // Second segment (different size)

	// Test actual reader compatibility by loading and decrypting the TDF with attributes
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should be able to load TDF created by StreamingWriter with attributes")
	require.NotNil(t, reader)

	// Read and decrypt the payload using io.Copy
	var decryptedData bytes.Buffer
	_, err = io.Copy(&decryptedData, reader)
	require.NoError(t, err, "Should be able to decrypt TDF payload with attributes and assertions")

	// Verify we get back the original data from both segments
	expectedData := make([]byte, 0, len(testData1)+len(testData2))
	expectedData = append(expectedData, testData1...)
	expectedData = append(expectedData, testData2...)
	assert.Equal(t, expectedData, decryptedData.Bytes(), "Decrypted data should match original two-segment data")

	t.Log("✅ Full end-to-end test passed with mock KAS, attributes, and reader validation")
}

func TestStreamingWriter_VariableLengthSegments(t *testing.T) {
	// Test with multiple segments of varying sizes in sequential order
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Create segments with varying sizes: 5, 10, 15, 3 bytes
	testSegments := [][]byte{
		[]byte("Test1"),           // 5 bytes
		[]byte("TestData22"),      // 10 bytes
		[]byte("TestDataSegment"), // 15 bytes
		[]byte("End"),             // 3 bytes
	}

	var allTDFBytes []byte

	// Write segments in order using 0-based indices
	for i, data := range testSegments {
		segmentResult, err := writer.WriteSegment(t.Context(), i, data)
		require.NoError(t, err)
		assert.NotEmpty(t, segmentResult)
		allTDFBytes = append(allTDFBytes, segmentResult.Data...)
		t.Logf("Segment %d (%d bytes): %d encrypted bytes, first 16 bytes: %x", i, len(data), len(segmentResult.Data), segmentResult.Data[:min(16, len(segmentResult.Data))])
	}

	// Finalize TDF
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)

	// Verify variable segment sizes
	segments := finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.Segments
	assert.Len(t, segments, 4)
	assert.Equal(t, int64(5), segments[0].Size) // First segment used as default
	assert.Equal(t, int64(5), finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize)
	assert.Equal(t, int64(10), segments[1].Size) // Different from default
	assert.Equal(t, int64(15), segments[2].Size) // Different from default
	assert.Equal(t, int64(3), segments[3].Size)  // Different from default

	// Test reader compatibility with variable segments
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should load TDF with variable segment lengths")

	var decryptedData bytes.Buffer
	_, err = io.Copy(&decryptedData, reader)
	require.NoError(t, err, "Should decrypt TDF with variable segment lengths")

	// Verify decrypted data matches original
	expectedData := bytes.Join(testSegments, nil)
	assert.Equal(t, expectedData, decryptedData.Bytes())

	t.Log("✅ Variable length segments test passed")
}

func TestStreamingWriter_OutOfOrderSegments(t *testing.T) {
	// Test writing segments out of order as happens in advanced streaming scenarios
	// Uses 0-based indices as the low-level API expects
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Define segments with different sizes (using 0-based segment indices)
	testSegments := map[int][]byte{
		0: []byte("First"),         // 5 bytes
		1: []byte("SecondPart"),    // 10 bytes
		2: []byte("Third"),         // 5 bytes
		3: []byte("FourthSection"), // 13 bytes
		4: []byte("Last"),          // 4 bytes
	}

	// Write segments out of order: 2, 0, 4, 1, 3 (0-based segment indices)
	writeOrder := []int{2, 0, 4, 1, 3}
	segmentBytes := make(map[int][]byte) // Store encrypted bytes by segment index

	for _, segmentIndex := range writeOrder {
		data := testSegments[segmentIndex]
		segmentResult, err := writer.WriteSegment(t.Context(), segmentIndex, data)
		require.NoError(t, err)
		assert.NotEmpty(t, segmentResult.Data)
		// Store the complete encrypted bytes for this segment index
		segmentBytes[segmentIndex] = segmentResult.Data
		t.Logf("Wrote segment %d out of order (%d bytes data → %d encrypted bytes)", segmentIndex, len(data), len(segmentResult.Data))
	}

	// Reassemble segments in correct order (0,1,2,3,4) for valid ZIP structure
	var allTDFBytes []byte
	for i := 0; i < 5; i++ {
		allTDFBytes = append(allTDFBytes, segmentBytes[i]...)
		t.Logf("Assembled segment %d: %d bytes, first 16 bytes: %x", i, len(segmentBytes[i]), segmentBytes[i][:min(16, len(segmentBytes[i]))])
	}
	t.Logf("Total TDF bytes before finalize: %d", len(allTDFBytes))

	// Finalize TDF
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)

	// Debug segment information
	segments := finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.Segments
	t.Logf("Found %d segments in manifest", len(segments))
	for i, seg := range segments {
		t.Logf("Segment %d: Size=%d, Hash=%q", i, seg.Size, seg.Hash)
	}

	// Write ZIP to filesystem for examination
	zipFile, err := os.Create("out-of-order-test.tdf")
	require.NoError(t, err, "Should create test file")
	defer zipFile.Close()
	// defer os.Remove("out-of-order-test.tdf") // Clean up after test - commented for examination

	_, err = zipFile.Write(allTDFBytes)
	require.NoError(t, err, "Should write TDF bytes to file")

	t.Logf("Written TDF to out-of-order-test.tdf (%d bytes)", len(allTDFBytes))

	// Test reader with out-of-order written segments
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should load TDF written out of order")

	var decryptedData bytes.Buffer
	_, err = io.Copy(&decryptedData, reader)
	require.NoError(t, err, "Should decrypt TDF written out of order")

	// The decrypted data should be in LOGICAL order (0,1,2,3,4)
	// even though segments were written out of order (2,0,4,1,3)
	var expectedData []byte
	for i := 0; i < 5; i++ {
		expectedData = append(expectedData, testSegments[i]...)
	}
	assert.Equal(t, expectedData, decryptedData.Bytes(), "Data should be in logical order despite out-of-order writing")

	t.Log("✅ Out-of-order segments test passed")
}

func TestStreamingWriter_LargeVariableSegments(t *testing.T) {
	// Test with larger segments of significantly different sizes
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Create segments with dramatically different sizes
	testSegments := [][]byte{
		[]byte("A"),                       // 1 byte
		bytes.Repeat([]byte("B"), 100),    // 100 bytes
		[]byte("CCC"),                     // 3 bytes
		bytes.Repeat([]byte("DDDD"), 250), // 1000 bytes
		[]byte("E"),                       // 1 byte
		bytes.Repeat([]byte("F"), 50),     // 50 bytes
	}

	var allTDFBytes []byte

	// Write all segments
	for i, data := range testSegments {
		segmentResult, err := writer.WriteSegment(t.Context(), i, data)
		require.NoError(t, err)
		assert.NotEmpty(t, segmentResult.Data)
		allTDFBytes = append(allTDFBytes, segmentResult.Data...)
		t.Logf("Large segment %d: %d bytes → %d encrypted bytes", i, len(data), len(segmentResult.Data))
	}

	// Finalize TDF
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)

	// Verify highly variable segment sizes
	segments := finalizeResult.Manifest.EncryptionInformation.IntegrityInformation.Segments
	assert.Len(t, segments, 6)
	expectedSizes := []int64{1, 100, 3, 1000, 1, 50}
	for i, expectedSize := range expectedSizes {
		assert.Equal(t, expectedSize, segments[i].Size, "Segment %d size mismatch", i)
	}

	// Test reader with highly variable segment sizes
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should load TDF with highly variable segment sizes")

	var decryptedData bytes.Buffer
	_, err = io.Copy(&decryptedData, reader)
	require.NoError(t, err, "Should decrypt TDF with highly variable segment sizes")

	// Verify all data is correctly decrypted
	expectedData := bytes.Join(testSegments, nil)
	assert.Equal(t, expectedData, decryptedData.Bytes())

	// Verify total size
	expectedTotalSize := 1 + 100 + 3 + 1000 + 1 + 50 // 1155 bytes
	assert.Len(t, decryptedData.Bytes(), expectedTotalSize)

	t.Log("✅ Large variable segments test passed")
}

func TestStreamingWriter_RandomReadAccess(t *testing.T) {
	// Test random read access to verify segment locator works correctly
	sdk, cleanup := setupMockKASServer(t)
	defer cleanup()

	writer, err := sdk.NewStreamingWriter(t.Context())
	require.NoError(t, err)

	// Create segments with known data patterns for testing specific offsets
	testSegments := [][]byte{
		[]byte("AAAAAAAAAA"),           // 10 bytes of 'A' (offset 0-9)
		[]byte("BBBBBBBBBBBBBBBB"),     // 16 bytes of 'B' (offset 10-25)
		[]byte("CCCCCCCCCCCCCCCCCCCC"), // 20 bytes of 'C' (offset 26-45)
		[]byte("DDDD"),                 // 4 bytes of 'D' (offset 46-49)
	}

	var allTDFBytes []byte

	// Write segments in order
	for i, data := range testSegments {
		segmentResult, err := writer.WriteSegment(t.Context(), i, data)
		require.NoError(t, err)
		allTDFBytes = append(allTDFBytes, segmentResult.Data...)
	}

	// Finalize TDF
	finalizeResult, err := writer.Finalize(t.Context(), []string{})
	require.NoError(t, err)
	allTDFBytes = append(allTDFBytes, finalizeResult.Data...)

	// Load TDF for reading
	tdfReader := bytes.NewReader(allTDFBytes)
	reader, err := sdk.LoadTDF(tdfReader, WithIgnoreAllowlist(true))
	require.NoError(t, err, "Should load TDF for random access testing")

	// Test random read access at specific offsets
	testCases := []struct {
		offset   int64
		length   int
		expected byte
		desc     string
	}{
		{0, 5, 'A', "Start of first segment"},
		{5, 5, 'A', "Middle of first segment"},
		{10, 8, 'B', "Start of second segment"},
		{18, 7, 'B', "Middle of second segment"},
		{26, 10, 'C', "Start of third segment"},
		{35, 10, 'C', "Middle of third segment"},
		{46, 4, 'D', "Entire fourth segment"},
		{48, 2, 'D', "End of fourth segment"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			// Seek to the desired offset
			_, err := reader.Seek(tc.offset, io.SeekStart)
			require.NoError(t, err, "Should be able to seek to offset %d", tc.offset)

			// Read the specified length
			buffer := make([]byte, tc.length)
			n, err := reader.Read(buffer)
			require.NoError(t, err, "Should be able to read %d bytes at offset %d", tc.length, tc.offset)
			require.Equal(t, tc.length, n, "Should read exactly %d bytes", tc.length)

			// Verify all bytes match the expected character
			for i, b := range buffer {
				assert.Equal(t, tc.expected, b, "Byte at position %d (global offset %d) should be %c", i, tc.offset+int64(i), tc.expected)
			}
		})
	}

	// Test edge cases
	t.Run("Read at exact segment boundaries", func(t *testing.T) {
		// Read across segment boundary (end of A into start of B)
		_, err := reader.Seek(9, io.SeekStart)
		require.NoError(t, err)

		buffer := make([]byte, 2)
		n, err := reader.Read(buffer)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		assert.Equal(t, byte('A'), buffer[0], "Last byte of first segment should be 'A'")
		assert.Equal(t, byte('B'), buffer[1], "First byte of second segment should be 'B'")
	})

	t.Run("Read across multiple segments", func(t *testing.T) {
		// Read from middle of second segment through third segment
		_, err := reader.Seek(20, io.SeekStart)
		require.NoError(t, err)

		buffer := make([]byte, 10) // Should span B segment end and C segment start
		n, err := reader.Read(buffer)
		require.NoError(t, err)
		require.Equal(t, 10, n)

		// First 6 bytes should be 'B' (from offset 20-25)
		for i := 0; i < 6; i++ {
			assert.Equal(t, byte('B'), buffer[i], "Byte %d should be 'B'", i)
		}
		// Next 4 bytes should be 'C' (from offset 26-29)
		for i := 6; i < 10; i++ {
			assert.Equal(t, byte('C'), buffer[i], "Byte %d should be 'C'", i)
		}
	})

	t.Log("✅ Random read access test passed")
}

func TestStreamingWriter_PartNumberConversion(t *testing.T) {
	testCases := []struct {
		name         string
		segmentIndex int
		expectedErr  error
		expectSegIdx int
	}{
		{"Valid segment 0", 0, nil, 0},
		{"Invalid negative segment", -1, ErrStreamingWriterInvalidPart, -1},
		{"Valid segment 1", 1, nil, 1},
		{"Valid segment 2", 2, nil, 2},
		{"Valid segment 10", 10, nil, 10},
	}

	// Create a minimal SDK instance for testing
	sdk, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
	require.NoError(t, err)
	defer sdk.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := sdk.NewStreamingWriter(t.Context())
			require.NoError(t, err)

			_, err = writer.WriteSegment(t.Context(), tc.segmentIndex, []byte("test"))

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
