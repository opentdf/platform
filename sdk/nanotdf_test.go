package sdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	nanoFakePem       = "pem"
	fakeObligationFQN = "https://fake.example.com/obl/value/obligation1"
)

// mockTransport is a custom RoundTripper that intercepts HTTP requests
type mockTransport struct {
	publicKey  string
	kid        string
	kasKeyPair ocrypto.KeyPair // Store the KAS key pair for consistent crypto operations
}

// nanotdfEqual compares two nanoTdf structures for equality.
func nanoTDFEqual(a, b *NanoTDFHeader) bool {
	// Compare kasURL field
	if a.kasURL.protocol != b.kasURL.protocol || a.kasURL.getLength() != b.kasURL.getLength() || a.kasURL.body != b.kasURL.body {
		return false
	}

	// Compare binding field
	if a.bindCfg.useEcdsaBinding != b.bindCfg.useEcdsaBinding || a.bindCfg.eccMode != b.bindCfg.eccMode {
		return false
	}

	// Compare sigCfg field
	if a.sigCfg.hasSignature != b.sigCfg.hasSignature || a.sigCfg.signatureMode != b.sigCfg.signatureMode || a.sigCfg.cipher != b.sigCfg.cipher {
		return false
	}

	// Compare policy field
	// if a.PolicyBinding  != b.PolicyBinding) {
	// 	return false
	// }

	// Compare EphemeralPublicKey field
	if !bytes.Equal(a.EphemeralKey, b.EphemeralKey) {
		return false
	}

	// If all comparisons passed, the structures are equal
	return true
}

//// policyBodyEqual compares two PolicyBody instances for equality.
// func policyBodyEqual(a, b PolicyBody) bool { //nolint:unused future usage
//	// Compare based on the concrete type of PolicyBody
//	switch a.mode {
//	case policyTypeRemotePolicy:
//		return remotePolicyEqual(a.rp, b.rp)
//	case policyTypeEmbeddedPolicyPlainText:
//	case policyTypeEmbeddedPolicyEncrypted:
//	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
//		return embeddedPolicyEqual(a.ep, b.ep)
//	}
//	return false
// }

//// remotePolicyEqual compares two remotePolicy instances for equality.
// func remotePolicyEqual(a, b remotePolicy) bool { // nolint:unused future usage
//	// Compare url field
//	if a.url.protocol != b.url.protocol || a.url.getLength() != b.url.getLength() || a.url.body != b.url.body {
//		return false
//	}
//	return true
// }
//
//// embeddedPolicyEqual compares two embeddedPolicy instances for equality.
// func embeddedPolicyEqual(a, b embeddedPolicy) bool { // nolint:unused future usage
//	// Compare lengthBody and body fields
//	return a.lengthBody == b.lengthBody && bytes.Equal(a.body, b.body)
// }
//
//// eccSignatureEqual compares two eccSignature instances for equality.
// func eccSignatureEqual(a, b *eccSignature) bool { // nolint:unused future usage
//	// Compare value field
//	return bytes.Equal(a.value, b.value)
// }

func init() {
	// Register the remotePolicy type with gob
	gob.Register(&remotePolicy{})
}

func NotTestReadNanoTDFHeader(t *testing.T) {
	// Prepare a sample nanoTdf structure
	goodHeader := NanoTDFHeader{
		kasURL: ResourceLocator{
			protocol: urlProtocolHTTPS,
			body:     "kas.virtru.com",
		},
		bindCfg: bindingConfig{
			useEcdsaBinding: true,
			eccMode:         ocrypto.ECCModeSecp256r1,
		},
		sigCfg: signatureConfig{
			hasSignature:  true,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm64Bit,
		},
		// PolicyBinding: policyInfo{
		//	body: PolicyBody{
		//		mode: policyTypeRemotePolicy,
		//		rp: remotePolicy{
		//			url: ResourceLocator{
		//				protocol: urlProtocolHTTPS,
		//				body:     "kas.virtru.com/policy",
		//			},
		//		},
		//	},
		//	binding: &eccSignature{
		//		value: []byte{181, 228, 19, 166, 2, 17, 229, 241},
		//	},
		// },
		EphemeralKey: []byte{
			123, 34, 52, 160, 205, 63, 54, 255, 123, 186, 109,
			143, 232, 223, 35, 246, 44, 157, 9, 53, 111, 133,
			130, 248, 169, 207, 21, 18, 108, 138, 157, 164, 108,
		},
	}

	const (
		kExpectedHeaderSize = 128
	)

	// Serialize the sample nanoTdf structure into a byte slice using gob
	file, err := os.Open("nanotdfspec.ntdf")
	if err != nil {
		t.Fatalf("Cannot open nanoTdf file: %v", err)
	}
	defer file.Close()

	resultHeader, headerSize, err := NewNanoTDFHeaderFromReader(io.ReadSeeker(file))
	if err != nil {
		t.Fatalf("Error while reading nanoTdf header: %v", err)
	}

	if headerSize != kExpectedHeaderSize {
		t.Fatalf("expecting length %d, got %d", kExpectedHeaderSize, headerSize)
	}

	// Compare the result with the original nanoTdf structure
	if !nanoTDFEqual(&resultHeader, &goodHeader) {
		t.Error("Result does not match the expected nanoTdf structure.")
	}
}

const (
//	sdkPrivateKey = `-----BEGIN PRIVATE KEY-----
// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW
// 6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/
// PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5
// -----END PRIVATE KEY-----`

//	sdkPublicKey = `-----BEGIN PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ
// vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==
// -----END PUBLIC KEY-----`

//	kasPrivateKey = `-----BEGIN PRIVATE KEY-----
// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB
// PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O
// byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf
// -----END PRIVATE KEY-----`

//	kasPublicKey = `-----BEGIN PUBLIC KEY-----
//
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
// jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
// -----END PUBLIC KEY-----`
)

// disabled for now, no remote policy support yet
func NotTestNanoTDFEncryptFile(t *testing.T) {
	const (
		kExpectedOutSize = 128
	)

	var s SDK
	infile, err := os.Open("nanotest1.txt")
	if err != nil {
		t.Fatal(err)
	}

	// try to delete the output file in case it exists already - ignore error if it doesn't exist
	_ = os.Remove("nanotest1.ntdf")

	outfile, err := os.Create("nanotest1.ntdf")
	if err != nil {
		t.Fatal(err)
	}

	// TODO - populate config properly
	kasURL := "https://kas.virtru.com/kas"
	var config NanoTDFConfig
	err = config.kasURL.setURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	outSize, err := s.CreateNanoTDF(io.Writer(outfile), io.ReadSeeker(infile), config)
	if err != nil {
		t.Fatal(err)
	}
	if outSize != kExpectedOutSize {
		t.Fatalf("expecting length %d, got %d", kExpectedOutSize, outSize)
	}
}

// disabled for now
func NotTestCreateNanoTDF(t *testing.T) {
	var s SDK

	grpc.WithTransportCredentials(insecure.NewCredentials())

	infile, err := os.Open("nanotest1.txt")
	if err != nil {
		t.Fatal(err)
	}

	// try to delete the output file in case it exists already - ignore error if it doesn't exist
	_ = os.Remove("nanotest1.ntdf")

	outfile, err := os.Create("nanotest1.ntdf")
	if err != nil {
		t.Fatal(err)
	}

	// TODO - populate config properly
	kasURL := "https://kas.virtru.com/kas"
	var config NanoTDFConfig
	err = config.kasURL.setURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.CreateNanoTDF(io.Writer(outfile), io.ReadSeeker(infile), config)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNonZeroRandomPaddedIV(t *testing.T) {
	iv, err := nonZeroRandomPaddedIV()
	require.NoError(t, err)
	require.NotNil(t, iv)
	assert.Len(t, iv, ocrypto.GcmStandardNonceSize)

	// Ensure that the IV is not all zeros
	allZero := true
	for _, b := range iv {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "IV should not be all zeros")
}

func TestCreateNanoTDF(t *testing.T) {
	tests := []struct {
		name          string
		writer        io.Writer
		reader        io.Reader
		config        NanoTDFConfig
		expectedError string
	}{
		{
			name:          "Nil writer",
			writer:        nil,
			reader:        bytes.NewReader([]byte("test data")),
			config:        NanoTDFConfig{},
			expectedError: "writer is nil",
		},
		{
			name:          "Nil reader",
			writer:        new(bytes.Buffer),
			reader:        nil,
			config:        NanoTDFConfig{},
			expectedError: "reader is nil",
		},
		{
			name:          "Empty NanoTDFConfig",
			writer:        new(bytes.Buffer),
			reader:        bytes.NewReader([]byte("test data")),
			config:        NanoTDFConfig{},
			expectedError: "config.kasUrl is empty",
		},
		{
			name:   "KAS Identifier NanoTDFConfig",
			writer: new(bytes.Buffer),
			reader: bytes.NewReader([]byte("test data")),
			config: NanoTDFConfig{
				kasURL: ResourceLocator{
					protocol:   1,
					body:       "kas.com",
					identifier: "e0",
				},
			},
			expectedError: "error making request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
			require.NoError(t, err)
			_, err = s.CreateNanoTDF(tt.writer, tt.reader, tt.config)
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestDataSet(t *testing.T) {
	const (
		kasURL = "https://test.virtru.com"
	)

	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	err = conf.SetKasURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	err = conf.SetAttributes([]string{"https://examples.com/attr/attr1/value/value1"})
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conf.kasPublicKey = key.PublicKey()

	getHeaderAndSymKey := func(cfg *NanoTDFConfig) ([]byte, []byte) {
		out := &bytes.Buffer{}
		symKey, _, _, err := writeNanoTDFHeader(out, *cfg)
		if err != nil {
			t.Fatal()
		}

		return out.Bytes(), symKey
	}

	header1, _ := getHeaderAndSymKey(conf)
	header2, _ := getHeaderAndSymKey(conf)

	if bytes.Equal(header1, header2) {
		t.Fatal("headers should not match")
	}

	conf.EnableCollection()
	header1, symKey1 := getHeaderAndSymKey(conf)
	header2, symKey2 := getHeaderAndSymKey(conf)

	if !bytes.Equal(symKey1, symKey2) {
		t.Fatal("keys should match")
	}
	if !bytes.Equal(header1, header2) {
		t.Fatal("headers should match")
	}

	for i := 2; i <= kMaxIters; i++ {
		header, _ := getHeaderAndSymKey(conf)
		if !bytes.Equal(header, header1) {
			t.Fatal("max iteration reset occurred too early, headers differ")
		}
	}

	header, _ := getHeaderAndSymKey(conf)
	if bytes.Equal(header, header1) {
		t.Fatal("header did not reset")
	}
}

type NanoSuite struct {
	suite.Suite
	mockTransport *mockTransport
}

func TestNanoTDF(t *testing.T) {
	suite.Run(t, new(NanoSuite))
}

func (s *NanoSuite) SetupSuite() {
	// Create a single mock transport instance for the entire test suite
	s.mockTransport = newMockTransport()
}

// mockWellKnownServiceClient is a mock implementation of sdkconnect.WellKnownServiceClient
type mockWellKnownServiceClient struct {
	mockResponse func() (*wellknownconfiguration.GetWellKnownConfigurationResponse, error)
}

func (m *mockWellKnownServiceClient) GetWellKnownConfiguration(_ context.Context, _ *wellknownconfiguration.GetWellKnownConfigurationRequest) (*wellknownconfiguration.GetWellKnownConfigurationResponse, error) {
	if m.mockResponse != nil {
		return m.mockResponse()
	}
	return nil, errors.New("no mock response configured")
}

func (s *NanoSuite) Test_CreateNanoTDF_BaseKey() {
	// Mock KAS Info
	mockKASInfo := &KASInfo{
		URL:       "https://kas.example.com",
		PublicKey: mockECPublicKey1,
		KID:       "key-p256",
	}

	baseKey := createTestBaseKeyMap(&s.Suite, policy.Algorithm_ALGORITHM_EC_P256, mockKASInfo.KID, mockKASInfo.PublicKey, mockKASInfo.URL)
	wellKnown := createWellKnown(baseKey)
	mockClient := createMockWellKnownServiceClient(&s.Suite, wellKnown, nil)

	// Create SDK
	sdk := &SDK{
		config: config{
			logger: slog.Default(),
		},
		wellknownConfiguration: mockClient,
	}

	config, err := sdk.NewNanoTDFConfig()
	s.Require().NoError(err)

	err = config.SetKasURL("http://should-change.com")
	s.Require().NoError(err)

	// Mock writer and reader
	writer := new(bytes.Buffer)
	reader := bytes.NewReader([]byte("test data"))

	// Call CreateNanoTDF
	_, err = sdk.CreateNanoTDF(writer, reader, *config)
	s.Require().NoError(err)

	// Check that writer is not empty
	s.Require().NotEmpty(writer.Bytes())
}

func (s *NanoSuite) Test_GetKasInfoForNanoTDF_BaseKey() {
	tests := []struct {
		name           string
		algorithm      policy.Algorithm
		kasURI         string
		publicKeyPem   string
		kid            string
		wellKnownError error
		expectedInfo   *KASInfo
		expectedError  string
	}{
		{
			name:         "Base Key Enabled - EC P256 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p256",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p256",
				Algorithm: "ec:secp256r1",
			},
		},
		{
			name:         "Base Key Enabled - EC P384 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P384,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p384",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p384",
				Algorithm: "ec:secp384r1",
			},
		},
		{
			name:         "Base Key Enabled - EC P521 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P521,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p521",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p521",
				Algorithm: "ec:secp521r1",
			},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Create a mock wellknown configuration response
			baseKey := createTestBaseKeyMap(&s.Suite, tt.algorithm, tt.kid, tt.publicKeyPem, tt.kasURI)
			wellKnown := createWellKnown(baseKey)
			mockClient := createMockWellKnownServiceClient(&s.Suite, wellKnown, tt.wellKnownError)

			// Create SDK with mocked wellknown client
			sdk := &SDK{
				wellknownConfiguration: mockClient,
			}

			// Create a NanoTDFConfig
			config := NanoTDFConfig{
				bindCfg: bindingConfig{
					eccMode: ocrypto.ECCModeSecp384r1,
				},
			}
			kasURL := "https://should-not-change.com"
			err := config.SetKasURL(kasURL)
			s.Require().NoError(err)

			// Call the getKasInfoForNanoTDF function
			info, err := getKasInfoForNanoTDF(sdk, &config)

			// Check for expected errors
			if tt.expectedError != "" {
				s.Require().Error(err)
				s.Require().Nil(info)
				return
			}

			// Check success case
			s.Require().NoError(err)
			s.Require().NotNil(info)
			s.Require().Equal(tt.expectedInfo.URL, info.URL)
			s.Require().Equal(tt.expectedInfo.PublicKey, info.PublicKey)
			s.Require().Equal(tt.expectedInfo.KID, info.KID)
			s.Require().Equal(tt.expectedInfo.Algorithm, info.Algorithm)
			// Ensure the config was updated.
			actualURL, err := config.kasURL.GetURL()
			s.Require().NoError(err)
			s.Require().Equal(tt.kasURI, actualURL)
			expectedEcMode, err := ocrypto.ECKeyTypeToMode(ocrypto.KeyType(tt.expectedInfo.Algorithm))
			s.Require().NoError(err)
			s.Require().Equal(expectedEcMode, config.bindCfg.eccMode)
		})
	}
}

func (s *NanoSuite) Test_PopulateNanoBaseKeyWithMockWellKnown() {
	// Define test cases
	tests := []struct {
		name           string
		algorithm      policy.Algorithm
		kasURI         string
		publicKeyPem   string
		kid            string
		wellKnownError error
		expectedInfo   *KASInfo
		expectedError  string
	}{
		{
			name:         "EC P256 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P256,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p256",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p256",
				Algorithm: "ec:secp256r1",
			},
		},
		{
			name:         "EC P384 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P384,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p384",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p384",
				Algorithm: "ec:secp384r1",
			},
		},
		{
			name:         "EC P521 - Success",
			algorithm:    policy.Algorithm_ALGORITHM_EC_P521,
			kasURI:       "https://kas.example.com",
			publicKeyPem: nanoFakePem,
			kid:          "key-p521",
			expectedInfo: &KASInfo{
				URL:       "https://kas.example.com",
				PublicKey: nanoFakePem,
				KID:       "key-p521",
				Algorithm: "ec:secp521r1",
			},
		},
		{
			name:           "Error from WellKnown Config",
			algorithm:      policy.Algorithm_ALGORITHM_EC_P256,
			kasURI:         "https://kas.example.com",
			wellKnownError: errors.New("failed to get configuration"),
			expectedError:  "unable to retrieve config information",
		},
		{
			name:          "Unsupported algorithm RSA 2048",
			algorithm:     policy.Algorithm_ALGORITHM_RSA_2048,
			kasURI:        "https://localhost:8080",
			publicKeyPem:  nanoFakePem,
			kid:           "key-rsa",
			expectedError: "base key algorithm is not supported for nano",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Create a mock wellknown configuration response
			baseKey := createTestBaseKeyMap(&s.Suite, tt.algorithm, tt.kid, tt.publicKeyPem, tt.kasURI)
			wellKnown := createWellKnown(baseKey)
			mockClient := createMockWellKnownServiceClient(&s.Suite, wellKnown, tt.wellKnownError)

			// Create SDK with mocked wellknown client
			sdk := &SDK{
				wellknownConfiguration: mockClient,
			}

			// Call the real populateNanoBaseKey function
			info, err := getNanoKasInfoFromBaseKey(sdk)

			// Check for expected errors
			if tt.expectedError != "" {
				s.Require().Error(err)
				s.Require().Contains(err.Error(), tt.expectedError)
				s.Require().Nil(info)
				return
			}

			// Check success case
			s.Require().NoError(err)
			s.Require().NotNil(info)
			s.Require().Equal(tt.expectedInfo.URL, info.URL)
			s.Require().Equal(tt.expectedInfo.PublicKey, info.PublicKey)
			s.Require().Equal(tt.expectedInfo.KID, info.KID)
			s.Require().Equal(tt.expectedInfo.Algorithm, info.Algorithm)
		})
	}
}

func createMockWellKnownServiceClient(s *suite.Suite, wellKnownConfig map[string]interface{}, wellKnownError error) *mockWellKnownServiceClient {
	return &mockWellKnownServiceClient{
		mockResponse: func() (*wellknownconfiguration.GetWellKnownConfigurationResponse, error) {
			if wellKnownError != nil {
				return nil, wellKnownError
			}

			cfg, err := structpb.NewStruct(wellKnownConfig)
			s.Require().NoError(err, "Failed to create struct from well-known configuration")

			return &wellknownconfiguration.GetWellKnownConfigurationResponse{
				Configuration: cfg,
			}, nil
		},
	}
}

// Test suite for NanoTDF Reader functionality
func (s *NanoSuite) Test_NanoTDFReader_LoadNanoTDF() {
	// Create a real NanoTDF for testing
	sdk, err := s.createTestSDK()
	sdk.fulfillableObligationFQNs = []string{"https://example.com/obl/value/obl1"}
	s.Require().NoError(err)
	nanoTDFData, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)
	reader := bytes.NewReader(nanoTDFData)

	// Test successful load with ignore allowlist
	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)
	s.Require().NotNil(nanoReader)
	s.Require().Equal(reader, nanoReader.reader)
	s.Require().NotNil(nanoReader.config)
	s.Require().True(nanoReader.config.ignoreAllowList)
	s.Require().Len(nanoReader.config.fulfillableObligationFQNs, 1)
	s.Require().Equal("https://example.com/obl/value/obl1", nanoReader.config.fulfillableObligationFQNs[0])

	// Test with KAS allowlist
	allowedURLs := []string{"https://kas.example.com"}
	reader = bytes.NewReader(nanoTDFData) // Reset reader
	nanoReader2, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoKasAllowlist(allowedURLs))
	s.Require().NoError(err)
	s.Require().NotNil(nanoReader2.config.kasAllowlist)
	s.Require().True(nanoReader2.config.kasAllowlist.IsAllowed("https://kas.example.com"))

	// Test with fulfillable obligations
	obligations := []string{"obligation1", "obligation2"}
	reader = bytes.NewReader(nanoTDFData) // Reset reader
	nanoReader3, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoTDFFulfillableObligationFQNs(obligations), WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)
	s.Require().Equal(obligations, nanoReader3.config.fulfillableObligationFQNs)

	// Test with invalid reader (nil)
	_, err = sdk.LoadNanoTDF(s.T().Context(), nil)
	s.Require().Error(err)
}

func (s *NanoSuite) Test_NanoTDFReader_Init_WithPayloadKeySet() {
	// Create a real NanoTDF for testing
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)
	nanoTDFData, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)
	reader := bytes.NewReader(nanoTDFData)
	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)

	// Test that calling Init twice doesn't cause issues when payloadKey is set
	nanoReader.payloadKey = []byte("mock-key")
	err = nanoReader.Init(s.T().Context())
	s.Require().NoError(err) // Should return early since payloadKey is set
}

func (s *NanoSuite) Test_NanoTDFReader_Init_WithoutPayloadKeySet() {
	// Create a real NanoTDF for testing
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)
	nanoTDFData, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)
	reader := bytes.NewReader(nanoTDFData)

	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)

	err = nanoReader.Init(s.T().Context())
	s.Require().NoError(err)
	s.Require().NotNil(nanoReader.payloadKey)
}

func (s *NanoSuite) Test_NanoTDFReader_ObligationsSupport() {
	// Create a real NanoTDF for testing
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)
	nanoTDFData, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)
	reader := bytes.NewReader(nanoTDFData)
	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)
	s.Require().Nil(nanoReader.requiredObligations)

	// Mock some triggered obligations as would happen during rewrap
	mockObligations := RequiredObligations{
		FQNs: []string{"obligation1", "obligation2"},
	}
	nanoReader.requiredObligations = &mockObligations

	// Verify obligations are stored
	s.Require().NotNil(nanoReader.requiredObligations)
	s.Require().Len(nanoReader.requiredObligations.FQNs, 2)
	s.Require().Contains(nanoReader.requiredObligations.FQNs, "obligation1")
	s.Require().Contains(nanoReader.requiredObligations.FQNs, "obligation2")
}

func (s *NanoSuite) Test_NanoTDFReader_DecryptNanoTDF() {
	// Create a real NanoTDF for testing
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)
	nanoTDFData, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)
	reader := bytes.NewReader(nanoTDFData)
	writer := &bytes.Buffer{}

	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)

	_, err = nanoReader.DecryptNanoTDF(s.T().Context(), writer)
	s.Require().NoError(err)
	s.Require().Equal([]byte("Virtru!!!!"), writer.Bytes())
}

func (s *NanoSuite) Test_NanoTDFReader_RealWorkflow() {
	// Test the complete workflow: Create -> Load -> Parse Header
	originalData := []byte("This is test data for NanoTDF encryption!")

	// Step 1: Create a real NanoTDF
	input := bytes.NewReader(originalData)
	output := &bytes.Buffer{}

	// Create SDK with consistent mock transport
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)

	config, err := sdk.NewNanoTDFConfig()
	s.Require().NoError(err)

	err = config.SetKasURL("https://kas.example.com")
	s.Require().NoError(err)

	err = config.SetAttributes([]string{"https://example.com/attr/classification/value/secret"})
	s.Require().NoError(err)

	// The kasPublicKey will be fetched automatically from the mock HTTP client during CreateNanoTDF

	// Create the NanoTDF
	tdfSize, err := sdk.CreateNanoTDF(output, input, *config)
	s.Require().NoError(err)
	s.Require().Positive(tdfSize)

	// Step 2: Load the created NanoTDF
	tdfData := output.Bytes()
	reader := bytes.NewReader(tdfData)

	nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoIgnoreAllowlist(true))
	s.Require().NoError(err)
	s.Require().NotNil(nanoReader)

	// Step 3: Validate the header (it should be loaded automatically)
	s.Require().NotNil(nanoReader.headerBuf)
	s.Require().NotEmpty(nanoReader.headerBuf)

	// Check KAS URL
	kasURL, err := nanoReader.header.kasURL.GetURL()
	s.Require().NoError(err)
	s.Require().Equal("https://kas.example.com", kasURL)

	// Check policy mode and other header fields
	s.Require().Equal(PolicyType(2), nanoReader.header.PolicyMode) // Embedded encrypted policy
	s.Require().NotNil(nanoReader.header.PolicyBody)
	s.Require().NotEmpty(nanoReader.header.PolicyBody)
	s.Require().NotNil(nanoReader.header.EphemeralKey)
	s.Require().Len(nanoReader.header.EphemeralKey, 33) // secp256r1 compressed key

	_, err = nanoReader.Obligations(s.T().Context())
	s.Require().NoError(err)
}

func (s *NanoSuite) Test_NanoTDF_Obligations() {
	sdk, err := s.createTestSDK()
	s.Require().NoError(err)
	encryptedPolicyTDF, err := s.createRealNanoTDF(sdk)
	s.Require().NoError(err)

	// Table-driven test for nano TDF obligations support
	testCases := []struct {
		name                   string
		fulfillableObligations []string
		requiredObligations    []string
		expectError            error
		populateObligations    []string
	}{
		{
			name:                "Rewrap not called prior - Call Rewrap",
			expectError:         nil,
			requiredObligations: []string{fakeObligationFQN},
		},
		{
			name:                   "Rewrap called - Obligations populated",
			expectError:            nil,
			requiredObligations:    []string{"https://example.com/attr/attr1/value/value1"},
			fulfillableObligations: []string{"https://example.com/attr/attr1/value/value1"},
			populateObligations:    []string{"https://example.com/attr/attr1/value/value1"},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			reader := bytes.NewReader(encryptedPolicyTDF)
			nanoReader, err := sdk.LoadNanoTDF(s.T().Context(), reader, WithNanoTDFFulfillableObligationFQNs(tc.fulfillableObligations), WithNanoIgnoreAllowlist(true))
			s.Require().NoError(err)
			// Check that it has fulfillable obligations set
			if len(tc.fulfillableObligations) > 0 {
				s.Require().NotNil(nanoReader.config.fulfillableObligationFQNs)
				s.Require().Equal(tc.fulfillableObligations, nanoReader.config.fulfillableObligationFQNs)
			} else {
				s.Require().Empty(nanoReader.config.fulfillableObligationFQNs)
			}

			if tc.populateObligations != nil {
				nanoReader.requiredObligations = &RequiredObligations{FQNs: tc.populateObligations}
			}

			// Initialize the reader (this will parse the header)
			obl, err := nanoReader.Obligations(s.T().Context())
			if tc.expectError != nil {
				s.Require().Error(err)
				s.Require().Empty(obl.FQNs)
				s.Require().ErrorIs(err, tc.expectError)
				return
			}
			s.Require().NoError(err)
			s.Require().Equal(tc.requiredObligations, obl.FQNs)

			// Call again to verify caching
			obl, err = nanoReader.Obligations(s.T().Context())
			s.Require().NoError(err)
			s.Require().Equal(tc.requiredObligations, obl.FQNs)
		})
	}
}

func (s *NanoSuite) Test_PolicyBinding_GMAC() {
	// Create test policy data
	policyData := []byte(`{"body":{"dataAttributes":["https://example.com/attr/classification/value/secret"]}}`)

	// Create GMAC binding - need to simulate having GMAC at end of the digest
	gmacBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	// Append GMAC to the digest to simulate real scenario
	policyData = append(policyData, gmacBytes...)

	digest := ocrypto.CalculateSHA256(policyData)

	// For testing, we will use the last bytes as the GMAC binding
	gmacBytes = digest[len(digest)-len(gmacBytes):]

	binding := &gmacPolicyBinding{
		binding: gmacBytes,
		digest:  digest,
	}

	// Test String function
	s.Require().Equal(hex.EncodeToString(gmacBytes), binding.String(), "GMAC hash should return binding data directly")

	// Test Verify function - should pass with correct binding
	valid, err := binding.Verify()
	s.Require().NoError(err)
	s.Require().True(valid, "GMAC binding should be valid when binding matches digest suffix")

	// Test Verify function with wrong binding - should fail
	wrongBinding := &gmacPolicyBinding{
		binding: []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
		digest:  digest,
	}
	valid, err = wrongBinding.Verify()
	s.Require().NoError(err)
	s.Require().False(valid, "GMAC binding should be invalid when binding doesn't match digest suffix")
}

func (s *NanoSuite) Test_PolicyBinding_ECDSA() {
	// Create a test ECDSA key pair
	keyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	s.Require().NoError(err)

	// Create test policy data
	policyData := []byte(`{"body":{"dataAttributes":["https://example.com/attr/classification/value/secret"]}}`)
	digest := ocrypto.CalculateSHA256(policyData)

	// Sign the digest
	r, sBytes, err := ocrypto.ComputeECDSASig(digest, keyPair.PrivateKey)
	s.Require().NoError(err)

	// Get the public key in compressed format
	compressedPubKey, err := ocrypto.CompressedECPublicKey(ocrypto.ECCModeSecp256r1, keyPair.PrivateKey.PublicKey)
	s.Require().NoError(err)

	binding := &ecdsaPolicyBinding{
		r:               r,
		s:               sBytes,
		ephemeralPubKey: compressedPubKey,
		digest:          digest,
		curve:           keyPair.PrivateKey.Curve,
	}

	// Test String function
	expectedHash := string(ocrypto.SHA256AsHex(append(r, sBytes...)))
	s.Require().NotEmpty(binding.String(), "Hash should not be empty")
	s.Require().Equal(expectedHash, binding.String(), "ECDSA hash should be SHA256 of r||s")

	// Test Verify function - should pass with correct signature
	valid, err := binding.Verify()
	s.Require().NoError(err)
	s.Require().True(valid, "ECDSA binding should be valid with correct signature")

	// Test Verify function with wrong signature - should fail
	invalidR := make([]byte, 32)
	invalidS := make([]byte, 32)
	for i := range invalidR {
		invalidR[i] = byte(i)
		invalidS[i] = byte(i + 10)
	}

	wrongBinding := &ecdsaPolicyBinding{
		r:               invalidR,
		s:               invalidS,
		ephemeralPubKey: compressedPubKey,
		digest:          digest,
		curve:           keyPair.PrivateKey.Curve,
	}

	valid, err = wrongBinding.Verify()
	s.Require().NoError(err)
	s.Require().False(valid, "ECDSA binding should be invalid with wrong signature")
}

func (s *NanoSuite) Test_NanoTDFHeader_VerifyPolicyBinding() {
	s.Run("ECDSA Policy Binding Verification", func() {
		// Create a test ECDSA key pair
		keyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
		s.Require().NoError(err)

		// Create test policy data
		policyData := []byte(`{"body":{"dataAttributes":["https://example.com/attr/classification/value/secret"]}}`)
		digest := ocrypto.CalculateSHA256(policyData)

		// Sign the digest
		r, sBytes, err := ocrypto.ComputeECDSASig(digest, keyPair.PrivateKey)
		s.Require().NoError(err)

		// Get compressed public key
		compressedPubKey, err := ocrypto.CompressedECPublicKey(ocrypto.ECCModeSecp256r1, keyPair.PrivateKey.PublicKey)
		s.Require().NoError(err)

		// Create header with ECDSA binding
		header := &NanoTDFHeader{
			bindCfg: bindingConfig{
				useEcdsaBinding: true,
				eccMode:         ocrypto.ECCModeSecp256r1,
			},
			PolicyBody:          policyData,
			EphemeralKey:        compressedPubKey,
			ecdsaPolicyBindingR: r,
			ecdsaPolicyBindingS: sBytes,
		}

		// Test VerifyPolicyBinding method
		valid, err := header.VerifyPolicyBinding()
		s.Require().NoError(err)
		s.Require().True(valid, "ECDSA policy binding should be valid")
	})

	s.Run("GMAC Policy Binding Verification", func() {
		// Create test policy data
		policyData := []byte(`{"body":{"dataAttributes":["https://example.com/attr/classification/value/secret"]}}`)

		// Create GMAC binding - need to simulate having GMAC at end of the digest
		gmacBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		// Append GMAC to the digest to simulate real scenario
		policyData = append(policyData, gmacBytes...)

		digest := ocrypto.CalculateSHA256(policyData)

		// For testing, we will use the last bytes as the GMAC binding
		gmacBytes = digest[len(digest)-len(gmacBytes):]

		// Create header with GMAC binding
		header := &NanoTDFHeader{
			bindCfg: bindingConfig{
				useEcdsaBinding: false,
			},
			PolicyBody:        policyData,
			gmacPolicyBinding: gmacBytes,
		}

		// Test VerifyPolicyBinding method
		valid, err := header.VerifyPolicyBinding()
		s.Require().NoError(err)
		s.Require().True(valid, "GMAC hash should match")
	})

	s.Run("Policy Binding Creation Error", func() {
		// Create header with invalid ECC mode to trigger error in PolicyBinding()
		header := &NanoTDFHeader{
			bindCfg: bindingConfig{
				useEcdsaBinding: true,
				eccMode:         255, // Invalid ECC mode
			},
			PolicyBody: []byte("test"),
		}

		// Test VerifyPolicyBinding method with error case
		valid, err := header.VerifyPolicyBinding()
		s.Require().Error(err)
		s.Require().False(valid)
		s.Require().Contains(err.Error(), "unsupported nanoTDF ecc mode", "Error should be related to curve/ECC mode")
	})
}

// Helper function to create real NanoTDF data for testing
func (s *NanoSuite) createRealNanoTDF(sdk *SDK) ([]byte, error) {
	// Read the test file content
	input := bytes.NewReader([]byte("Virtru!!!!"))
	output := &bytes.Buffer{}

	// Create a NanoTDF config
	config, err := sdk.NewNanoTDFConfig()
	if err != nil {
		return nil, err
	}

	// Set a test KAS URL
	err = config.SetKasURL("https://kas.example.com")
	if err != nil {
		return nil, err
	}

	// Set test attributes
	err = config.SetAttributes([]string{"https://example.com/attr/attr1/value/value1"})
	if err != nil {
		return nil, err
	}

	err = config.SetPolicyMode(NanoTDFPolicyModeDefault)
	if err != nil {
		return nil, err
	}

	// The kasPublicKey will be fetched automatically from the mock HTTP client during CreateNanoTDF

	// Create the NanoTDF
	_, err = sdk.CreateNanoTDF(output, input, *config)
	if err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func (s *NanoSuite) createMockHTTPClient() *http.Client {
	return &http.Client{
		Transport: s.mockTransport,
	}
}

// Helper function to create a properly configured SDK for testing
func (s *NanoSuite) createTestSDK() (*SDK, error) {
	sdk, err := New("http://localhost:8080", WithPlatformConfiguration(PlatformConfiguration{}))
	if err != nil {
		return nil, err
	}

	sdk.conn.Client = s.createMockHTTPClient()
	sdk.conn.Options = []connect.ClientOption{connect.WithProtoJSON()}
	sdk.tokenSource = getTokenSource(s.T())

	return sdk, nil
}

func newMockTransport() *mockTransport {
	// Generate a consistent KAS key pair for the mock
	kasKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate KAS key pair: %v", err))
	}

	publicKeyPEM, err := kasKeyPair.PublicKeyInPemFormat()
	if err != nil {
		panic(fmt.Sprintf("Failed to get public key PEM: %v", err))
	}

	return &mockTransport{
		publicKey:  publicKeyPEM,
		kid:        "e1",
		kasKeyPair: kasKeyPair,
	}
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if this is a PublicKey request to KAS
	if strings.Contains(req.URL.Path, "/kas.AccessService/PublicKey") {
		// Create a mock PublicKeyResponse in the format expected by Connect RPC
		response := &kas.PublicKeyResponse{
			PublicKey: m.publicKey,
			Kid:       m.kid,
		}

		// Marshal the response to JSON using Connect protocol format
		responseJSON, err := json.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal mock response: %w", err)
		}

		// Create a mock HTTP response
		resp := &http.Response{
			Status:     http.StatusText(http.StatusOK),
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body:          io.NopCloser(bytes.NewReader(responseJSON)),
			ContentLength: int64(len(responseJSON)),
			Request:       req,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
		}

		return resp, nil
	}

	// Check if this is a Rewrap request to KAS
	if strings.Contains(req.URL.Path, "/kas.AccessService/Rewrap") {
		return m.handleRewrapRequest(req)
	}

	// For any other requests, return an error
	return nil, fmt.Errorf("unexpected request to %s", req.URL.String())
}

// handleRewrapRequest handles mock rewrap requests for testing
func (m *mockTransport) handleRewrapRequest(req *http.Request) (*http.Response, error) {
	// Read the request body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Parse the Connect RPC request
	var bodyJSON map[string]interface{}
	err = json.Unmarshal(bodyBytes, &bodyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	// Extract the signed request token
	signedRequestToken, ok := bodyJSON["signedRequestToken"].(string)
	if !ok {
		return nil, errors.New("missing signedRequestToken in request")
	}

	// Parse the JWT token without verification (for testing)
	token, err := jwt.ParseString(signedRequestToken, jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract the request body from the JWT
	requestBodyClaim, ok := token.Get("requestBody")
	if !ok {
		return nil, errors.New("missing requestBody in JWT")
	}

	requestBodyJSON, ok := requestBodyClaim.(string)
	if !ok {
		return nil, errors.New("requestBody is not a string")
	}

	// Parse the unsigned rewrap request
	var unsignedReq kas.UnsignedRewrapRequest
	err = protojson.Unmarshal([]byte(requestBodyJSON), &unsignedReq)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal unsigned request: %w", err)
	}

	// Get the client's public key (for the rewrap session key)
	clientPublicKeyPEM := unsignedReq.GetClientPublicKey()

	// Extract the NanoTDF header from the KeyAccessObject to get the ephemeral public key
	if len(unsignedReq.GetRequests()) == 0 || len(unsignedReq.GetRequests()[0].GetKeyAccessObjects()) == 0 {
		return nil, errors.New("no key access objects in request")
	}

	headerBuf := unsignedReq.GetRequests()[0].GetKeyAccessObjects()[0].GetKeyAccessObject().GetHeader()
	if len(headerBuf) == 0 {
		return nil, errors.New("no header in key access object")
	}

	// Parse the NanoTDF header to extract the ephemeral public key
	headerReader := bytes.NewReader(headerBuf)
	nanoHeader, _, err := NewNanoTDFHeaderFromReader(headerReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NanoTDF header: %w", err)
	}

	// Get the KAS private key for ECDH computation
	kasPrivateKeyForECDH, err := m.kasKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("failed to get KAS private key: %w", err)
	}

	// Convert ephemeral public key to PEM format for ECDH computation
	curve, err := nanoHeader.ECCurve()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECC curve: %w", err)
	}

	ephemeralPublicKey, err := ocrypto.UncompressECPubKey(curve, nanoHeader.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress ephemeral public key: %w", err)
	}

	// Convert to PEM format using the same method as the real KAS service
	derBytes, err := x509.MarshalPKIXPublicKey(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	ephemeralPublicKeyPEM := pem.EncodeToMemory(pemBlock)

	// Compute ECDH shared secret between KAS private key and ephemeral public key
	// This recreates the symmetric key that was used during NanoTDF creation
	ecdhSharedSecret, err := ocrypto.ComputeECDHKey([]byte(kasPrivateKeyForECDH), ephemeralPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}

	// Derive the symmetric key using the same process as createNanoTDFSymmetricKey
	originalSymmetricKey, err := ocrypto.CalculateHKDF(versionSalt(), ecdhSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	// Now generate a new ephemeral key pair for the rewrap session
	rewrapKasKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rewrap KAS key pair: %w", err)
	}

	rewrapKasPublicKeyPEM, err := rewrapKasKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("failed to get rewrap KAS public key PEM: %w", err)
	}

	rewrapKasPrivateKeyPEM, err := rewrapKasKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("failed to get rewrap KAS private key PEM: %w", err)
	}

	// Compute ECDH shared secret between client's rewrap public key and new KAS ephemeral private key
	rewrapEcdhKey, err := ocrypto.ComputeECDHKey([]byte(rewrapKasPrivateKeyPEM), []byte(clientPublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to compute rewrap ECDH key: %w", err)
	}

	// Derive session key using HKDF with version salt
	sessionKey, err := ocrypto.CalculateHKDF(versionSalt(), rewrapEcdhKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate rewrap session key: %w", err)
	}

	// Create AES-GCM encryptor with session key
	encryptor, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM encryptor: %w", err)
	}

	// Encrypt the original symmetric key with the rewrap session key
	wrappedKey, err := encryptor.Encrypt(originalSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	// Build the rewrap response
	rewrapResponse := &kas.RewrapResponse{
		SessionPublicKey: rewrapKasPublicKeyPEM,
		Responses: []*kas.PolicyRewrapResult{
			{
				PolicyId: "policy",
				Results: []*kas.KeyAccessRewrapResult{
					{
						KeyAccessObjectId: "kao-0",
						Status:            "permit",
						Result: &kas.KeyAccessRewrapResult_KasWrappedKey{
							KasWrappedKey: wrappedKey,
						},
						Metadata: createMetadataWithObligations([]string{fakeObligationFQN}),
					},
				},
			},
		},
	}

	// Marshal the response
	responseJSON, err := protojson.Marshal(rewrapResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rewrap response: %w", err)
	}

	// Create HTTP response
	resp := &http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:          io.NopCloser(bytes.NewReader(responseJSON)),
		ContentLength: int64(len(responseJSON)),
		Request:       req,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
	}

	return resp, nil
}
