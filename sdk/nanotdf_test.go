package sdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	nanoFakePem = "pem"
)

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
}

func TestNanoTDF(t *testing.T) {
	suite.Run(t, new(NanoSuite))
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
