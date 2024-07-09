package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	wellknownpb "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	oneKB = 1024
	// tenKB     = 10 * oneKB
	oneMB     = 1024 * 1024
	hundredMB = 100 * oneMB
	oneGB     = 10 * hundredMB
	// tenGB     = 10 * oneGB
)

const (
	stepSize int64 = 2 * oneMB
	char           = 'a'
)

type tdfTest struct {
	fileSize    int64
	tdfFileSize float64
	checksum    string
	mimeType    string
}

const (
	mockRSAPublicKey1 = `-----BEGIN CERTIFICATE-----
MIICmDCCAYACCQC3BCaSANRhYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANr
YXMwHhcNMjEwOTE1MTQxMTQ4WhcNMjIwOTE1MTQxMTQ4WjAOMQwwCgYDVQQDDANr
YXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOpiotrvV2i5h6clHM
zDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9ExyczB
WJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp41r/T
1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim86Haw
u/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3TfOEvX
F6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU54Zz
DaLZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABewfZOJ4/KNRE8IQ5TsW/AVn7C1
l5ty6tUUBSVi8/df7WYts0bHEdQh9yl9agEU5i4rj43y8vMVZNzSeHcurtV/+C0j
fbkHQHeiQ1xn7cq3Sbh4UVRyuu4C5PklEH4AN6gxmgXC3kT15uWw8I4nm/plzYLs
I099IoRfC5djHUYYLMU/VkOIHuPC3sb7J65pSN26eR8bTMVNagk187V/xNwUuvkf
+NUxDO615/5BwQKnAu5xiIVagYnDZqKCOtYS5qhxF33Nlnwlm7hH8iVZ1RI+n52l
wVyElqp317Ksz+GtTIc+DE6oryxK3tZd4hrj9fXT4KiJvQ4pcRjpePgH7B8=
-----END CERTIFICATE-----`

	mockRSAPrivateKey1 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOpiotrvV2i5h6
clHMzDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9Ex
yczBWJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp4
1r/T1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim8
6Hawu/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3Tf
OEvXF6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU
54ZzDaLZAgMBAAECggEBALb0yK0PlMUyzHnEUwXV1y5AIoAWhsYp0qvJ1msHUVKz
+yQ/VJz4+tQQxI8OvGbbnhNkd5LnWdYkYzsIZl7b/kBCPcQw3Zo+4XLCzhUAn1E1
M+n42c8le1LtN6Z7mVWoZh7DPONy7t+ABvm7b7S1+1i78DPmgCeWYZGeAhIcPXG6
5AxWIV3jigxksE6kYY9Y7DmtsZgMRrdV7SU8VtgPtT7tua8z5/U3Av0WINyKBSoM
0yDHsAg57KnM8znx2JWLtHd0Mk5bBuu2DLbtyKNrVUAUuMPzrLGBh9S9QRd934KU
uFAi1TEfgEachnGgSHJpzVzr2ur1tifABnQ7GNXObe0CgYEA6KowK0subdDY+uGW
ciP2XDAMerbJJeL0/UIGPb/LUmskniio2493UBGgY2FsRyvbzJ+/UAOjIPyIxhj7
78ZyVG8BmIzKan1RRVh//O+5yvks/eTOYjWeQ1Lcgqs3q4YAO13CEBZgKWKTUomg
mskFJq04tndeSIyhDaW+BuWaXA8CgYEA42ABz3pql+DH7oL5C4KYBymK6wFBBOqk
dVk+ftyJQ6PzuZKpfsu4aPIjKm71lkTgK6O9o08s3SckAdu6vLukq2TZFF+a+9OI
lu5ww7GvfdMTgLAaFchD4bPlOInh1KVjBc1MwGXpl0ROde5pi8+WUrv9QJuoQfB/
4rhYdbJLSpcCgYA41mqSCPm8pgp7r2RbWeGzP6Gs0L5u3PTQcbKonxQCfF4jrPcj
O/b/vm6aGJClClfVsyi/WUQeqNKY4j2Zo7cGXV/cbnh8b0TNVgNePQn8Rcbx91Vb
tJGHDNUFruIYqtGfrxXbbDvtoEExJqHvbjAt9J8oJB0KSCCH/vdfI/QDjQKBgQCD
xLPH5Y24js/O7aAeh4RLQkv7fTKNAt5kE2AgbPYveOhZ9yC7Fpy8VPcENGGmwCuZ
nr7b0ZqSX4iCezBxB92aZktXf0B2CFT0AyLehi7JoHWA8o1rai/MsVB5v45ciawl
RKDiLy18OF2wAoawO5FGSSOvOYX9EL9MSMEbFESF6QKBgCVlZ9pPC+55rGT6AcEL
tUpDs+/wZvcmfsFd8xC5mMUN0DatAVzVAUI95+tQaWU3Uj+bqHq0lC6Wy2VceG0D
D+7EicjdGFN/2WVPXiYX1fblkxasZY+wChYBrPLjA9g0qOzzmXbRBph5QxDuQjJ6
qcddVKB624a93ZBssn7OivnR
-----END PRIVATE KEY-----`
)

var testHarnesses = []tdfTest{ //nolint:gochecknoglobals // requires for testing tdf
	{
		fileSize:    5,
		tdfFileSize: 1557,
		checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
	},
	{
		fileSize:    5,
		tdfFileSize: 1557,
		checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		mimeType:    "text/plain",
	},
	{
		fileSize:    oneKB,
		tdfFileSize: 2581,
		checksum:    "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
	},
	{
		fileSize:    hundredMB,
		tdfFileSize: 104866410,
		checksum:    "cee41e98d0a6ad65cc0ec77a2ba50bf26d64dc9007f7f1c7d7df68b8b71291a6",
	},
	{
		fileSize:    5 * hundredMB,
		tdfFileSize: 524324210,
		checksum:    "d2fb707e70a804cf2ea770c9229295689831b4c88879c62bdb966e77e7336f18",
	},
}

type TestReadAt struct {
	segmentSize     int64
	dataOffset      int64
	dataLength      int
	expectedPayload string
}

type partialReadTdfTest struct {
	payload     string
	kasInfoList []KASInfo
	readAtTests []TestReadAt
}

const testPayload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var partialTDFTestHarnesses = []partialReadTdfTest{ //nolint:gochecknoglobals // requires for testing tdf
	{
		payload: testPayload, // len: 62
		kasInfoList: []KASInfo{
			{
				URL:       "http://localhost:65432/api/kas",
				PublicKey: mockRSAPublicKey1,
			},
			{
				URL:       "http://localhost:65432/api/kas",
				PublicKey: mockRSAPublicKey1,
			},
		},
		readAtTests: []TestReadAt{
			{
				segmentSize:     2,
				dataOffset:      26,
				dataLength:      26,
				expectedPayload: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			},
			{
				segmentSize:     2 * oneMB,
				dataOffset:      61,
				dataLength:      1,
				expectedPayload: "9",
			},
			{
				segmentSize:     2,
				dataOffset:      0,
				dataLength:      62,
				expectedPayload: testPayload,
			},
			{
				segmentSize:     int64(len(testPayload)),
				dataOffset:      0,
				dataLength:      len(testPayload),
				expectedPayload: testPayload,
			},
			{
				segmentSize:     1,
				dataOffset:      26,
				dataLength:      26,
				expectedPayload: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			},
		},
	},
}

var buffer []byte //nolint:gochecknoglobals // for testing

func init() {
	// create a buffer and write with 0xff
	buffer = make([]byte, stepSize)
	for index := 0; index < len(buffer); index++ {
		buffer[index] = char
	}
}

type TDFSuite struct {
	suite.Suite
	tcTerminate func()
	sdk         *SDK
	kas         FakeKas
}

func (s *TDFSuite) SetupSuite() {
	// Set up the test environment
	s.startBackend()
}

func (s *TDFSuite) TearDownSuite() {
	// Tear down the test environment
	s.tcTerminate()
}

func TestTDF(t *testing.T) {
	suite.Run(t, new(TDFSuite))
}

func (s *TDFSuite) Test_SimpleTDF() {
	metaData := []byte(`{"displayName" : "openTDF go sdk"}`)
	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	assertions := []Assertion{
		{
			ID:           "assertion1",
			Type:         handlingAssertion.String(),
			Scope:        trustedDataObj.String(),
			AppliedState: unencrypted.String(),
			Statement: Statement{
				Format: Base64BinaryStatement.String(),
				Value:  "ICAgIDxlZGoOkVkaD4=",
			},
		},
		{
			ID:           "assertion2",
			Type:         baseAssertion.String(),
			Scope:        trustedDataObj.String(),
			AppliedState: unencrypted.String(),
			Statement: Statement{
				Format: Base64BinaryStatement.String(),
				Value:  "ICAgIDxlZGoOkVkaD4=",
			},
			Binding: Binding{
				Method:    JWT.String(),
				Signature: "ICAgIDxlZGoOkVkaD4=",
			},
		},
	}

	expectedTdfSize := int64(2577)
	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"
	{
		kasURLs := []KASInfo{
			{
				URL:       "http://localhost:65432/",
				PublicKey: "",
			},
		}

		inBuf := bytes.NewBufferString(plainText)
		bufReader := bytes.NewReader(inBuf.Bytes())

		fileWriter, err := os.Create(tdfFilename)
		s.Require().NoError(err)

		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			s.Require().NoError(err)
		}(fileWriter)

		tdfObj, err := s.sdk.CreateTDF(fileWriter, bufReader,
			WithKasInformation(kasURLs...),
			WithMetaData(string(metaData)),
			WithDataAttributes(attributes...),
			WithAssertions(assertions...))

		s.Require().NoError(err)
		s.InDelta(float64(expectedTdfSize), float64(tdfObj.size), 32.0)
	}

	// test meta data
	{
		readSeeker, err := os.Open(tdfFilename)
		s.Require().NoError(err)

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			s.Require().NoError(err)
		}(readSeeker)

		r, err := s.sdk.LoadTDF(readSeeker)
		s.Require().NoError(err)

		unencryptedMetaData, err := r.UnencryptedMetadata()
		s.Require().NoError(err)

		s.EqualValues(metaData, unencryptedMetaData)

		dataAttributes, err := r.DataAttributes()
		s.Require().NoError(err)

		s.Equal(attributes, dataAttributes)
	}

	// test reader
	{
		readSeeker, err := os.Open(tdfFilename)
		s.Require().NoError(err)

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			s.Require().NoError(err)
		}(readSeeker)

		buf := make([]byte, 8)

		r, err := s.sdk.LoadTDF(readSeeker)
		s.Require().NoError(err)

		offset := 2
		n, err := r.ReadAt(buf, int64(offset))
		if err != nil {
			s.Require().ErrorIs(err, io.EOF)
		}

		expectedPlainTxt := plainText[offset : offset+n]
		s.Equal(expectedPlainTxt, string(buf[:n]))
	}

	_ = os.Remove(tdfFilename)
}

func (s *TDFSuite) Test_TDFReader() { //nolint:gocognit // requires for testing tdf
	for _, test := range partialTDFTestHarnesses { // create .txt file
		kasInfoList := test.kasInfoList

		// reset public keys so we have to get them from the service
		for index := range kasInfoList {
			kasInfoList[index].PublicKey = ""
		}

		for _, readAtTest := range test.readAtTests {
			tdfBuf := bytes.Buffer{}
			readSeeker := bytes.NewReader([]byte(test.payload))
			_, err := s.sdk.CreateTDF(
				io.Writer(&tdfBuf),
				readSeeker,
				WithKasInformation(kasInfoList...),
				WithSegmentSize(readAtTest.segmentSize),
			)
			s.Require().NoError(err)

			// test reader
			tdfReadSeeker := bytes.NewReader(tdfBuf.Bytes())
			r, err := s.sdk.LoadTDF(tdfReadSeeker)
			s.Require().NoError(err)

			rbuf := make([]byte, readAtTest.dataLength)
			n, err := r.ReadAt(rbuf, readAtTest.dataOffset)
			s.Require().NoError(err)

			s.Equal(readAtTest.dataLength, n)
			s.Equal(readAtTest.expectedPayload, string(rbuf))

			// Test Read
			plainTextFile := "text.txt"
			{
				fileWriter, err := os.Create(plainTextFile)
				s.Require().NoError(err)

				defer func(fileWriter *os.File) {
					err := fileWriter.Close()
					s.Require().NoError(err)
				}(fileWriter)

				_, err = io.Copy(fileWriter, r)
				s.Require().NoError(err)
			}

			fileData, err := os.ReadFile(plainTextFile)
			s.Require().NoError(err)

			s.Equal(test.payload, string(fileData))

			_ = os.Remove(plainTextFile)
		}
	}
}

func (s *TDFSuite) Test_TDF() {
	for index, test := range testHarnesses {
		// create .txt file
		plaintTextFileName := strconv.Itoa(index) + ".txt"
		tdfFileName := plaintTextFileName + ".tdf"
		decryptedTdfFileName := tdfFileName + ".txt"

		kasInfoList := []KASInfo{
			s.kas.KASInfo,
		}
		kasInfoList[0].PublicKey = ""

		// test encrypt
		testEncrypt(s.T(), s.sdk, kasInfoList, plaintTextFileName, tdfFileName, test)

		// test decrypt with reader
		testDecryptWithReader(s.T(), s.sdk, tdfFileName, decryptedTdfFileName, test)

		// Remove the test files
		_ = os.Remove(plaintTextFileName)
		_ = os.Remove(tdfFileName)
	}
}

// create tdf
func testEncrypt(t *testing.T, sdk *SDK, kasInfoList []KASInfo, plainTextFilename, tdfFileName string, test tdfTest) {
	// create a plain text file
	createFileName(buffer, plainTextFilename, test.fileSize)

	// open file
	readSeeker, err := os.Open(plainTextFilename)
	require.NoError(t, err)

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		require.NoError(t, err)
	}(readSeeker)

	fileWriter, err := os.Create(tdfFileName)
	require.NoError(t, err)

	defer func(fileWriter *os.File) {
		err := fileWriter.Close()
		require.NoError(t, err)
	}(fileWriter) // CreateTDF TDFConfig
	var options []TDFOption
	if test.mimeType != "" {
		options = []TDFOption{
			WithKasInformation(kasInfoList...),
			WithMimeType(test.mimeType),
		}
	} else {
		options = []TDFOption{
			WithKasInformation(kasInfoList...),
		}
	}
	tdfObj, err := sdk.CreateTDF(fileWriter, readSeeker, options...)
	require.NoError(t, err)

	assert.InDelta(t, float64(test.tdfFileSize), float64(tdfObj.size), .04*float64(test.tdfFileSize))
}

func testDecryptWithReader(t *testing.T, sdk *SDK, tdfFile, decryptedTdfFileName string, test tdfTest) {
	readSeeker, err := os.Open(tdfFile)
	require.NoError(t, err)

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		require.NoError(t, err)
	}(readSeeker)

	r, err := sdk.LoadTDF(readSeeker)
	require.NoError(t, err)

	if test.mimeType != "" {
		assert.Equal(t, test.mimeType, r.Manifest().Payload.MimeType, "mimeType does not match")
	}

	{
		fileWriter, err := os.Create(decryptedTdfFileName)
		require.NoError(t, err)

		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			require.NoError(t, err)
		}(fileWriter)

		_, err = io.Copy(fileWriter, r)
		require.NoError(t, err)
	}

	res := checkIdentical(t, decryptedTdfFileName, test.checksum)
	assert.True(t, res, "decrypted text didn't match plain text")

	var bufSize int64 = 5
	buf := make([]byte, bufSize)
	resultBuf := bytes.Repeat([]byte{char}, int(bufSize))

	// read last 5 bytes
	n, err := r.ReadAt(buf, test.fileSize-(bufSize))
	if err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	assert.Equal(t, resultBuf[:n], buf[:n], "decrypted text didn't match plain text with ReadAt interface")

	_ = os.Remove(decryptedTdfFileName)
}

func createFileName(buf []byte, filename string, size int64) {
	f, err := os.Create(filename)
	if err != nil {
		panic(fmt.Sprintf("os.CreateTDF failed: %v", err))
	}

	totalBytes := size
	var bytesToWrite int64
	for totalBytes > 0 {
		if totalBytes >= stepSize {
			totalBytes -= stepSize
			bytesToWrite = stepSize
		} else {
			bytesToWrite = totalBytes
			totalBytes = 0
		}
		_, err := f.Write(buf[:bytesToWrite])
		if err != nil {
			panic(fmt.Sprintf("io.Write failed: %v", err))
		}
	}
	err = f.Close()
	if err != nil {
		panic(fmt.Sprintf("os.Close failed: %v", err))
	}
}

func (s *TDFSuite) startBackend() {
	// Create a stub for wellknown
	wellknownCfg := map[string]interface{}{
		"configuration": map[string]interface{}{
			"health": map[string]interface{}{
				"endpoint": "/healthz",
			},
			"platform_issuer": "http://localhost:65432/auth",
		},
	}

	fwk := &FakeWellKnown{v: wellknownCfg}

	grpcListener := bufconn.Listen(1024 * 1024)

	grpcServer := grpc.NewServer()
	s.kas = FakeKas{privateKey: mockRSAPrivateKey1, KASInfo: KASInfo{
		URL: "http://localhost:65432/", PublicKey: mockRSAPublicKey1, KID: "r1", Algorithm: "rsa:2048"},
	}
	kaspb.RegisterAccessServiceServer(grpcServer, &s.kas)
	wellknownpb.RegisterWellKnownServiceServer(grpcServer, fwk)
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			panic(fmt.Sprintf("failed to serve: %v", err))
		}
	}()
	dialer := func(ctx context.Context, host string) (net.Conn, error) {
		slog.InfoContext(ctx, "dialing with custom dialer (local grpc)", "ctx", ctx, "host", host)
		return grpcListener.Dial()
	}

	ats := getTokenSource(s.T())

	sdk, err := New("localhost:65432",
		WithClientCredentials("test", "test", nil),
		withCustomAccessTokenSource(&ats),
		WithTokenEndpoint("http://localhost:65432/auth/token"),
		WithInsecurePlaintextConn(),
		WithExtraDialOptions(grpc.WithContextDialer(dialer)))
	if err != nil {
		panic(fmt.Sprintf("error creating SDK with authconfig: %v", err))
	}
	s.sdk = sdk

	s.tcTerminate = func() {
		slog.Info("terminando")
	}
}

type FakeWellKnown struct {
	wellknownpb.UnimplementedWellKnownServiceServer
	v map[string]interface{}
}

func (f *FakeWellKnown) GetWellKnownConfiguration(_ context.Context, _ *wellknownpb.GetWellKnownConfigurationRequest) (*wellknownpb.GetWellKnownConfigurationResponse, error) {
	cfg, err := structpb.NewStruct(f.v)
	if err != nil {
		return nil, err
	}

	return &wellknownpb.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}, nil
}

type FakeKas struct {
	kaspb.UnimplementedAccessServiceServer
	KASInfo
	privateKey string
}

func (f *FakeKas) Rewrap(_ context.Context, in *kaspb.RewrapRequest) (*kaspb.RewrapResponse, error) {
	signedRequestToken := in.GetSignedRequestToken()

	token, err := jwt.ParseInsecure([]byte(signedRequestToken))
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseInsecure failed: %w", err)
	}

	requestBody, found := token.Get("requestBody")
	if !found {
		return nil, fmt.Errorf("requestBody not found in token")
	}

	requestBodyStr, ok := requestBody.(string)
	if !ok {
		return nil, fmt.Errorf("requestBody not a string")
	}
	entityWrappedKey := f.getRewrappedKey(requestBodyStr)

	return &kaspb.RewrapResponse{EntityWrappedKey: entityWrappedKey}, nil
}

func (f *FakeKas) PublicKey(_ context.Context, _ *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	return &kaspb.PublicKeyResponse{PublicKey: f.KASInfo.PublicKey, Kid: f.KID}, nil
}

func (f *FakeKas) getRewrappedKey(rewrapRequest string) []byte {
	bodyData := RequestBody{}
	err := json.Unmarshal([]byte(rewrapRequest), &bodyData)
	if err != nil {
		panic(fmt.Sprintf("json.Unmarshal failed: %v", err))
	}
	wrappedKey, err := ocrypto.Base64Decode([]byte(bodyData.WrappedKey))
	if err != nil {
		panic(fmt.Sprintf("ocrypto.Base64Decode failed: %v", err))
	}
	kasPrivateKey := strings.ReplaceAll(f.privateKey, "\n\t", "\n")
	asymDecrypt, err := ocrypto.NewAsymDecryption(kasPrivateKey)
	if err != nil {
		panic(fmt.Sprintf("ocrypto.NewAsymDecryption failed: %v", err))
	}
	symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
	if err != nil {
		panic(fmt.Sprintf("ocrypto.Decrypt failed: %v", err))
	}
	asymEncrypt, err := ocrypto.NewAsymEncryption(bodyData.ClientPublicKey)
	if err != nil {
		panic(fmt.Sprintf("ocrypto.NewAsymEncryption failed: %v", err))
	}
	entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
	if err != nil {
		panic(fmt.Sprintf("ocrypto.encrypt failed: %v", err))
	}
	return entityWrappedKey
}

func checkIdentical(t *testing.T, file, checksum string) bool {
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("os.Open failed: %v", err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			t.Fatalf("f.Close failed: %v", err)
		}
	}(f)

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("io.Copy failed: %v", err)
	}
	c := h.Sum(nil)

	// slog.Info(fmt.Sprintf("%x", c))
	return checksum == fmt.Sprintf("%x", c)
}
