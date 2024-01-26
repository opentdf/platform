package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const (
	oneKB = 1024
	// tenKB     = 10 * oneKB
	oneMB     = 1024 * 1024
	hundredMB = 100 * oneMB
	// oneGB     = 10 * hundredMB
	// tenGB     = 10 * oneGB
)

const (
	stepSize int64 = 2 * oneMB
)

type tdfTest struct {
	fileSize    int64
	tdfFileSize int64
	kasInfoList []KASInfo
}

//nolint:gochecknoglobals
var mockKasPublicKey = `-----BEGIN CERTIFICATE-----
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

//nolint:gochecknoglobals
var mockKasPrivateKey = `-----BEGIN PRIVATE KEY-----
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

var testHarnesses = []tdfTest{ //nolint:gochecknoglobals
	{
		fileSize:    5,
		tdfFileSize: 1580,
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: "",
			},
		},
	},
	{
		fileSize:    oneKB,
		tdfFileSize: 2604,
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: "",
			},
		},
	},
	{
		fileSize:    hundredMB,
		tdfFileSize: 104866456,
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: mockKasPublicKey,
			},
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: mockKasPublicKey,
			},
		},
	},
}

var buffer []byte //nolint:gochecknoglobals

func init() {
	// create a buffer and write with 0xff
	buffer = make([]byte, stepSize)
	for index := 0; index < len(buffer); index++ {
		buffer[index] = 'a'
	}
}

func TestSimpleTDF(t *testing.T) {
	server, signingPubKey, signingPrivateKey := runKas(t)
	defer server.Close()

	metaDataStr := `{"displayName" : "openTDF go sdk"}`

	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	expectedTdfSize := int64(1989)
	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"
	{
		// Create TDFConfig
		tdfConfig, err := NewTDFConfig()
		if err != nil {
			t.Fatalf("Fail to create tdf config: %v", err)
		}

		kasURLs := []KASInfo{
			{
				url:       server.URL,
				publicKey: "",
			},
		}

		err = tdfConfig.AddKasInformation(kasURLs)
		if err != nil {
			t.Fatalf("tdfConfig.AddKasUrls failed: %v", err)
		}

		tdfConfig.SetMetaData(metaDataStr)
		tdfConfig.AddAttributes(attributes)

		inBuf := bytes.NewBufferString(plainText)
		bufReader := bytes.NewReader(inBuf.Bytes())

		fileWriter, err := os.Create(tdfFilename)
		if err != nil {
			t.Fatalf("os.Create failed: %v", err)
		}
		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			if err != nil {
				t.Fatalf("Fail to close the file: %v", err)
			}
		}(fileWriter)

		tdfSize, err := Create(*tdfConfig, bufReader, fileWriter)
		if err != nil {
			t.Fatalf("tdf.Create failed: %v", err)
		}

		if tdfSize != expectedTdfSize {
			t.Errorf("tdf size test failed expected %v, got %v", tdfSize, expectedTdfSize)
		}
	}

	// test meta data
	{
		readSeeker, err := os.Open(tdfFilename)
		if err != nil {
			t.Fatalf("Fail to open archive file:%s %v", tdfFilename, err)
		}

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file:%v", err)
			}
		}(readSeeker)

		// create auth config
		authConfig, err := NewAuthConfig()
		if err != nil {
			t.Fatalf("Fail to close archive file:%v", err)
		}

		// override the signing keys to get the mock working.
		authConfig.signingPublicKey = signingPubKey
		authConfig.signingPrivateKey = signingPrivateKey

		metaData, err := GetMetadata(*authConfig, readSeeker)
		if err != nil {
			t.Fatalf("Fail to get meta data from tdf:%v", err)
		}

		if metaDataStr != metaData {
			t.Errorf("meta data test failed expected %v, got %v", metaDataStr, metaData)
		}

		dataAttributes, err := GetAttributes(readSeeker)
		if err != nil {
			t.Fatalf("Fail to get policy from tdf:%v", err)
		}

		if reflect.DeepEqual(attributes, dataAttributes) != true {
			t.Errorf("attributes test failed expected %v, got %v", attributes, dataAttributes)
		}
	}

	// test decrypt
	{
		readSeeker, err := os.Open(tdfFilename)
		if err != nil {
			t.Fatalf("Fail to open archive file:%s %v", tdfFilename, err)
		}

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			if err != nil {
				t.Fatalf("Fail to close archive file:%v", err)
			}
		}(readSeeker)

		// writer
		var buf bytes.Buffer
		// create auth config
		authConfig, err := NewAuthConfig()
		if err != nil {
			t.Fatalf("Fail to close archive file:%v", err)
		}

		// override the signing keys to get the mock working.
		authConfig.signingPublicKey = signingPubKey
		authConfig.signingPrivateKey = signingPrivateKey

		payloadSize, err := GetPayload(*authConfig, readSeeker, &buf)
		if err != nil {
			t.Fatalf("Fail to decrypt tdf:%v", err)
		}

		if string(buf.Bytes()[:payloadSize]) != plainText {
			t.Errorf("decrypt test failed expected %v, got %v", plainText, buf.String())
		}
	}

	_ = os.Remove(tdfFilename)
}

func TestTDF(t *testing.T) {
	server, signingPubKey, signingPrivateKey := runKas(t)
	defer server.Close()

	for index, test := range testHarnesses { // create .txt file
		plaintTextFileName := strconv.Itoa(index) + ".txt"
		tdfFileName := plaintTextFileName + ".tdf"
		decryptedTdfFileName := tdfFileName + ".txt"

		kasInfoList := test.kasInfoList
		for index := range kasInfoList {
			kasInfoList[index].url = server.URL
			kasInfoList[index].publicKey = ""
		}

		tdfConfig, err := NewTDFConfig()
		if err != nil {
			t.Fatalf("Fail to create tdf config: %v", err)
		}

		err = tdfConfig.AddKasInformation(kasInfoList)
		if err != nil {
			t.Fatalf("tdfConfig.AddKasUrls failed: %v", err)
		}

		// test encrypt
		testEncrypt(t, *tdfConfig, plaintTextFileName, tdfFileName, test)

		// create auth config
		authConfig, err := NewAuthConfig()
		if err != nil {
			t.Fatalf("Fail to close archive file:%v", err)
		}

		// override the signing keys to get the mock working.
		authConfig.signingPublicKey = signingPubKey
		authConfig.signingPrivateKey = signingPrivateKey

		// test decrypt
		testDecrypt(t, *authConfig, tdfFileName, decryptedTdfFileName, test.fileSize)

		// Remove the test files
		_ = os.Remove(plaintTextFileName)
		_ = os.Remove(tdfFileName)
		_ = os.Remove(decryptedTdfFileName)
	}
}

// create tdf
func testEncrypt(t *testing.T, tdfConfig TDFConfig, plainTextFilename, tdfFileName string, test tdfTest) {
	// create a plain text file
	createFileName(t, buffer, plainTextFilename, test.fileSize)

	// open file
	readSeeker, err := os.Open(plainTextFilename)
	if err != nil {
		t.Fatalf("Fail to open plain text file:%s %v", plainTextFilename, err)
	}

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		if err != nil {
			t.Fatalf("Fail to close plain text file:%v", err)
		}
	}(readSeeker)

	fileWriter, err := os.Create(tdfFileName)

	if err != nil {
		t.Fatalf("os.Create failed: %v", err)
	}
	defer func(fileWriter *os.File) {
		err := fileWriter.Close()
		if err != nil {
			t.Fatalf("Fail to close the tdf file: %v", err)
		}
	}(fileWriter) // Create TDFConfig
	tdfSize, err := Create(tdfConfig, readSeeker, fileWriter)
	if err != nil {
		t.Fatalf("tdf.Create failed: %v", err)
	}

	if tdfSize != test.tdfFileSize {
		t.Errorf("tdf size test failed expected %v, got %v", test.tdfFileSize, tdfSize)
	}
}

func testDecrypt(t *testing.T, authConfig AuthConfig, tdfFile, decryptedTdfFileName string, payloadSize int64) {
	readSeeker, err := os.Open(tdfFile)
	if err != nil {
		t.Fatalf("Fail to open archive file:%s %v", tdfFile, err)
	}

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		if err != nil {
			t.Fatalf("Fail to close archive file:%v", err)
		}
	}(readSeeker)

	fileWriter, err := os.Create(decryptedTdfFileName)
	if err != nil {
		t.Fatalf("os.Create failed: %v", err)
	}

	defer func(fileWriter *os.File) {
		err := fileWriter.Close()
		if err != nil {
			t.Fatalf("Fail to close the file: %v", err)
		}
	}(fileWriter) // Create TDFConfig

	decryptedData, err := GetPayload(authConfig, readSeeker, fileWriter)
	if err != nil {
		t.Fatalf("tdf.Create failed: %v", err)
	}

	if payloadSize != decryptedData {
		t.Errorf("payload size test failed expected %v, got %v", payloadSize, decryptedData)
	}
}

func createFileName(t *testing.T, buf []byte, filename string, size int64) {
	f, err := os.Create(filename)
	if err != nil {
		t.Fatalf("os.Create failed: %v", err)
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
			t.Fatalf("io.Write failed: %v", err)
		}
	}
	err = f.Close()
	if err != nil {
		t.Fatalf("os.Close failed: %v", err)
	}
}

func runKas(t *testing.T) (*httptest.Server, string, string) {
	signingKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		t.Fatalf("crypto.NewRSAKeyPair: %v", err)
	}

	signingPubKey, err := signingKeyPair.PublicKeyInPemFormat()
	if err != nil {
		t.Fatalf("crypto.PublicKeyInPemFormat failed: %v", err)
	}

	signingPrivateKey, err := signingKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatalf("crypto.PrivateKeyInPemFormat failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(kAcceptKey) != kContentTypeJSONValue {
			t.Fatalf("expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
		}

		r.Header.Set(kContentTypeKey, kContentTypeJSONValue)

		switch {
		case r.URL.Path == kasPublicKeyPath:
			kasPublicKeyResponse, err := json.Marshal(mockKasPublicKey)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(kasPublicKeyResponse)
			if err != nil {
				t.Fatalf("http.ResponseWriter.Write failed: %v", err)
			}
		case r.URL.Path == kRewrapV2:
			requestBody, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("io.ReadAll failed: %v", err)
			}
			var data map[string]string
			err = json.Unmarshal(requestBody, &data)
			if err != nil {
				t.Fatalf("json.Unmarsha failed: %v", err)
			}
			tokenString, ok := data[kSignedRequestToken]
			if !ok {
				t.Fatalf("signed token missing in rewrap response")
			}
			token, err := jwt.ParseWithClaims(tokenString, &rewrapJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				signingRSAPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(signingPubKey))
				if err != nil {
					return nil, fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM failed: %w", err)
				}

				return signingRSAPublicKey, nil
			})
			var rewrapRequest = ""
			if err != nil {
				t.Fatalf("jwt.ParseWithClaims failed:%v", err)
			} else if claims, fine := token.Claims.(*rewrapJWTClaims); fine {
				rewrapRequest = claims.Body
			} else {
				t.Fatalf("unknown claims type, cannot proceed")
			}
			err = json.Unmarshal([]byte(rewrapRequest), &data)
			if err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			wrappedKey, err := crypto.Base64Decode([]byte(data["wrappedKey"]))
			if err != nil {
				t.Fatalf("crypto.Base64Decode failed: %v", err)
			}
			kasPrivateKey := strings.ReplaceAll(mockKasPrivateKey, "\n\t", "\n")
			asymDecrypt, err := crypto.NewAsymDecryption(kasPrivateKey)
			if err != nil {
				t.Fatalf("crypto.NewAsymDecryption failed: %v", err)
			}
			symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
			if err != nil {
				t.Fatalf("crypto.Decrypt failed: %v", err)
			}
			asymEncrypt, err := crypto.NewAsymEncryption(data[kClientPublicKey])
			if err != nil {
				t.Fatalf("crypto.NewAsymEncryption failed: %v", err)
			}
			entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
			if err != nil {
				t.Fatalf("crypto.encrypt failed: %v", err)
			}
			response, err := json.Marshal(map[string]string{
				kEntityWrappedKey: string(crypto.Base64Encode(entityWrappedKey)),
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(response)
			if err != nil {
				t.Fatalf("http.ResponseWriter.Write failed: %v", err)
			}
		default:
			t.Fatalf("expected to request: %s", r.URL.Path)
		}
	}))

	return server, signingPubKey, signingPrivateKey
}
