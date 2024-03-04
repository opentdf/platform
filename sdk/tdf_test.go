package sdk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/opentdf/platform/sdk/internal/crypto"
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
	tdfFileSize int64
	checksum    string
	kasInfoList []KASInfo
}

//nolint:gochecknoglobals // Mock Value
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

//nolint:gochecknoglobals // Mock value
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

var testHarnesses = []tdfTest{ //nolint:gochecknoglobals // requires for testing tdf
	{
		fileSize:    5,
		tdfFileSize: 1557,
		checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: "",
			},
		},
	},
	{
		fileSize:    oneKB,
		tdfFileSize: 2581,
		checksum:    "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: "",
			},
		},
	},
	{
		fileSize:    hundredMB,
		tdfFileSize: 104866410,
		checksum:    "cee41e98d0a6ad65cc0ec77a2ba50bf26d64dc9007f7f1c7d7df68b8b71291a6",
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
	{
		fileSize:    5 * hundredMB,
		tdfFileSize: 524324210,
		checksum:    "d2fb707e70a804cf2ea770c9229295689831b4c88879c62bdb966e77e7336f18",
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
	// {
	//	fileSize:    2 * oneGB,
	//	tdfFileSize: 2097291006,
	//	checksum:    "57bb3422770a98f193baa6f0fd67dd9743dc07c868abd95ad0606dff0bee32b4",
	//	kasInfoList: []KASInfo{
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//	},
	// },
	// {
	//	fileSize:    4 * oneGB,
	//	tdfFileSize: 4194580006,
	//	checksum:    "a9c267f8600c18263250a10b0ab7995528cf80fc85275ab5a36ada3e350519fd",
	//	kasInfoList: []KASInfo{
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//	},
	// },
	// {
	//	fileSize:    6 * oneGB,
	//	tdfFileSize: 6291869194,
	//	checksum:    "1a48fc773889be3361e9ca826fad32c191b10309f03996e1d233e02bc4c4b979",
	//	kasInfoList: []KASInfo{
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//	},
	// },
	// {
	//	fileSize:    20 * oneGB,
	//	tdfFileSize: 20972892194,
	//	checksum:    "bd218f6cc4dc038d5707a276b0fdd5d1b3725cebe4e2e7b475cf2d09d551af08",
	//	kasInfoList: []KASInfo{
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//		{
	//			url:       "http://localhost:65432/api/kas",
	//			publicKey: mockKasPublicKey,
	//		},
	//	},
	// },
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

const payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var partialTDFTestHarnesses = []partialReadTdfTest{ //nolint:gochecknoglobals // requires for testing tdf
	{
		payload: payload, // len: 62
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
				expectedPayload: payload,
			},
			{
				segmentSize:     int64(len(payload)),
				dataOffset:      0,
				dataLength:      len(payload),
				expectedPayload: payload,
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

func TestSimpleTDF(t *testing.T) {
	serverURL, closer, sdk := runKas()
	defer closer()

	metaDataStr := `{"displayName" : "openTDF go sdk"}`

	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	expectedTdfSize := int64(2069)
	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"
	{
		kasURLs := []KASInfo{
			{
				url:       serverURL,
				publicKey: "",
			},
		}

		inBuf := bytes.NewBufferString(plainText)
		bufReader := bytes.NewReader(inBuf.Bytes())

		fileWriter, err := os.Create(tdfFilename)
		if err != nil {
			t.Fatalf("os.CreateTDF failed: %v", err)
		}
		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			if err != nil {
				t.Fatalf("Fail to close the file: %v", err)
			}
		}(fileWriter)

		tdfObj, err := sdk.CreateTDF(fileWriter, bufReader,
			WithKasInformation(kasURLs...),
			WithMetaData(metaDataStr),
			WithDataAttributes(attributes...))
		if err != nil {
			t.Fatalf("tdf.CreateTDF failed: %v", err)
		}

		if math.Abs(float64(tdfObj.size-expectedTdfSize)) > 1.01*float64(expectedTdfSize) {
			t.Errorf("tdf size test failed expected %v, got %v", tdfObj.size, expectedTdfSize)
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

		r, err := sdk.LoadTDF(readSeeker)
		if err != nil {
			t.Fatalf("Fail to load the tdf:%v", err)
		}

		unencryptedMetaData, err := r.UnencryptedMetadata()
		if err != nil {
			t.Fatalf("Fail to get meta data from tdf:%v", err)
		}

		if metaDataStr != unencryptedMetaData {
			t.Errorf("meta data test failed expected %v, got %v", metaDataStr, unencryptedMetaData)
		}

		dataAttributes, err := r.DataAttributes()
		if err != nil {
			t.Fatalf("Fail to get policy from tdf:%v", err)
		}

		if reflect.DeepEqual(attributes, dataAttributes) != true {
			t.Errorf("attributes test failed expected %v, got %v", attributes, dataAttributes)
		}
	}

	// test reader
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

		buf := make([]byte, 8)

		r, err := sdk.LoadTDF(readSeeker)
		if err != nil {
			t.Fatalf("Fail to create reader:%v", err)
		}

		offset := 2
		n, err := r.ReadAt(buf, int64(offset))
		if err != nil && errors.Is(err, io.EOF) != true {
			t.Fatalf("Fail to read from reader:%v", err)
		}

		expectedPlainTxt := plainText[offset : offset+n]
		if string(buf[:n]) != expectedPlainTxt {
			t.Errorf("decrypt test failed expected %v, got %v", expectedPlainTxt, string(buf))
		}
	}

	_ = os.Remove(tdfFilename)
}

func TestTDFReader(t *testing.T) { //nolint:gocognit
	serverURL, closer, sdk := runKas()
	defer closer()

	for _, test := range partialTDFTestHarnesses { // create .txt file
		kasInfoList := test.kasInfoList
		for index := range kasInfoList {
			kasInfoList[index].url = serverURL
			kasInfoList[index].publicKey = ""
		}

		for _, readAtTest := range test.readAtTests {
			tdfBuf := bytes.Buffer{}
			readSeeker := bytes.NewReader([]byte(test.payload))
			_, err := sdk.CreateTDF(
				io.Writer(&tdfBuf),
				readSeeker,
				WithKasInformation(kasInfoList...),
				WithSegmentSize(readAtTest.segmentSize),
			)

			if err != nil {
				t.Fatalf("tdf.CreateTDF failed: %v", err)
			}

			// test reader
			tdfReadSeeker := bytes.NewReader(tdfBuf.Bytes())
			r, err := sdk.LoadTDF(tdfReadSeeker)
			if err != nil {
				t.Fatalf("failed to read tdf: %v", err)
			}

			rbuf := make([]byte, readAtTest.dataLength)
			n, err := r.ReadAt(rbuf, readAtTest.dataOffset)
			if err != nil {
				t.Fatalf("Fail to read from reader:%v", err)
			}

			if n != readAtTest.dataLength {
				t.Errorf("decrypt test failed expected length %v, got %v", readAtTest.dataLength, n)
			}

			if string(rbuf) != readAtTest.expectedPayload {
				t.Errorf("decrypt test failed expected %v, got %v", readAtTest.expectedPayload, string(rbuf))
			}

			// Test Read
			plainTextFile := "text.txt"
			{
				fileWriter, err := os.Create(plainTextFile)

				if err != nil {
					t.Fatalf("os.CreateTDF failed: %v", err)
				}
				defer func(fileWriter *os.File) {
					err := fileWriter.Close()
					if err != nil {
						t.Fatalf("Fail to close the tdf file: %v", err)
					}
				}(fileWriter)

				_, err = io.Copy(fileWriter, r)
				if err != nil {
					t.Fatalf("Fail to copy into file: %v", err)
				}
			}

			fileData, err := os.ReadFile(plainTextFile)
			if err != nil {
				t.Fatalf("os.ReadFile failed: %v", err)
			}

			if string(fileData) != test.payload {
				t.Errorf("decrypt test failed expected %v, got %v", test.payload, string(fileData))
			}
			_ = os.Remove(plainTextFile)
		}
	}
}

func TestTDF(t *testing.T) {
	serverURL, closer, sdk := runKas()
	defer closer()

	for index, test := range testHarnesses {
		// create .txt file
		plaintTextFileName := strconv.Itoa(index) + ".txt"
		tdfFileName := plaintTextFileName + ".tdf"
		decryptedTdfFileName := tdfFileName + ".txt"

		kasInfoList := test.kasInfoList
		for index := range kasInfoList {
			kasInfoList[index].url = serverURL
			kasInfoList[index].publicKey = ""
		}

		// test encrypt
		testEncrypt(t, sdk, kasInfoList, plaintTextFileName, tdfFileName, test)

		// test decrypt with reader
		testDecryptWithReader(t, sdk, tdfFileName, decryptedTdfFileName, test)

		// Remove the test files
		_ = os.Remove(plaintTextFileName)
		_ = os.Remove(tdfFileName)
	}
}

func BenchmarkReader(b *testing.B) {
	test := tdfTest{
		fileSize: 10 * oneMB,
		kasInfoList: []KASInfo{
			{
				url:       "http://localhost:65432/api/kas",
				publicKey: mockKasPublicKey,
			},
		},
	}

	serverURL, closer, sdk := runKas()
	defer closer()

	kasInfoList := test.kasInfoList
	for index := range kasInfoList {
		kasInfoList[index].url = serverURL
		kasInfoList[index].publicKey = ""
	}

	// encrypt
	// create a buffer and write with 0xff
	inBuf := make([]byte, test.fileSize)
	for index := 0; index < len(inBuf); index++ {
		inBuf[index] = char
	}

	tdfBuf := bytes.Buffer{}
	readSeeker := bytes.NewReader(inBuf)
	_, err := sdk.CreateTDF(io.Writer(&tdfBuf), readSeeker, WithKasInformation(kasInfoList...))
	if err != nil {
		b.Fatalf("tdf.CreateTDF failed: %v", err)
	}

	readSeeker = bytes.NewReader(tdfBuf.Bytes())
	r, err := sdk.LoadTDF(readSeeker)
	if err != nil {
		b.Fatalf("failed to read tdf: %v", err)
	}

	outBuf := bytes.Buffer{}
	for i := 0; i < b.N; i++ {
		n, err := r.WriteTo(io.Writer(&outBuf))
		if err != nil {
			b.Fatalf("io.Writer failed: %v", err)
		}

		if !bytes.Equal(outBuf.Bytes()[:n], inBuf) {
			b.Errorf("Input buffer is different from out buffer decrypt test failed")
		}
	}
}

// create tdf
func testEncrypt(t *testing.T, sdk *SDK, kasInfoList []KASInfo, plainTextFilename, tdfFileName string, test tdfTest) {
	// create a plain text file
	createFileName(buffer, plainTextFilename, test.fileSize)

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
		t.Fatalf("os.CreateTDF failed: %v", err)
	}
	defer func(fileWriter *os.File) {
		err := fileWriter.Close()
		if err != nil {
			t.Fatalf("Fail to close the tdf file: %v", err)
		}
	}(fileWriter) // CreateTDF TDFConfig
	tdfObj, err := sdk.CreateTDF(fileWriter, readSeeker, WithKasInformation(kasInfoList...))
	if err != nil {
		t.Fatalf("tdf.CreateTDF failed: %v", err)
	}

	if math.Abs(float64(tdfObj.size-test.tdfFileSize)) > 1.01*float64(test.tdfFileSize) {
		t.Errorf("tdf size test failed expected %v, got %v", test.tdfFileSize, tdfObj.size)
	}
}

func testDecryptWithReader(t *testing.T, sdk *SDK, tdfFile, decryptedTdfFileName string, test tdfTest) {
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

	r, err := sdk.LoadTDF(readSeeker)
	if err != nil {
		t.Fatalf("failed to read tdf: %v", err)
	}

	{
		fileWriter, err := os.Create(decryptedTdfFileName)

		if err != nil {
			t.Fatalf("os.CreateTDF failed: %v", err)
		}
		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			if err != nil {
				t.Fatalf("Fail to close the tdf file: %v", err)
			}
		}(fileWriter)

		_, err = io.Copy(fileWriter, r)
		if err != nil {
			t.Fatalf("Fail to copy into file: %v", err)
		}
	}

	res := checkIdentical(t, decryptedTdfFileName, test.checksum)
	if !res {
		t.Errorf("decrypted text didn't match palin text")
	}

	var bufSize int64 = 5
	buf := make([]byte, bufSize)
	resultBuf := bytes.Repeat([]byte{char}, int(bufSize))

	// read last 5 bytes
	n, err := r.ReadAt(buf, test.fileSize-(bufSize))
	if err != nil && errors.Is(err, io.EOF) != true {
		t.Fatalf("sdk.Reader.ReadAt failed: %v", err)
	}

	if !bytes.Equal(buf[:n], resultBuf[:n]) {
		t.Errorf("decrypted text didn't match palin text with ReadAt interface")
	}

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

// if we have credentials for a local keycloak we assume that
// we are running against a local cluster and dont' need a fake KAS
// in this case we return a GRPC rewrapper and authenticate against
// keycloak
func runKas() (string, func(), *SDK) {
	clientID := os.Getenv("SDK_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("SDK_OIDC_CLIENT_SECRET")
	if clientID != "" && clientSecret != "" {
		opts := make([]Option, 0)
		opts = append(opts,
			WithClientCredentials(clientID, clientSecret, []string{}),
			WithTokenEndpoint("http://localhost:65432/auth/realms/tdf/protocol/openid-connect/token"),
			WithInsecureConn(),
		)

		sdk, err := New("http://doesntmatterhere.example.org", opts...)
		if err != nil {
			panic(fmt.Sprintf("error creating SDK: %v", err))
		}

		return "grpc://localhost:9000", func() {}, sdk
	}

	signingKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		panic(fmt.Sprintf("crypto.NewRSAKeyPair: %v", err))
	}

	signingPubKey, err := signingKeyPair.PublicKeyInPemFormat()
	if err != nil {
		panic(fmt.Sprintf("crypto.PublicKeyInPemFormat failed: %v", err))
	}

	signingPrivateKey, err := signingKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		panic(fmt.Sprintf("crypto.PrivateKeyInPemFormat failed: %v", err))
	}

	accessTokenBytes := make([]byte, 10)
	if _, err := rand.Read(accessTokenBytes); err != nil {
		panic("failed to create random access token")
	}
	accessToken := crypto.Base64Encode(accessTokenBytes)

	server := httptest.NewServer(http.HandlerFunc(getKASRequestHandler(string(accessToken), signingPubKey)))

	authConfig := AuthConfig{dpopPublicKeyPEM: signingPubKey, dpopPrivateKeyPEM: signingPrivateKey, accessToken: string(accessToken)}

	sdk, err := New("http://thisdoesnotmatterhere.example.org", WithAuthConfig(authConfig))
	if err != nil {
		panic(fmt.Sprintf("error creating SDK with authconfig: %v", err))
	}
	return server.URL, func() { server.Close() }, sdk
}

func getKASRequestHandler(expectedAccessToken, //nolint:gocognit // KAS is pretty complicated
	dpopPublicKeyPEM string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(kAcceptKey) != kContentTypeJSONValue {
			panic(fmt.Sprintf("expected Accept: application/json header, got: %s", r.Header.Get("Accept")))
		}

		r.Header.Set(kContentTypeKey, kContentTypeJSONValue)

		switch {
		case r.URL.Path == kasPublicKeyPath:
			sendPublicKey(w)
		case r.URL.Path == kRewrapV2:
			requestBody, err := io.ReadAll(r.Body)
			if err != nil {
				panic(fmt.Sprintf("io.ReadAll failed: %v", err))
			}
			if r.Header.Get("authorization") != fmt.Sprintf("Bearer %s", expectedAccessToken) {
				panic(fmt.Sprintf("got a bad auth header: [%s]", r.Header.Get("authorization")))
			}

			var data map[string]string
			err = json.Unmarshal(requestBody, &data)
			if err != nil {
				panic(fmt.Sprintf("json.Unmarsha failed: %v", err))
			}
			tokenString, ok := data[kSignedRequestToken]
			if !ok {
				panic("signed token missing in rewrap response")
			}
			token, err := jwt.ParseWithClaims(tokenString, &rewrapJWTClaims{}, func(_ *jwt.Token) (interface{}, error) {
				signingRSAPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(dpopPublicKeyPEM))
				if err != nil {
					return nil, fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM failed: %w", err)
				}

				return signingRSAPublicKey, nil
			})
			var rewrapRequest string
			if err != nil {
				panic(fmt.Sprintf("jwt.ParseWithClaims failed:%v", err))
			} else if claims, fine := token.Claims.(*rewrapJWTClaims); fine {
				rewrapRequest = claims.Body
			} else {
				panic("unknown claims type, cannot proceed")
			}

			entityWrappedKey := getRewrappedKey(rewrapRequest)
			response, err := json.Marshal(map[string]string{
				kEntityWrappedKey: string(crypto.Base64Encode(entityWrappedKey)),
			})
			if err != nil {
				panic(fmt.Sprintf("json.Marshal failed: %v", err))
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(response)
			if err != nil {
				panic(fmt.Sprintf("http.ResponseWriter.Write failed: %v", err))
			}
		default:
			panic(fmt.Sprintf("expected to request: %s", r.URL.Path))
		}
	}
}

func getRewrappedKey(rewrapRequest string) []byte {
	bodyData := RequestBody{}
	err := json.Unmarshal([]byte(rewrapRequest), &bodyData)
	if err != nil {
		panic(fmt.Sprintf("json.Unmarshal failed: %v", err))
	}
	wrappedKey, err := crypto.Base64Decode([]byte(bodyData.WrappedKey))
	if err != nil {
		panic(fmt.Sprintf("crypto.Base64Decode failed: %v", err))
	}
	kasPrivateKey := strings.ReplaceAll(mockKasPrivateKey, "\n\t", "\n")
	asymDecrypt, err := crypto.NewAsymDecryption(kasPrivateKey)
	if err != nil {
		panic(fmt.Sprintf("crypto.NewAsymDecryption failed: %v", err))
	}
	symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
	if err != nil {
		panic(fmt.Sprintf("crypto.Decrypt failed: %v", err))
	}
	asymEncrypt, err := crypto.NewAsymEncryption(bodyData.ClientPublicKey)
	if err != nil {
		panic(fmt.Sprintf("crypto.NewAsymEncryption failed: %v", err))
	}
	entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
	if err != nil {
		panic(fmt.Sprintf("crypto.encrypt failed: %v", err))
	}
	return entityWrappedKey
}

func sendPublicKey(w http.ResponseWriter) {
	kasPublicKeyResponse, err := json.Marshal(mockKasPublicKey)
	if err != nil {
		panic(fmt.Sprintf("json.Marshal failed: %v", err))
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(kasPublicKeyResponse)
	if err != nil {
		panic(fmt.Sprintf("http.ResponseWriter.Write failed: %v", err))
	}
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
