package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	attributespb "github.com/opentdf/platform/protocol/go/policy/attributes"
	wellknownpb "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/sdk/internal/autoconfigure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

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
	n                string
	fileSize         int64
	tdfFileSize      float64
	checksum         string
	mimeType         string
	splitPlan        []autoconfigure.SplitStep
	policy           []autoconfigure.AttributeValueFQN
	expectedPlanSize int
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

	mockRSAPrivateKey2 = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCissi7TDbI5k6J
32DSoS+jKhwoC2a3eaLwe65Fly5brQRGdNHgXuQ85g2fKLr4D84PWW+3rXGIH9Cf
AXqx9WsBBz1Nb2h+SBh68KACN/gbtLo12fMis4/LO5o7/MfbrpwtARh+w+eNDcM1
bzzYSMPuzoTxmvllGveZhRaacaAqRajZELRdHgotXPR31PjtCWPHxhErKdMkZ4R8
Nrl7nDunAiVXp+YiqeVlDzxlI7QhEMsHCokDfjvb05LT48FHmLYeHWEAOBNii/Tn
8rotlArjeaksr2+cG0jrbjb2DnJVVbeg2JoMtgVyrlg1y1UcW6bISA785JCGicrd
MVglmfXPAgMBAAECggEAJkbun9YJ65D3eEtj8Zn3ZalCD4/DHjZRRcerU/cB8pKN
d3ADcoiQpN0w5jmEZ1j8jzLo7CszkyV9BPOppJWLE6Za301vJYqbq8zRsEPvrMED
sCizIX5iPZurqSJK+N2nI5Vm6Gf5oX9T5k3h4DaaViQjNd5Sf11tVCJyE2rZFiiF
sS08O//k5dO3W1mf2hZ7VGWGMjYGzV14/X0IPb0ov+1kGKpHa8hnqhfqfyjsSfQ2
gBYhn4Rg/aYY1UgomJsxzmmROzbKcdS+95Zy5BrdUJJiK1gzDhu2OZE/c2UgiuUo
kHiIV6rqtnSz7Pk3+fboC2PXLDfYaLD4ocf69ea7TQKBgQDkeHnLbn8ly/qR4/Ac
Tgui1Uze5KTF2GM8n+gh3Sb3i5uQbkLneDrS/4d+Qgq2+wPOjmte7O5ZqnGmhqY/
QBXBBWF2IsM6cP5YrTBrxQHdaB4ALyIkH7t/qswRKeNwmluMwRSVdD54H8ge/Rcs
9JeUQzWJ25xriOPR9gyeRIo8rQKBgQC2TXaq4ZW4bW2fXr0I/X4O3nw92Bpsqzl7
AhI1x1y+MuzpTlZOwFpxZsYvzYy9k34Bq9/Uz3lzw1VhJF79ozJ1BjcLzTWpEugC
0QvePjx/OtvVqH6m/ZPftlgHldC8JSC/CFwGhKvhNvtnNcd1jJeZk1QLYEZh5l9P
nlGmpWKv6wKBgQC7HVhSnfqQUBC1b0L1S44IHD1Kx2OTjXco7aXGJkOFtdcAYO12
eWdj61ditl/kIIyrnMSfB9jlosxVoC2D2851ORzrDelqcaQ9qAniGYU/ecgoSnHh
uANtucpLvEzDqgeUrYVYKc4Hv6+8gXd7oA6MpMayUyQ2hfRfvu3yqRu2OQKBgGlm
ghysTocR5ZaGDN9cyHxKUCTlg+meWZ5wBR1IxatGAEmnvCjN97ynAiDzQ9L7qpfG
yqPczMiMgBmpEK6uo2abkEnnfIXjY3b1bFozO4EIA8AVKhzccZmfcGf6S3PsN3Gb
oLE4FbQhuNrkcgzZm3D0iFwHbsn9is+apnSmHFe/AoGBANUjuB3adekqf3PsMEMa
zZFcHltBa/fRS6nMr3Vofm8tVDHlvSBAchTLrY1CAKJyNDllWqzts34iXacQk5BX
WYNzdvj1FGrOgkpHbG1XwI6kQNXGjaddo+8JmHBhHW7m1MrUsIUSgV3C5tdi0p5a
RomV0C3jlGK/HfVVrWTBtlEV
-----END PRIVATE KEY-----`
	mockRSAPublicKey2 = `-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIUDnM4QkMGj+2UWW4USnhziNyi3XowDQYJKoZIhvcNAQEL
BQAwDjEMMAoGA1UEAwwDa2FzMB4XDTI0MDYxNDE0MTYwOFoXDTI1MDYxNDE0MTYw
OFowDjEMMAoGA1UEAwwDa2FzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAorLIu0w2yOZOid9g0qEvoyocKAtmt3mi8HuuRZcuW60ERnTR4F7kPOYNnyi6
+A/OD1lvt61xiB/QnwF6sfVrAQc9TW9ofkgYevCgAjf4G7S6NdnzIrOPyzuaO/zH
266cLQEYfsPnjQ3DNW882EjD7s6E8Zr5ZRr3mYUWmnGgKkWo2RC0XR4KLVz0d9T4
7Qljx8YRKynTJGeEfDa5e5w7pwIlV6fmIqnlZQ88ZSO0IRDLBwqJA34729OS0+PB
R5i2Hh1hADgTYov05/K6LZQK43mpLK9vnBtI62429g5yVVW3oNiaDLYFcq5YNctV
HFumyEgO/OSQhonK3TFYJZn1zwIDAQABo1MwUTAdBgNVHQ4EFgQUOnXMGYIbKsdc
wMDdsekltIUKxv4wHwYDVR0jBBgwFoAUOnXMGYIbKsdcwMDdsekltIUKxv4wDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABC07euj4ZZHqKEhTe6kG
utKN25psXOe6lk+0crGzC425MI7y5lKHfkfm+eMGDBfG+w42FerUiQKtc2sxzarR
vUJOdNQyhqx8kPJ6cSGPWx/tsCLe95zUhDRBv0N07OoLpJWpu8IRdMwiKjKWjutW
McR2P+L6Ih0Mwr+H72SU3PWL1pNZVmZW3jAvu+7s6tyP3gkIdrz6BGtdO38DkhQ3
6NY6wKbZ+U+ME8mqrDy8OAqm8z1bm2YXYTdfgS3ypt+KaDwZee3gpIk8jhce0UTr
spiUiGZJJRd1+A5i4HvEOpo/gITdYE2jZF9afj4pgz9AQshCg6Fw8mIZasabT4MH
7g==
-----END CERTIFICATE-----`

	mockRSAPrivateKey3 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZTCZCLl6OaFNl
0WGnXI8thwz38LWwncdp74dzOotz+CC5nmoclEhFoPQPMbCI5ncH+GnGwEG9D0GI
paOGzAniVz8BlLS01WuYiLFleh1tUmyOu3nIXs5ke/2MCs1+cUK7Ghii3q6xKHfT
CHu+X+pL9PYIssDwHpqevLPsXFD7kFnRRKkmMXqLKcOgr4+qcNqQ7YN/30SJv6lw
3/FznVyhZnULi/0MDmMGHtpA5ypqycx1xLo0QygAWc9iH+lpjNbu6IvkI0dW1vjI
KMmg+BBA5uPu424lurefChCDURH32a+VXQHNr+f1j4SZJRod0Q4eDTgOadYrxj2/
U045/f0jAgMBAAECggEAQBAuvOGb6m92ysohwUtRGnmh1cvmYhTNzVuog2Mn/CLp
qiilt6PQQCjvVZoyaEPH4rDRo5mc32GMxYpTOHX0e35yejqm+htmh6w4Vmwd+B3F
+DAoyK+2GRAn+WpaTkkO1holyYq9/pMm4C5faEO1KmEIoMHzF2Xyv/ukRVafEUGw
Mltp8PxSnaLL+PHQJT8XqTyC6uT3h0ntXh7ShDXA/ihg6hy0zOBJ8ZWHMlZt4koP
jscLm+JqqjOPGrddoUzjBwDavjgsWmgC6AGlkL+knLrrLuYql5m4VXcgwYCGxMNE
vlulEtC/2qWPYJVy9Y2cKAlel++kCUEb75s6RPGcwQKBgQDRbSJ9U8zgpTMirFDb
/0PgdYPK2p/5co96Y08sT+TlGmsduDVJhrXPLnUccYBhUREm10pPG9Lw92XRV0hm
17I+7UijjNw2ZX2z9mjCMIUFo974SIRXfGlk8kFpqIYLzm3dl6HuNG8KCs/kgIkk
kqQyEWXarQAv+QZz+klOQVzfCwKBgQC7Y4n1kTQTDnq+wXehPq5VS34/Bpu7lzF8
fAKAF33xQ/fyijXFo7uX+Z3rWcyOK1TzmppTcD7M/rmnZECbM99p8c9zGUwggnzs
4Y9yT5xhbSP2ecER+KdHsLbyOWlmWch0iq6rOVWhRzwcUYtc5SoTqxexawAtFowk
sTGKHuEJSQKBgQCTELZ1mBF5d8kPAj7OHtXFnABuxVQt0dsbsP16Oqickg7Ckgcp
mOW3lgI7dSEYNdt7kRfnsbxR5wmjFk4LmlDbi7nE0DgcIu1BITqzk2r2aPs9E3+M
CBvi/ZQd5HAtfkr8n2zhYATR4oHXDsQ/4JJZboo+I9rL1W5Ip2wu/gt/vQKBgFLV
W2Sr/SL3YZb1GpayiIm3x2TA3RJ9cSigANLyj3+ZFf+mzMJC8Gfrtb0VgvDNgs30
Z4e+tGQVraerD0wMEBRbCeLNKfOs+uATjT9wpaYDgsQvagMxsXBlU1mbu1W9Fnk9
3JxfydRzEsVJ3pr/yivLk7ufmwJTVzvZABcYM03RAoGAcBpkAdrm30xQaizQ3PhW
FEeNF82AQ5HeMn+pWQEWh5H0OLl86anWyVInceIYCmiYSSyA2HQkeaPbx6uX9drW
mWG6WforNiPLQhygVLbihu38LDhaU8El4dItCuOz0J08vN3DaLry0Lo5riflBmGT
899NI+svMPeDL5zxN5h1FXA=
-----END PRIVATE KEY-----`
	mockRSAPublicKey3 = `-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIUWLo+ebtVODHDFM4OrwNGpVodcUswDQYJKoZIhvcNAQEL
BQAwDjEMMAoGA1UEAwwDa2FzMB4XDTI0MDYxNDE0MTY1N1oXDTI1MDYxNDE0MTY1
N1owDjEMMAoGA1UEAwwDa2FzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAmUwmQi5ejmhTZdFhp1yPLYcM9/C1sJ3Hae+HczqLc/gguZ5qHJRIRaD0DzGw
iOZ3B/hpxsBBvQ9BiKWjhswJ4lc/AZS0tNVrmIixZXodbVJsjrt5yF7OZHv9jArN
fnFCuxoYot6usSh30wh7vl/qS/T2CLLA8B6anryz7FxQ+5BZ0USpJjF6iynDoK+P
qnDakO2Df99Eib+pcN/xc51coWZ1C4v9DA5jBh7aQOcqasnMdcS6NEMoAFnPYh/p
aYzW7uiL5CNHVtb4yCjJoPgQQObj7uNuJbq3nwoQg1ER99mvlV0Bza/n9Y+EmSUa
HdEOHg04DmnWK8Y9v1NOOf39IwIDAQABo1MwUTAdBgNVHQ4EFgQUe+m7UJKzFLkc
uMdt6yHhqcvh+pEwHwYDVR0jBBgwFoAUe+m7UJKzFLkcuMdt6yHhqcvh+pEwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAcF85bMOadHZeYXmJ9nFv
9I5v/Jynju2uI5F2813VD05iJRke1dcPVcT2Dj1PucYV19Wo0pCMdWOkHhF6p9pZ
Iuxu2zA7cGQNhhUi6MKr5cUWl6tBprAghzdwEH1cZQsBiV3ki7fCCiDURIJaTlNq
/AGxRqo7/Mzh/3wci/i/XyY/FfiIr+beHuB2SPCm6hdizRH6vPAmquVAUGq2lmhl
uOnQR2c7Dix39LZQCiEfPSUnTAKJCyMpolky7Vq31PsPKk+gK19XftfH/Aul21vt
ZwVW7fLwZ2SSmC9cOjSkzZw/eDwwIRNgo94OL4mw5cXSPOuMeO8Tugc6LO4v91SO
yg==
-----END CERTIFICATE-----`
)

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

type assertionTests struct {
	assertions                []AssertionConfig
	assertionVerificationKeys *AssertionVerificationKeys
	expectedSize              int
}

const payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var buffer []byte //nolint:gochecknoglobals // for testing

func init() {
	// create a buffer and write with 0xff
	buffer = make([]byte, stepSize)
	for index := 0; index < len(buffer); index++ {
		buffer[index] = char
	}
}

type keyInfo struct {
	kid, private, public string
}

type TDFSuite struct {
	suite.Suite
	sdk   *SDK
	kases []FakeKas
}

func (s *TDFSuite) SetupSuite() {
	// Set up the test environment
	s.startBackend()
}

func (s *TDFSuite) SetupTest() {
	s.sdk.kasKeyCache.clear()
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

	expectedTdfSize := int64(2095)
	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"
	{
		kasURLs := []KASInfo{
			{
				URL:       "https://a.kas/",
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
		)

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

		payloadKey, err := r.UnsafePayloadKeyRetrieval()
		s.Require().NoError(err)
		s.Len(payloadKey, kKeySize)
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

func (s *TDFSuite) Test_TDFWithAssertion() {
	hs256Key := make([]byte, 32)
	_, err := rand.Read(hs256Key)
	s.Require().NoError(err)

	privateKey, err := rsa.GenerateKey(rand.Reader, tdf3KeySize)
	s.Require().NoError(err)

	defaultKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: hs256Key,
	}

	for _, test := range []assertionTests{ //nolint:gochecknoglobals // requires for testing tdf
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "base64binary",
						Schema: "text",
						Value:  "ICAgIDxlZGoOkVkaD4=",
					},
				},
				{
					ID:             "assertion2",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			assertionVerificationKeys: nil,
			expectedSize:              2896,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "base64binary",
						Schema: "text",
						Value:  "ICAgIDxlZGoOkVkaD4=",
					},
					SigningKey: defaultKey,
				},
				{
					ID:             "assertion2",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
					SigningKey: defaultKey,
				},
			},
			assertionVerificationKeys: &AssertionVerificationKeys{
				DefaultKey: defaultKey,
			},
			expectedSize: 2896,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "base64binary",
						Schema: "text",
						Value:  "ICAgIDxlZGoOkVkaD4=",
					},
					SigningKey: AssertionKey{
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
				},
				{
					ID:             "assertion2",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
					SigningKey: AssertionKey{
						Alg: AssertionKeyAlgRS256,
						Key: privateKey,
					},
				},
			},
			assertionVerificationKeys: &AssertionVerificationKeys{
				// defaultVerificationKey: nil,
				Keys: map[string]AssertionKey{
					"assertion1": {
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
					"assertion2": {
						Alg: AssertionKeyAlgRS256,
						Key: privateKey.PublicKey,
					},
				},
			},
			expectedSize: 3195,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "base64binary",
						Schema: "text",
						Value:  "ICAgIDxlZGoOkVkaD4=",
					},
					SigningKey: AssertionKey{
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
				},
				{
					ID:             "assertion2",
					Type:           BaseAssertion,
					Scope:          TrustedDataObj,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			assertionVerificationKeys: &AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					"assertion1": {
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
				},
			},
			expectedSize: 2896,
		},
	} {
		expectedTdfSize := test.expectedSize
		tdfFilename := "secure-text.tdf"
		plainText := "Virtru"
		{
			kasURLs := []KASInfo{
				{
					URL:       "https://a.kas/",
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
				WithAssertions(test.assertions...))

			s.Require().NoError(err)
			s.InDelta(float64(expectedTdfSize), float64(tdfObj.size), 32.0)
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

			var r *Reader
			if test.assertionVerificationKeys == nil {
				r, err = s.sdk.LoadTDF(readSeeker)
			} else {
				r, err = s.sdk.LoadTDF(readSeeker, WithAssertionVerificationKeys(*test.assertionVerificationKeys))
			}
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
}

func (s *TDFSuite) Test_TDFReader() { //nolint:gocognit // requires for testing tdf
	for _, test := range []partialReadTdfTest{ //nolint:gochecknoglobals // requires for testing tdf
		{
			payload: payload, // len: 62
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
	} { // create .txt file
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
	for index, test := range []tdfTest{
		{
			n:           "small",
			fileSize:    5,
			tdfFileSize: 1557,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		},
		{
			n:           "small-with-mime-type",
			fileSize:    5,
			tdfFileSize: 1557,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			mimeType:    "text/plain",
		},
		{
			n:           "1-kiB",
			fileSize:    oneKB,
			tdfFileSize: 2581,
			checksum:    "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
		},
		{
			n:           "medium",
			fileSize:    hundredMB,
			tdfFileSize: 104866410,
			checksum:    "cee41e98d0a6ad65cc0ec77a2ba50bf26d64dc9007f7f1c7d7df68b8b71291a6",
		},
	} {
		s.Run(test.n, func() {
			// create .txt file
			plaintTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plaintTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			kasInfoList := make([]KASInfo, len(s.kases))
			for i, ki := range s.kases {
				kasInfoList[i] = ki.KASInfo
				kasInfoList[i].PublicKey = ""
			}
			kasInfoList[0].PublicKey = ""
			kasInfoList[0].Default = true

			defer func() {
				// Remove the test files
				_ = os.Remove(plaintTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// test encrypt
			s.testEncrypt(s.sdk, kasInfoList, plaintTextFileName, tdfFileName, test)

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_KeyRotation() {
	for index, test := range []tdfTest{
		{
			n:           "rotate",
			fileSize:    5,
			tdfFileSize: 1557,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		},
	} {
		s.Run(test.n, func() {
			// create .txt file
			plainTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plainTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"
			tdf2Name := plainTextFileName + "-r2.tdf"

			kasInfoList := []KASInfo{s.kases[0].KASInfo}
			kasInfoList[0].PublicKey = ""

			defer func() {
				// Remove the test files
				_ = os.Remove(plainTextFileName)
				_ = os.Remove(tdfFileName)
				_ = os.Remove(tdf2Name)
			}()

			tdo := s.testEncrypt(s.sdk, kasInfoList, plainTextFileName, tdfFileName, test)
			s.Equal("r1", tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KID)

			defer rotateKey(&s.kases[0], "r2", mockRSAPrivateKey2, mockRSAPublicKey2)()
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)

			kasInfoList[0].PublicKey = ""
			kasInfoList[0].KID = ""
			s.sdk.kasKeyCache.clear()
			tdo2 := s.testEncrypt(s.sdk, kasInfoList, tdf2Name, tdfFileName, test)
			s.Equal("r2", tdo2.manifest.EncryptionInformation.KeyAccessObjs[0].KID)

			defer rotateKey(&s.kases[0], "r3", mockRSAPrivateKey3, mockRSAPublicKey3)()
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_KeySplits() {
	for index, test := range []tdfTest{
		{
			n:           "shared",
			fileSize:    5,
			tdfFileSize: 2664,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []autoconfigure.SplitStep{
				{KAS: "https://a.kas/", SplitID: "a"},
				{KAS: "https://b.kas/", SplitID: "a"},
				{KAS: `https://c.kas/`, SplitID: "a"},
			},
		},
		{
			n:           "split",
			fileSize:    5,
			tdfFileSize: 2664,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []autoconfigure.SplitStep{
				{KAS: "https://a.kas/", SplitID: "a"},
				{KAS: "https://b.kas/", SplitID: "b"},
				{KAS: "https://c.kas/", SplitID: "c"},
			},
		},
		{
			n:           "mixture",
			fileSize:    5,
			tdfFileSize: 3211,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []autoconfigure.SplitStep{
				{KAS: "https://a.kas/", SplitID: "a"},
				{KAS: "https://b.kas/", SplitID: "a"},
				{KAS: "https://b.kas/", SplitID: "b"},
				{KAS: "https://c.kas/", SplitID: "b"},
			},
		},
	} {
		s.Run(test.n, func() {
			plaintTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plaintTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			kasInfoList := make([]KASInfo, len(s.kases))
			for i, ki := range s.kases {
				kasInfoList[i] = ki.KASInfo
				kasInfoList[i].PublicKey = ""
			}
			kasInfoList[0].PublicKey = ""

			defer func() {
				_ = os.Remove(plaintTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// test encrypt
			tdo := s.testEncrypt(s.sdk, kasInfoList, plaintTextFileName, tdfFileName, test)
			s.Equal(test.splitPlan[0].KAS, tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KasURL)
			s.Len(tdo.manifest.EncryptionInformation.KeyAccessObjs, len(test.splitPlan))

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_Autoconfigure() {
	for index, test := range []tdfTest{
		{
			n:                "ac-default",
			fileSize:         5,
			tdfFileSize:      1733,
			checksum:         "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			policy:           []autoconfigure.AttributeValueFQN{clsAllowed},
			expectedPlanSize: 1,
		},
		{
			n:                "ac-relto",
			fileSize:         5,
			tdfFileSize:      2517,
			checksum:         "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			policy:           []autoconfigure.AttributeValueFQN{rel2aus, rel2usa},
			expectedPlanSize: 2,
		},
	} {
		s.Run(test.n, func() {
			plaintTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plaintTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			kasInfoList := make([]KASInfo, 1)
			kasInfoList[0] = s.kases[0].KASInfo
			kasInfoList[0].PublicKey = ""
			kasInfoList[0].Default = true

			defer func() {
				_ = os.Remove(plaintTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// test encrypt
			tdo := s.testEncrypt(s.sdk, kasInfoList, plaintTextFileName, tdfFileName, test)
			s.Len(tdo.manifest.EncryptionInformation.KeyAccessObjs, test.expectedPlanSize)

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func rotateKey(k *FakeKas, kid, private, public string) func() {
	old := *k
	k.privateKey = private
	k.KASInfo.KID = kid
	k.KASInfo.PublicKey = public
	k.legakeys[old.KID] = keyInfo{old.KID, old.privateKey, old.KASInfo.PublicKey}
	return func() {
		delete(k.legakeys, old.KID)
		k.privateKey = old.privateKey
		k.KASInfo.KID = old.KASInfo.KID
		k.KASInfo.PublicKey = old.KASInfo.PublicKey
	}
}

// create tdf
func (s *TDFSuite) testEncrypt(sdk *SDK, kasInfoList []KASInfo, plainTextFilename, tdfFileName string, test tdfTest) *TDFObject {
	// create a plain text file
	s.createFileName(buffer, plainTextFilename, test.fileSize)

	// open file
	readSeeker, err := os.Open(plainTextFilename)
	s.Require().NoError(err)

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		s.Require().NoError(err)
	}(readSeeker)

	fileWriter, err := os.Create(tdfFileName)
	s.Require().NoError(err)

	defer func(fileWriter *os.File) {
		err := fileWriter.Close()
		s.Require().NoError(err)
	}(fileWriter) // CreateTDF TDFConfig

	encryptOpts := []TDFOption{WithKasInformation(kasInfoList...)}
	if test.mimeType != "" {
		encryptOpts = append(encryptOpts, WithMimeType(test.mimeType))
	}
	switch {
	case len(test.policy) > 0:
		da := make([]string, len(test.policy))
		for i := 0; i < len(da); i++ {
			da[i] = test.policy[i].String()
		}
		encryptOpts = append(encryptOpts, WithDataAttributes(da...))
	case len(test.splitPlan) > 0:
		encryptOpts = append(encryptOpts, withSplitPlan(test.splitPlan...))
	}

	tdfObj, err := sdk.CreateTDF(fileWriter, readSeeker, encryptOpts...)
	s.Require().NoError(err)

	s.InDelta(float64(test.tdfFileSize), float64(tdfObj.size), .04*float64(test.tdfFileSize))
	return tdfObj
}

func (s *TDFSuite) testDecryptWithReader(sdk *SDK, tdfFile, decryptedTdfFileName string, test tdfTest) {
	readSeeker, err := os.Open(tdfFile)
	s.Require().NoError(err)

	defer func(readSeeker *os.File) {
		err := readSeeker.Close()
		s.Require().NoError(err)
	}(readSeeker)

	r, err := sdk.LoadTDF(readSeeker)
	s.Require().NoError(err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(60*time.Millisecond))
	defer cancel()
	err = r.Init(ctx)
	s.Require().NoError(err)
	s.Require().NotNil(r.payloadKey)

	if test.mimeType != "" {
		s.Equal(test.mimeType, r.Manifest().Payload.MimeType, "mimeType does not match")
	}

	{
		fileWriter, err := os.Create(decryptedTdfFileName)
		s.Require().NoError(err)

		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			s.Require().NoError(err)
		}(fileWriter)

		_, err = io.Copy(fileWriter, r)
		s.Require().NoError(err)
	}

	s.True(s.checkIdentical(decryptedTdfFileName, test.checksum), "decrypted text didn't match plain text")

	var bufSize int64 = 5
	buf := make([]byte, bufSize)
	resultBuf := bytes.Repeat([]byte{char}, int(bufSize))

	// read last 5 bytes
	n, err := r.ReadAt(buf, test.fileSize-(bufSize))
	if err != nil {
		s.Require().ErrorIs(err, io.EOF)
	}
	s.Equal(resultBuf[:n], buf[:n], "decrypted text didn't match plain text with ReadAt interface")

	_ = os.Remove(decryptedTdfFileName)
}

func (s *TDFSuite) createFileName(buf []byte, filename string, size int64) {
	f, err := os.Create(filename)
	s.Require().NoError(err)

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
		s.Require().NoError(err)
	}
	err = f.Close()
	s.Require().NoError(err)
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
	fa := &FakeAttributes{}

	listeners := make(map[string]*bufconn.Listener)
	dialer := func(ctx context.Context, host string) (net.Conn, error) {
		l, ok := listeners[host]
		if !ok {
			slog.ErrorContext(ctx, "unable to dial host!", "ctx", ctx, "host", host)
			return nil, fmt.Errorf("unknown host [%s]", host)
		}
		slog.InfoContext(ctx, "dialing with custom dialer (local grpc)", "ctx", ctx, "host", host)
		return l.Dial()
	}

	s.kases = make([]FakeKas, 9)

	for i, ki := range []struct {
		url, private, public string
	}{
		{"http://localhost:65432/", mockRSAPrivateKey1, mockRSAPublicKey1},
		{"https://a.kas/", mockRSAPrivateKey1, mockRSAPublicKey1},
		{"https://b.kas/", mockRSAPrivateKey2, mockRSAPublicKey2},
		{"https://c.kas/", mockRSAPrivateKey3, mockRSAPublicKey3},
		{kasAu, mockRSAPrivateKey1, mockRSAPublicKey1},
		{kasCa, mockRSAPrivateKey2, mockRSAPublicKey2},
		{lasUk, mockRSAPrivateKey2, mockRSAPublicKey2},
		{kasNz, mockRSAPrivateKey3, mockRSAPublicKey3},
		{kasUs, mockRSAPrivateKey1, mockRSAPublicKey1},
	} {
		grpcListener := bufconn.Listen(1024 * 1024)
		url, err := url.Parse(ki.url)
		s.Require().NoError(err)
		var origin string
		switch {
		case url.Port() == "80":
			origin = url.Hostname()
		case url.Port() != "":
			origin = url.Hostname() + ":" + url.Port()
		case url.Scheme == "https":
			origin = url.Hostname() + ":443"
		default:
			origin = url.Hostname()
		}
		listeners[origin] = grpcListener

		grpcServer := grpc.NewServer()
		s.kases[i] = FakeKas{s: s, privateKey: ki.private, KASInfo: KASInfo{
			URL: ki.url, PublicKey: ki.public, KID: "r1", Algorithm: "rsa:2048"},
			legakeys: map[string]keyInfo{},
		}
		attributespb.RegisterAttributesServiceServer(grpcServer, fa)
		kaspb.RegisterAccessServiceServer(grpcServer, &s.kases[i])
		wellknownpb.RegisterWellKnownServiceServer(grpcServer, fwk)
		go func() {
			err := grpcServer.Serve(grpcListener)
			s.NoError(err)
		}()
	}

	ats := getTokenSource(s.T())

	sdk, err := New("localhost:65432",
		WithClientCredentials("test", "test", nil),
		withCustomAccessTokenSource(&ats),
		WithTokenEndpoint("http://localhost:65432/auth/token"),
		WithInsecurePlaintextConn(),
		WithExtraDialOptions(grpc.WithContextDialer(dialer)))
	s.Require().NoError(err)
	s.sdk = sdk
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

const (
	kasAu     = "https://kas.au/"
	kasCa     = "https://kas.ca/"
	lasUk     = "https://kas.uk/"
	kasNz     = "https://kas.nz/"
	kasUs     = "https://kas.us/"
	kasUsHcs  = "https://hcs.kas.us/"
	kasUsSI   = "https://si.kas.us/"
	authority = "https://virtru.com/"
)

var (
	CLS, _ = autoconfigure.NewAttributeNameFQN("https://virtru.com/attr/Classification")
	N2K, _ = autoconfigure.NewAttributeNameFQN("https://virtru.com/attr/Need%20to%20Know")
	REL, _ = autoconfigure.NewAttributeNameFQN("https://virtru.com/attr/Releasable%20To")

	clsAllowed, _ = autoconfigure.NewAttributeValueFQN("https://virtru.com/attr/Classification/value/Allowed")

	rel2aus, _ = autoconfigure.NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/AUS")
	rel2usa, _ = autoconfigure.NewAttributeValueFQN("https://virtru.com/attr/Releasable%20To/value/USA")
)

func mockAttributeFor(fqn autoconfigure.AttributeNameFQN) *policy.Attribute {
	ns := policy.Namespace{
		Id:   "v",
		Name: "virtru.com",
		Fqn:  "https://virtru.com",
	}
	switch fqn {
	case CLS:
		return &policy.Attribute{
			Id:        "CLS",
			Namespace: &ns,
			Name:      "Classification",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Fqn:       fqn.String(),
		}
	case N2K:
		return &policy.Attribute{
			Id:        "N2K",
			Namespace: &ns,
			Name:      "Need to Know",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Fqn:       fqn.String(),
		}
	case REL:
		return &policy.Attribute{
			Id:        "REL",
			Namespace: &ns,
			Name:      "Releasable To",
			Rule:      policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Fqn:       fqn.String(),
		}
	}
	return nil
}
func mockValueFor(fqn autoconfigure.AttributeValueFQN) *policy.Value {
	an := fqn.Prefix()
	a := mockAttributeFor(an)
	v := fqn.Value()
	p := policy.Value{
		Id:        a.GetId() + ":" + v,
		Attribute: a,
		Value:     v,
		Fqn:       fqn.String(),
	}

	switch an {
	case N2K:
		switch fqn.Value() {
		case "INT":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: lasUk}
		case "HCS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUsHcs}
		case "SI":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUsSI}
		}

	case REL:
		switch fqn.Value() {
		case "FVEY":
			p.Grants = make([]*policy.KeyAccessServer, 5)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasAu}
			p.Grants[1] = &policy.KeyAccessServer{Uri: kasCa}
			p.Grants[2] = &policy.KeyAccessServer{Uri: lasUk}
			p.Grants[3] = &policy.KeyAccessServer{Uri: kasNz}
			p.Grants[4] = &policy.KeyAccessServer{Uri: kasUs}
		case "AUS":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasAu}
		case "CAN":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasCa}
		case "GBR":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: lasUk}
		case "NZL":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasNz}
		case "USA":
			p.Grants = make([]*policy.KeyAccessServer, 1)
			p.Grants[0] = &policy.KeyAccessServer{Uri: kasUs}
		}
	}
	return &p
}

type FakeAttributes struct {
	attributespb.UnimplementedAttributesServiceServer
}

func (f *FakeAttributes) GetAttributeValuesByFqns(_ context.Context, in *attributespb.GetAttributeValuesByFqnsRequest) (*attributespb.GetAttributeValuesByFqnsResponse, error) {
	r := make(map[string]*attributespb.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, fqn := range in.GetFqns() {
		av, err := autoconfigure.NewAttributeValueFQN(fqn)
		if err != nil {
			slog.Error("invalid fqn", "notfqn", fqn, "error", err)
			return nil, status.New(codes.InvalidArgument, fmt.Sprintf("invalid attribute fqn [%s]", fqn)).Err()
		}
		v := mockValueFor(av)
		r[fqn] = &attributespb.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Attribute: v.GetAttribute(),
			Value:     v,
		}
	}
	return &attributespb.GetAttributeValuesByFqnsResponse{FqnAttributeValues: r}, nil
}

type FakeKas struct {
	kaspb.UnimplementedAccessServiceServer
	KASInfo
	privateKey string
	s          *TDFSuite
	legakeys   map[string]keyInfo
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
	f.s.Require().NoError(err, "json.Unmarshal failed")

	wrappedKey, err := ocrypto.Base64Decode([]byte(bodyData.WrappedKey))
	f.s.Require().NoError(err, "ocrypto.Base64Decode failed")

	kasPrivateKey := strings.ReplaceAll(f.privateKey, "\n\t", "\n")
	if bodyData.KID != "" && bodyData.KID != f.KID {
		// old kid
		lk, ok := f.legakeys[bodyData.KID]
		f.s.Require().True(ok, "unable to find key [%s]", bodyData.KID)
		kasPrivateKey = strings.ReplaceAll(lk.private, "\n\t", "\n")
	}

	asymDecrypt, err := ocrypto.NewAsymDecryption(kasPrivateKey)
	f.s.Require().NoError(err, "ocrypto.NewAsymDecryption failed")
	symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
	f.s.Require().NoError(err, "ocrypto.Decrypt failed")
	asymEncrypt, err := ocrypto.NewAsymEncryption(bodyData.ClientPublicKey)
	f.s.Require().NoError(err, "ocrypto.NewAsymEncryption failed")
	entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
	f.s.Require().NoError(err, "ocrypto.encrypt failed")
	return entityWrappedKey
}

func (s *TDFSuite) checkIdentical(file, checksum string) bool {
	f, err := os.Open(file)
	s.Require().NoError(err, "os.Open failed")

	defer func(f *os.File) {
		err := f.Close()
		s.Require().NoError(err, "os.Close failed")
	}(f)

	h := sha256.New()
	_, err = io.Copy(h, f)
	s.Require().NoError(err, "io.Copy failed")

	c := h.Sum(nil)
	return checksum == fmt.Sprintf("%x", c)
}
