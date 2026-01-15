package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"
	attributespb "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	wellknownpb "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	wellknownconnect "github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"github.com/opentdf/platform/sdk/internal/archive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	oneKB      = 1024
	oneMB      = 1024 * 1024
	hundredMB  = 100 * oneMB
	baseKeyKID = "base-key-kid"
	baseKeyURL = "http://base-key.com/"
	defaultKID = "r1"
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
	splitPlan        []keySplitStep
	policy           []AttributeValueFQN
	expectedPlanSize int
	opts             []TDFReaderOption
}

type baseKeyTest struct {
	tdfTest
	encryptOpts []TDFOption
	expectedKID string
	expectedURL string
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
	mockECPrivateKey1 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgokydHKV9HW88nqn9
2U2J1AqvcjrLDRCH6NBdNVqYLJOhRANCAASu1haeL6ckVfALALUlJKsehW8xomA9
dcWMuYTECCukuGCklqiD0ofQAo+stVTRjen+zxM7C6MJaHdsbE4Pf088
-----END PRIVATE KEY-----`
	mockECPublicKey1 = `-----BEGIN CERTIFICATE-----
MIIBcTCCARegAwIBAgIURFydDqs4150ytI73sMRmya2fvTMwCgYIKoZIzj0EAwIw
DjEMMAoGA1UEAwwDa2FzMB4XDTI0MDYxMTAxNTU0N1oXDTI1MDYxMTAxNTU0N1ow
DjEMMAoGA1UEAwwDa2FzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErtYWni+n
JFXwCwC1JSSrHoVvMaJgPXXFjLmExAgrpLhgpJaog9KH0AKPrLVU0Y3p/s8TOwuj
CWh3bGxOD39PPKNTMFEwHQYDVR0OBBYEFLg9mMeD25ZGvmjSYaunIPoeekzlMB8G
A1UdIwQYMBaAFLg9mMeD25ZGvmjSYaunIPoeekzlMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIhALYXC70t37RlmIkRDlUTehiVEHpSQXz04wQ9Ivw+
4h4hAiBNR3rD3KieiJaiJrCfM6TPJL7TIch7pAhMHdG6IPJMoQ==
-----END CERTIFICATE-----`
	mockECPrivateKey2 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgokydHKV9HW88nqn9
2U2J1AqvcjrLDRCH6NBdNVqYLJOhRANCAASu1haeL6ckVfALALUlJKsehW8xomA9
dcWMuYTECCukuGCklqiD0ofQAo+stVTRjen+zxM7C6MJaHdsbE4Pf088
-----END PRIVATE KEY-----`
	mockECPublicKey2 = `-----BEGIN CERTIFICATE-----
MIIBcTCCARegAwIBAgIURFydDqs4150ytI73sMRmya2fvTMwCgYIKoZIzj0EAwIw
DjEMMAoGA1UEAwwDa2FzMB4XDTI0MDYxMTAxNTU0N1oXDTI1MDYxMTAxNTU0N1ow
DjEMMAoGA1UEAwwDa2FzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErtYWni+n
JFXwCwC1JSSrHoVvMaJgPXXFjLmExAgrpLhgpJaog9KH0AKPrLVU0Y3p/s8TOwuj
CWh3bGxOD39PPKNTMFEwHQYDVR0OBBYEFLg9mMeD25ZGvmjSYaunIPoeekzlMB8G
A1UdIwQYMBaAFLg9mMeD25ZGvmjSYaunIPoeekzlMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSAAwRQIhALYXC70t37RlmIkRDlUTehiVEHpSQXz04wQ9Ivw+
4h4hAiBNR3rD3KieiJaiJrCfM6TPJL7TIch7pAhMHdG6IPJMoQ==
-----END CERTIFICATE-----`
)

type TestReadAt struct {
	segmentSize     int64
	dataOffset      int64
	dataLength      int
	expectedPayload string

	whence       int
	writerOffset int
}

type partialReadTdfTest struct {
	payload     string
	kasInfoList []KASInfo
	readAtTests []TestReadAt
}

type assertionTests struct {
	assertions                   []AssertionConfig
	verifiers                    *AssertionVerificationKeys
	disableAssertionVerification bool
	expectedSize                 int
	useHex                       bool
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
	sdk              *SDK
	kases            []FakeKas
	kasTestURLLookup map[string]string
	fakeWellKnown    map[string]interface{}
}

type Policy struct {
	UUID string        `json:"uuid"`
	Body KasPolicyBody `json:"body"`
}

type KasPolicyBody struct {
	DataAttributes []Attribute `json:"dataAttributes"`
	Dissem         []string    `json:"dissem"`
}

type Attribute struct {
	URI           string           `json:"attribute"` // attribute
	PublicKey     crypto.PublicKey `json:"pubKey"`    // pubKey
	ProviderURI   string           `json:"kasUrl"`    // kasUrl
	SchemaVersion string           `json:"tdf_spec_version,omitempty"`
	Name          string           `json:"displayName"` // displayName
}

func (s *TDFSuite) SetupSuite() {
	// Set up the test environment
	s.startBackend()
	// Update well-known with the server URL
	s.fakeWellKnown = createWellKnown(nil)
}

func (s *TDFSuite) SetupTest() {
	s.sdk.clear()
	s.fakeWellKnown = createWellKnown(nil)
}

func TestTDF(t *testing.T) {
	suite.Run(t, new(TDFSuite))
}

func (s *TDFSuite) Test_SimpleTDF() {
	type TestConfig struct {
		name           string
		tdfOptions     []TDFOption
		tdfReadOptions []TDFReaderOption
		useHex         bool
	}

	metaData := []byte(`{"displayName" : "openTDF go sdk"}`)
	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	expectedTdfSize := int64(2058)
	expectedTdfSizeWithHex := int64(2095)
	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"

	// add opts ...TDFOption to  TestConfig
	testConfigs := []TestConfig{
		{
			name: "a",
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}),
			},
		},
		{
			name: "metadata-rsa",
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
				WithTargetMode("0.0.0"),
			},
			tdfReadOptions: []TDFReaderOption{
				WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}),
			},
			useHex: true,
		},
		{
			name: "metadata-ec",
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://d.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
				WithWrappingKeyAlg(ocrypto.EC256Key),
			},
			tdfReadOptions: []TDFReaderOption{
				WithSessionKeyType(ocrypto.EC256Key),
				WithKasAllowlist([]string{s.kasTestURLLookup["https://d.kas/"]}),
			},
		},
		{
			name: "target-mode-0",
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://d.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
				WithWrappingKeyAlg(ocrypto.EC256Key),
				WithTargetMode("0.0.0"),
			},
			tdfReadOptions: []TDFReaderOption{
				WithSessionKeyType(ocrypto.EC256Key),
				WithKasAllowlist([]string{s.kasTestURLLookup["https://d.kas/"]}),
			},
			useHex: true,
		},
	}

	for _, config := range testConfigs {
		s.Run(
			config.name,
			func() {
				inBuf := bytes.NewBufferString(plainText)
				bufReader := bytes.NewReader(inBuf.Bytes())

				fileWriter, err := os.Create(tdfFilename)
				s.Require().NoError(err)

				defer func(fileWriter *os.File) {
					err := fileWriter.Close()
					s.Require().NoError(err)
				}(fileWriter)

				tdfObj, err := s.sdk.CreateTDF(fileWriter, bufReader, config.tdfOptions...)

				s.Require().NoError(err)
				if config.useHex {
					s.InDelta(float64(expectedTdfSizeWithHex), float64(tdfObj.size), 36.0)
				} else {
					s.InDelta(float64(expectedTdfSize), float64(tdfObj.size), 36.0)
				}

				// test meta data and build meta data
				readSeeker, err := os.Open(tdfFilename)
				s.Require().NoError(err)

				defer func(readSeeker *os.File) {
					err := readSeeker.Close()
					s.Require().NoError(err)
				}(readSeeker)

				r, err := s.sdk.LoadTDF(readSeeker, config.tdfReadOptions...)
				s.Require().NoError(err)

				unencryptedMetaData, err := r.UnencryptedMetadata()
				s.Require().NoError(err)
				s.Equal(metaData, unencryptedMetaData)

				dataAttributes, err := r.DataAttributes()
				s.Require().NoError(err)
				s.Equal(attributes, dataAttributes)

				payloadKey, err := r.UnsafePayloadKeyRetrieval()
				s.Require().NoError(err)
				s.Len(payloadKey, kKeySize)

				// check that root sig and seg sig are hex encoded if useHex is true
				b64decodedroot, err := ocrypto.Base64Decode([]byte(r.Manifest().Signature))
				s.Require().NoError(err)
				b64decodedseg, err := ocrypto.Base64Decode([]byte(r.Manifest().EncryptionInformation.Segments[0].Hash))
				s.Require().NoError(err)
				_, err1 := hex.DecodeString(string(b64decodedroot))
				_, err2 := hex.DecodeString(string(b64decodedseg))
				if config.useHex {
					s.Require().NoError(err1)
					s.Require().NoError(err2)
				} else {
					s.Require().Error(err1)
					s.Require().Error(err2)
				}

				// check version is present if usehex is false
				if config.useHex {
					s.Empty(r.Manifest().TDFVersion)
				} else {
					s.Equal(TDFSpecVersion, r.Manifest().TDFVersion)
				}

				// test reader
				readSeeker, err = os.Open(tdfFilename)
				s.Require().NoError(err)

				defer func(readSeeker *os.File) {
					err := readSeeker.Close()
					s.Require().NoError(err)
				}(readSeeker)

				buf := make([]byte, 8)
				r, err = s.sdk.LoadTDF(readSeeker, config.tdfReadOptions...)
				s.Require().NoError(err)

				offset := 2
				n, err := r.ReadAt(buf, int64(offset))
				if err != nil {
					s.Require().ErrorIs(err, io.EOF)
				}

				expectedPlainTxt := plainText[offset : offset+n]
				s.Equal(expectedPlainTxt, string(buf[:n]))

				_ = os.Remove(tdfFilename)
			},
		)
	}
}

func (s *TDFSuite) Test_SystemMetadataAssertions() {
	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	// Configure TDF options with default assertions
	tdfOptions := []TDFOption{
		WithKasInformation(KASInfo{
			URL:       s.kasTestURLLookup["https://a.kas/"],
			PublicKey: "",
		}),
		WithSystemMetadataAssertion(),
		WithDataAttributes(attributes...),
	}

	tdfReadOptions := []TDFReaderOption{
		WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}),
	}

	// Create TDF
	var buf bytes.Buffer
	plainText := "Test Data"

	inBuf := bytes.NewReader([]byte(plainText))
	tdfObj, err := s.sdk.CreateTDF(&buf, inBuf, tdfOptions...)
	s.Require().NoError(err)
	s.Require().NotNil(tdfObj)

	// Load TDF
	r, err := s.sdk.LoadTDF(bytes.NewReader(buf.Bytes()), tdfReadOptions...)
	s.Require().NoError(err)

	// Verify default assertion
	assertions := r.Manifest().Assertions
	s.Require().NoError(err)
	s.Require().NotEmpty(assertions)

	found := false
	for _, assertion := range assertions {
		if assertion.ID == SystemMetadataAssertionID { // Ensure `ID` exists
			found = true

			// Validate JSON in Statement.Value
			var metadata map[string]interface{}
			err := json.Unmarshal([]byte(assertion.Statement.Value), &metadata) // Ensure `Statement.Value` exists
			s.Require().NoError(err, "Statement Value is not valid JSON")

			// Check JSON fields
			s.Equal(TDFSpecVersion, metadata["tdf_spec_version"], "tdf_spec_version mismatch")
			s.Equal(runtime.GOOS, metadata["operating_system"], "operating_system mismatch")
			s.Equal("Go-"+Version, metadata["sdk_version"], "sdk_version mismatch")
			s.Equal(runtime.GOARCH, metadata["architecture"], "architecture mismatch")
			s.Equal(runtime.Version(), metadata["go_version"], "go_version mismatch")
		}
	}
	s.True(found, "System metadata assertion not found")
}

func (s *TDFSuite) Test_TDF_KAS_Allowlist() {
	type TestConfig struct {
		tdfOptions     []TDFOption
		tdfReadOptions []TDFReaderOption
		expectedError  string
	}

	metaData := []byte(`{"displayName" : "openTDF go sdk"}`)
	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}

	tdfFilename := "secure-text.tdf"
	plainText := "Virtru"

	// add opts ...TDFOption to  TestConfig
	testConfigs := []TestConfig{
		{
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}),
			},
		},
		{
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				WithKasAllowlist([]string{"https://nope-not-a-kas.com/kas"}),
			},
			expectedError: "KasAllowlist: kas url " + s.kasTestURLLookup["https://a.kas/"] + " is not allowed",
		},
		{
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				withKasAllowlist(AllowList{"nope-not-a-kas.com": true}),
			},
			expectedError: "KasAllowlist: kas url " + s.kasTestURLLookup["https://a.kas/"] + " is not allowed",
		},
		{
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				WithKasAllowlist([]string{"https://nope-not-a-kas.com/kas"}),
				WithIgnoreAllowlist(true),
			},
		},
		{
			tdfOptions: []TDFOption{
				WithKasInformation(KASInfo{
					URL:       s.kasTestURLLookup["https://a.kas/"],
					PublicKey: "",
				}),
				WithMetaData(string(metaData)),
				WithDataAttributes(attributes...),
			},
			tdfReadOptions: []TDFReaderOption{
				withKasAllowlist(AllowList{"nope-not-a-kas.com": true}),
				WithIgnoreAllowlist(true),
			},
		},
	}

	for _, config := range testConfigs {
		inBuf := bytes.NewBufferString(plainText)
		bufReader := bytes.NewReader(inBuf.Bytes())

		fileWriter, err := os.Create(tdfFilename)
		s.Require().NoError(err)

		defer func(fileWriter *os.File) {
			err := fileWriter.Close()
			s.Require().NoError(err)
		}(fileWriter)

		_, err = s.sdk.CreateTDF(fileWriter, bufReader, config.tdfOptions...)

		s.Require().NoError(err)

		// test meta data and build meta data
		readSeeker, err := os.Open(tdfFilename)
		s.Require().NoError(err)

		defer func(readSeeker *os.File) {
			err := readSeeker.Close()
			s.Require().NoError(err)
		}(readSeeker)

		r, err := s.sdk.LoadTDF(readSeeker, config.tdfReadOptions...)
		s.Require().NoError(err)

		buf := make([]byte, 8)
		s.Require().NoError(err)

		offset := 2
		_, err = r.ReadAt(buf, int64(offset))
		if config.expectedError != "" {
			s.Require().Error(err)
			s.Require().ErrorContains(err, config.expectedError)
		} else if err != nil {
			s.Require().ErrorIs(err, io.EOF)
		}

		_ = os.Remove(tdfFilename)
	}
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
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			verifiers:                    nil,
			disableAssertionVerification: false,
			expectedSize:                 2689,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			verifiers:                    nil,
			disableAssertionVerification: false,
			useHex:                       true,
			expectedSize:                 2896,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
					SigningKey: defaultKey,
				},
			},
			verifiers: &AssertionVerificationKeys{
				DefaultKey: defaultKey,
			},
			disableAssertionVerification: false,
			expectedSize:                 2689,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
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
			verifiers: &AssertionVerificationKeys{
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
			disableAssertionVerification: false,
			expectedSize:                 2988,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			verifiers: &AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					"assertion1": {
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
				},
			},
			disableAssertionVerification: false,
			expectedSize:                 2689,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion2",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			disableAssertionVerification: true,
			expectedSize:                 2180,
		},
	} {
		expectedTdfSize := test.expectedSize
		tdfFilename := "secure-text.tdf"
		plainText := "Virtru"
		{
			kasURLs := []KASInfo{
				{
					URL:       s.kasTestURLLookup["https://a.kas/"],
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

			createOptions := []TDFOption{
				WithKasInformation(kasURLs...),
				WithAssertions(test.assertions...),
			}
			if test.useHex {
				createOptions = append(createOptions, WithTargetMode("0.0.0"))
			}

			tdfObj, err := s.sdk.CreateTDF(fileWriter, bufReader, createOptions...)

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
			if test.verifiers == nil {
				r, err = s.sdk.LoadTDF(readSeeker, WithDisableAssertionVerification(test.disableAssertionVerification), WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}))
			} else {
				r, err = s.sdk.LoadTDF(readSeeker,
					WithAssertionVerificationKeys(*test.verifiers),
					WithDisableAssertionVerification(test.disableAssertionVerification),
					WithKasAllowlist([]string{s.kasTestURLLookup["https://a.kas/"]}))
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

func updateManifest(t *testing.T, tdfFile, outFile string, changer func(t *testing.T, dst io.Writer, f *zip.File) error) error {
	z, err := zip.OpenReader(tdfFile)
	if err != nil {
		return err
	}
	defer func() {
		err := z.Close()
		require.NoError(t, err)
	}()

	unzippedDir := tdfFile + "-unzipped"
	if err := os.MkdirAll(unzippedDir, os.ModePerm); err != nil {
		return err
	}
	defer func() {
		err := os.RemoveAll(unzippedDir)
		require.NoError(t, err)
	}()

	for _, file := range z.File {
		fpath := filepath.Join(unzippedDir, file.Name)
		if file.FileInfo().IsDir() {
			err := os.MkdirAll(fpath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}

		err = changer(t, outFile, file)
		outFile.Close()
		if err != nil {
			return err
		}
	}

	outZip, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer outZip.Close()

	zipWriter := zip.NewWriter(outZip)
	defer zipWriter.Close()

	err = filepath.Walk(unzippedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Name, err = filepath.Rel(unzippedDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Store
		}

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(writer, file)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

/*
	manifestPath := filepath.Join(unzippedDir, "0.manifest.json")
	manifestFile, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}

	var manifestData Manifest
	if err := json.Unmarshal(manifestFile, &manifestData); err != nil {
		return "", err
	}

	newManifestData := manifestChange(manifestData)
	newManifestFile, err := json.Marshal(newManifestData)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(manifestPath, newManifestFile, os.ModePerm); err != nil {
		return "", err
	}
*/

func (s *TDFSuite) Test_TDFWithAssertionNegativeTests() {
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
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
					SigningKey: defaultKey,
				},
			},
			expectedSize: 2689,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
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
			verifiers: &AssertionVerificationKeys{
				// defaultVerificationKey: nil,
				Keys: map[string]AssertionKey{
					"assertion1": {
						Alg: AssertionKeyAlgRS256,
						Key: privateKey.PublicKey,
					},
					"assertion2": {
						Alg: AssertionKeyAlgHS256,
						Key: hs256Key,
					},
				},
			},
			expectedSize: 2988,
		},
		{
			assertions: []AssertionConfig{
				{
					ID:             "assertion1",
					Type:           BaseAssertion,
					Scope:          TrustedDataObjScope,
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
					Scope:          TrustedDataObjScope,
					AppliesToState: Unencrypted,
					Statement: Statement{
						Format: "json",
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value:  "{\"uuid\":\"f74efb60-4a9a-11ef-a6f1-8ee1a61c148a\",\"body\":{\"dataAttributes\":null,\"dissem\":null}}",
					},
				},
			},
			verifiers: &AssertionVerificationKeys{
				DefaultKey: defaultKey,
			},
			expectedSize: 2689,
		},
	} {
		expectedTdfSize := test.expectedSize
		tdfFilename := "secure-text.tdf"
		plainText := "Virtru"
		{
			kasURLs := []KASInfo{
				{
					URL:       s.kasTestURLLookup["https://a.kas/"],
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
			if test.verifiers == nil {
				r, err = s.sdk.LoadTDF(readSeeker)
			} else {
				r, err = s.sdk.LoadTDF(readSeeker, WithAssertionVerificationKeys(*test.verifiers))
			}
			s.Require().NoError(err)

			offset := 2
			_, err = r.ReadAt(buf, int64(offset))
			s.Require().Error(err)
			s.Require().NotErrorIs(err, io.EOF)
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
					URL:       s.kasTestURLLookup["http://localhost:65432/"],
					PublicKey: mockRSAPublicKey1,
				},
				{
					URL:       s.kasTestURLLookup["http://localhost:65432/"],
					PublicKey: mockRSAPublicKey1,
				},
			},
			readAtTests: []TestReadAt{
				{
					segmentSize:     2,
					dataOffset:      26,
					dataLength:      26,
					expectedPayload: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",

					whence:       io.SeekStart,
					writerOffset: 26,
				},
				{
					segmentSize:     2 * oneMB,
					dataOffset:      61,
					dataLength:      1,
					expectedPayload: "9",

					whence:       io.SeekEnd,
					writerOffset: -1,
				},
				{
					segmentSize:     2,
					dataOffset:      0,
					dataLength:      62,
					expectedPayload: payload,

					whence:       io.SeekCurrent,
					writerOffset: 0,
				},
				{
					segmentSize:     int64(len(payload)),
					dataOffset:      0,
					dataLength:      len(payload),
					expectedPayload: payload,

					whence:       io.SeekStart,
					writerOffset: 0,
				},
				{
					segmentSize:     1,
					dataOffset:      26,
					dataLength:      26,
					expectedPayload: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",

					whence:       io.SeekCurrent,
					writerOffset: 26,
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
			{
				buf := bytes.NewBuffer(make([]byte, 0))

				pos, err := r.Seek(int64(readAtTest.writerOffset), readAtTest.whence)
				s.Require().NoError(err)
				s.Equal(readAtTest.dataOffset, pos)

				n, err := r.WriteTo(buf)
				s.Require().NoError(err)

				offset := readAtTest.writerOffset
				if offset < 0 {
					offset = len(payload) + offset
				}
				s.Equal(payload[offset:], buf.String())
				s.Equal(int64(len(buf.Bytes())), n)
			}
		}
	}
}

func (s *TDFSuite) Test_TDFReaderFail() {
	kasInfoList := []KASInfo{
		{
			URL:       s.kasTestURLLookup["http://localhost:65432/api/kas"],
			PublicKey: mockRSAPublicKey1,
		},
		{
			URL:       s.kasTestURLLookup["http://localhost:65432/api/kas"],
			PublicKey: mockRSAPublicKey1,
		},
	}
	for _, test := range []struct {
		name        string
		optFunc     TDFOption
		expectedErr string
	}{
		{
			name: "segmentSizeTooSmall",
			optFunc: func(c *TDFConfig) error {
				c.defaultSegmentSize = 2
				return nil
			},
			expectedErr: "segment size too small: 2",
		},
		{
			name: "segmentSizeTooLarge",
			optFunc: func(c *TDFConfig) error {
				c.defaultSegmentSize = maxSegmentSize + 1
				return nil
			},
			expectedErr: "segment size too large: 4194305",
		},
	} {
		s.Run(test.name, func() {
			_, err := s.sdk.CreateTDF(
				&fakeWriter{},
				bytes.NewReader([]byte{}),
				WithKasInformation(kasInfoList...),
				test.optFunc,
			)
			s.Require().EqualError(err, test.expectedErr)
		})
	}
}

func (s *TDFSuite) Test_ValidateSchema() {
	for index, test := range []struct {
		n       string
		changer func(*testing.T, io.Writer, *zip.File) error
		err     error
		failOn  SchemaValidationIntensity
	}{
		{
			n: "valid",
			changer: func(_ *testing.T, dst io.Writer, f *zip.File) error {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				_, err = io.Copy(dst, rc)
				return err
			},
			err:    nil,
			failOn: unreasonable,
		},
		{
			n: "emptymanifest",
			changer: func(_ *testing.T, dst io.Writer, f *zip.File) error {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				if f.Name == "0.manifest.json" {
					_, err = dst.Write([]byte("{}"))
				} else {
					_, err = io.Copy(dst, rc)
				}
				return err
			},
			err:    ErrInvalidPerSchema,
			failOn: Skip,
		},
		{
			n: "nojsonchange",
			changer: func(_ *testing.T, dst io.Writer, f *zip.File) error {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				// Validate json changer code
				if f.Name != "0.manifest.json" {
					_, err = io.Copy(dst, rc)
					return err
				}
				// Read file from json as a map
				var data map[string]interface{}
				err = json.NewDecoder(rc).Decode(&data)
				if err != nil {
					return err
				}
				// encode data to dst

				err = json.NewEncoder(dst).Encode(data)
				return err
			},
			err:    nil,
			failOn: unreasonable,
		},
		{
			n: "lax",
			changer: func(_ *testing.T, dst io.Writer, f *zip.File) error {
				rc, err := f.Open()
				if err != nil {
					return err
				}

				if f.Name != "0.manifest.json" {
					_, err = io.Copy(dst, rc)
					return err
				}
				// Read file from json as a map
				var data map[string]interface{}
				err = json.NewDecoder(rc).Decode(&data)
				if err != nil {
					return err
				}

				if m, ok := data["payload"].(map[string]interface{}); ok {
					m["tdf_spec_version"] = nil
				} else {
					s.Fail("payload type invalid")
				}

				err = json.NewEncoder(dst).Encode(data)
				return err
			},
			err:    ErrInvalidPerSchema,
			failOn: Strict,
		},
	} {
		s.Run(test.n, func() {
			// create .txt file
			plainTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			s.createFileName(buffer, plainTextFileName, 16)
			defer func() {
				// Remove the test files
				_ = os.Remove(plainTextFileName)
			}()
			tdfFileName := plainTextFileName + ".tdf"

			plainReader, err := os.Open(plainTextFileName)
			s.Require().NoError(err)

			defer func() {
				err := plainReader.Close()
				s.Require().NoError(err)
			}()

			ciphertextWriter, err := os.Create(tdfFileName)
			s.Require().NoError(err)

			defer func() {
				err := ciphertextWriter.Close()
				s.Require().NoError(err)
				err = os.Remove(tdfFileName)
				s.Require().NoError(err)
			}()

			encryptOpts := []TDFOption{
				WithKasInformation(s.kases[0].KASInfo),
				WithAutoconfigure(false),
			}

			// test encrypt
			_, err = s.sdk.CreateTDF(ciphertextWriter, plainReader, encryptOpts...)
			s.Require().NoError(err)

			alteredFileName := "altered-" + tdfFileName
			s.Require().NoError(updateManifest(s.T(), tdfFileName, alteredFileName, test.changer))

			cipherText, err := os.Open(alteredFileName)
			s.Require().NoError(err)

			defer func() {
				err := cipherText.Close()
				s.Require().NoError(err)
				_ = os.Remove(alteredFileName)
			}()

			for _, svi := range []SchemaValidationIntensity{Skip, Lax, Strict} {
				r, err := s.sdk.LoadTDF(cipherText, WithSchemaValidation(svi))
				switch {
				case test.failOn > svi:
					s.Require().NoError(err, "error should be nil at %s", svi)
				case test.err != nil && svi > Skip:
					// can either fail here or on first read (ie in Copy below)
					// Errors on 'skip' won't match the expected error type, though.
					if test.err != nil {
						s.Require().ErrorIs(err, test.err, "[%v] at %s", err, svi)
					} else {
						s.Require().Error(err, "at %s", svi)
					}
					continue
				default:
					s.Require().NoError(err, "[%v] at %s", err, svi)
				}

				if test.failOn > svi {
					n, err := io.Copy(io.Discard, r)
					s.Require().NoError(err, "at %s", svi)
					s.Equal(int64(16), n)
				} else {
					_, err := io.Copy(io.Discard, r)
					if test.err != nil && svi != Skip {
						s.Require().ErrorIs(err, test.err, "[%v] at %s", err, svi)
					} else {
						s.Require().Error(err, "[%v] at %s", err, svi)
					}
				}
			}
		})
	}
}

func (s *TDFSuite) Test_DefaultTDF() {
	for index, test := range []tdfTest{
		{
			n:           "small",
			fileSize:    5,
			tdfFileSize: 1560,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		},
		{
			n:           "small-with-mime-type",
			fileSize:    5,
			tdfFileSize: 1560,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			mimeType:    "text/plain",
		},
		{
			n:           "1-kiB",
			fileSize:    oneKB,
			tdfFileSize: 2598,
			checksum:    "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
		},
		{
			n:           "medium",
			fileSize:    hundredMB,
			tdfFileSize: 104866427,
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
			s.testEncrypt(s.sdk, []TDFOption{WithKasInformation(kasInfoList...)}, plaintTextFileName, tdfFileName, test)

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_MixedBaseKeyTest() {
	baseKey := createTestBaseKeyMap(&s.Suite, policy.Algorithm_ALGORITHM_RSA_2048, baseKeyKID, mockRSAPublicKey1, s.kasTestURLLookup[baseKeyURL])
	s.fakeWellKnown = createWellKnown(baseKey)
	attrVal := mockValueFor(rel2aus)
	for index, test := range []baseKeyTest{
		{
			tdfTest: tdfTest{
				n:           "medium",
				fileSize:    hundredMB,
				tdfFileSize: 104866427,
				checksum:    "cee41e98d0a6ad65cc0ec77a2ba50bf26d64dc9007f7f1c7d7df68b8b71291a6",
			},
			encryptOpts: []TDFOption{},
			expectedKID: baseKeyKID,
			expectedURL: s.kasTestURLLookup[baseKeyURL],
		},
		{
			tdfTest: tdfTest{
				n:           "medium_attributes_skip_base_key",
				fileSize:    hundredMB,
				tdfFileSize: 104866427,
				checksum:    "cee41e98d0a6ad65cc0ec77a2ba50bf26d64dc9007f7f1c7d7df68b8b71291a6",
			},
			encryptOpts: []TDFOption{WithDataAttributes(attrVal.GetFqn())},
			expectedKID: defaultKID,
			expectedURL: s.kasTestURLLookup[kasAu],
		},
	} {
		s.Run(test.n, func() {
			// create .txt file
			plaintTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plaintTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			defer func() {
				// Remove the test files
				_ = os.Remove(plaintTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// test encrypt
			tdfObj := s.testEncrypt(s.sdk, test.encryptOpts, plaintTextFileName, tdfFileName, test.tdfTest)
			s.Require().Equal(test.expectedKID, tdfObj.manifest.KeyAccessObjs[0].KID, "Base key KID should match")
			s.Require().Equal(test.expectedURL, tdfObj.manifest.KeyAccessObjs[0].KasURL, "KAS URI should match")
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test.tdfTest)
		})
	}
}

/*
The context for this test is that we want to be able to encrypt a TDF with multiple keys
of the same KAS with the same algorithm, but of different KIDs.

The test creates mocks of attribute values which are then pulled from
granter_test.go, which return the simple kas key mappings. (r0, r2)
Both are of type RSA 2048, and the KAS is the same for both.
*/
func (s *TDFSuite) Test_KeySplit_SameKas_SameAlgorithm() {
	attrVal1 := mockValueFor(mpc)
	attrVal2 := mockValueFor(mpd)

	// Add a key to the kas for proper decryption.
	// * Note: This is a hack to get around having to handle multiple
	// * keys within our testing structure. Ultimately we should
	// * modify the test infra to handle multiple active keys
	for _, fakeKas := range s.kases {
		if fakeKas.URL == s.kasTestURLLookup[evenMoreSpecificKas] {
			old := &fakeKas
			fakeKas.privateKey = mockRSAPrivateKey1
			fakeKas.KID = "r0"
			fakeKas.KASInfo.PublicKey = mockRSAPublicKey1
			fakeKas.legakeys[old.KID] = keyInfo{old.KID, old.privateKey, old.KASInfo.PublicKey}
		}
	}

	for index, test := range []tdfTest{
		{
			n:           "multiple-keys-same-kas-same-algorithm",
			fileSize:    5,
			tdfFileSize: 2581,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
		},
	} {
		s.Run(test.n, func() {
			// create .txt file
			plainTextFileName := test.n + "-" + strconv.Itoa(index) + ".txt"
			tdfFileName := plainTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			defer func() {
				// Remove the test files
				_ = os.Remove(plainTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// test encrypt
			tdo := s.testEncrypt(s.sdk, []TDFOption{WithDataAttributes(attrVal1.GetFqn(), attrVal2.GetFqn())}, plainTextFileName, tdfFileName, test)
			s.Len(tdo.manifest.KeyAccessObjs, 2, "Should have two key access objects")
			s.Equal("r0", tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KID)
			s.Equal("r3", tdo.manifest.EncryptionInformation.KeyAccessObjs[1].KID)
			s.Equal(s.kasTestURLLookup[evenMoreSpecificKas], tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KasURL)
			s.Equal(s.kasTestURLLookup[evenMoreSpecificKas], tdo.manifest.EncryptionInformation.KeyAccessObjs[1].KasURL)

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

			tdo := s.testEncrypt(s.sdk, []TDFOption{WithKasInformation(kasInfoList...)}, plainTextFileName, tdfFileName, test)
			s.Equal(defaultKID, tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KID)

			defer rotateKey(&s.kases[0], "r2", mockRSAPrivateKey2, mockRSAPublicKey2)()
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)

			kasInfoList[0].PublicKey = ""
			kasInfoList[0].KID = ""
			s.sdk.clear()
			tdo2 := s.testEncrypt(s.sdk, []TDFOption{WithKasInformation(kasInfoList...)}, tdf2Name, tdfFileName, test)
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
			tdfFileSize: 2759,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []keySplitStep{
				{KAS: s.kasTestURLLookup["https://a.kas/"], SplitID: "a"},
				{KAS: s.kasTestURLLookup["https://b.kas/"], SplitID: "a"},
				{KAS: s.kasTestURLLookup[`https://c.kas/`], SplitID: "a"},
			},
		},
		{
			n:           "split",
			fileSize:    5,
			tdfFileSize: 2759,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []keySplitStep{
				{KAS: s.kasTestURLLookup["https://a.kas/"], SplitID: "a"},
				{KAS: s.kasTestURLLookup["https://b.kas/"], SplitID: "b"},
				{KAS: s.kasTestURLLookup["https://c.kas/"], SplitID: "c"},
			},
		},
		{
			n:           "mixture",
			fileSize:    5,
			tdfFileSize: 3351,
			checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			splitPlan: []keySplitStep{
				{KAS: s.kasTestURLLookup["https://a.kas/"], SplitID: "a"},
				{KAS: s.kasTestURLLookup["https://b.kas/"], SplitID: "a"},
				{KAS: s.kasTestURLLookup["https://b.kas/"], SplitID: "b"},
				{KAS: s.kasTestURLLookup["https://c.kas/"], SplitID: "b"},
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
			tdo := s.testEncrypt(s.sdk, []TDFOption{WithKasInformation(kasInfoList...)}, plaintTextFileName, tdfFileName, test)
			s.Equal(test.splitPlan[0].KAS, tdo.manifest.EncryptionInformation.KeyAccessObjs[0].KasURL)
			s.Len(tdo.manifest.KeyAccessObjs, len(test.splitPlan))

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_Obligations_Decrypt() {
	for _, test := range []struct {
		n                      string
		fileSize               int64
		tdfFileSize            float64
		checksum               string
		requiredObligationFQNs []string
		opts                   []TDFOption
		fulfillableObligations []string
		attrValueFQNs          []AttributeValueFQN
		expectError            bool
	}{
		{
			n:                      "two-attributes-same-kas-with-fulfillable-obligations",
			fileSize:               5,
			tdfFileSize:            1909,
			checksum:               "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			requiredObligationFQNs: []string{obligationWatermark, obligationGeofence},
			opts:                   []TDFOption{WithDataAttributes(oa1.key, oa2.key)}, // Both go to obligationKas
			fulfillableObligations: []string{obligationWatermark, obligationGeofence},
			attrValueFQNs:          []AttributeValueFQN{oa1, oa2},
			expectError:            false,
		},
		{
			n:                      "two-attributes-same-kas-no-fulfillable-obligations",
			fileSize:               5,
			tdfFileSize:            1909,
			checksum:               "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			requiredObligationFQNs: []string{obligationWatermark, obligationGeofence},
			opts:                   []TDFOption{WithDataAttributes(oa1.key, oa2.key)},
			fulfillableObligations: []string{}, // No fulfillable obligations
			expectError:            true,
		},
		{
			n:                      "fulfill-one-of-two-attributes-same-kas",
			fileSize:               5,
			tdfFileSize:            1909,
			checksum:               "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			requiredObligationFQNs: []string{obligationWatermark, obligationGeofence},
			opts:                   []TDFOption{WithDataAttributes(oa1.key, oa2.key)},
			fulfillableObligations: []string{obligationWatermark},
			expectError:            true,
		},
	} {
		s.Run(test.n, func() {
			// Create a new SDK instance with limited fulfillable obligations
			plainTextFileName := test.n + ".txt"
			tdfFileName := plainTextFileName + ".tdf"
			decryptedTdfFileName := tdfFileName + ".txt"

			defer func() {
				// Remove the test files
				_ = os.Remove(plainTextFileName)
				_ = os.Remove(tdfFileName)
				_ = os.Remove(decryptedTdfFileName)
			}()

			// test encrypt using the default SDK (which has all fulfillable obligations)
			s.testEncrypt(s.sdk, test.opts, plainTextFileName, tdfFileName, tdfTest{
				n:           test.n,
				fileSize:    test.fileSize,
				tdfFileSize: test.tdfFileSize,
				checksum:    test.checksum,
			})

			readSeeker, err := os.Open(tdfFileName)
			s.Require().NoError(err)
			defer func(readSeeker *os.File) {
				err := readSeeker.Close()
				s.Require().NoError(err)
			}(readSeeker)

			r, err := s.sdk.LoadTDF(readSeeker)
			s.Require().NoError(err)
			r.config.fulfillableObligationFQNs = test.fulfillableObligations

			if !test.expectError {
				// Validate successful decryption
				s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, tdfTest{
					n:        test.n,
					fileSize: test.fileSize,
					checksum: test.checksum,
					policy:   test.attrValueFQNs,
					opts:     []TDFReaderOption{WithTDFFulfillableObligationFQNs(test.fulfillableObligations)},
				})

				_, err = r.WriteTo(io.Discard)
				s.Require().NoError(err)
			} else {
				// The decryption should fail due to unmet obligations
				_, err = r.WriteTo(io.Discard)
				s.Require().Error(err, "Decryption should fail when obligations are not met")
			}

			obligations, err := r.Obligations(s.T().Context())
			s.Require().NoError(err)
			s.Require().NotNil(obligations, "Obligations should not be nil")
			s.Require().Len(obligations.FQNs, len(test.requiredObligationFQNs), "Should have correct number of obligations")
			actualObligations := obligations
			for _, ob := range test.requiredObligationFQNs {
				s.Require().Contains(actualObligations.FQNs, ob, "Actual obligations should contain "+ob)
			}
		})
	}
}

func (s *TDFSuite) Test_Obligations() {
	originalV2 := s.sdk.AuthorizationV2
	defer func() {
		s.sdk.AuthorizationV2 = originalV2
	}()

	// Define test cases covering all code paths in Obligations()
	testCases := []struct {
		name                      string
		requiredObligations       []string
		fulfillableObligationFQNs []string
		shouldReturnError         bool
		expectedError             error
		prepopulatedObligations   []string
		dataAttributes            []string
		expectedSize              float64
	}{
		{
			name:                      "Rewrap not called prior - Populate from Init() - No Error",
			fulfillableObligationFQNs: []string{obligationWatermark},
			requiredObligations:       []string{obligationWatermark},
			dataAttributes:            []string{oa1.key},
			shouldReturnError:         false,
			expectedError:             nil,
			expectedSize:              1737,
		},
		{
			// This test does not actually Rewrap, if it did we would have a mismatch
			// set of required obligations.
			name:                      "Rewrap called previously - No Error",
			requiredObligations:       []string{obligationGeofence},
			fulfillableObligationFQNs: []string{obligationGeofence},
			dataAttributes:            []string{oa1.key},
			shouldReturnError:         false,
			expectedError:             nil,
			prepopulatedObligations:   []string{obligationGeofence},
			expectedSize:              1737,
		},
		{
			name:                      "Rewrap not called previously - No required obligations",
			requiredObligations:       []string{},
			fulfillableObligationFQNs: []string{},
			dataAttributes:            []string{},
			shouldReturnError:         false,
			expectedError:             nil,
			expectedSize:              1573,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// Create test files for each test case
			plainTextFileName := fmt.Sprintf("obligations_%s.txt", strings.ReplaceAll(tc.name, " ", "_"))
			tdfFileName := plainTextFileName + ".tdf"

			defer func() {
				_ = os.Remove(plainTextFileName)
				_ = os.Remove(tdfFileName)
			}()

			// Encrypt the TDF file for testing
			opts := []TDFOption{WithKasInformation(s.kases[0].KASInfo), WithDataAttributes(tc.dataAttributes...)}
			s.testEncrypt(s.sdk, opts, plainTextFileName, tdfFileName, tdfTest{
				n:           strings.ReplaceAll(tc.name, " ", "_"),
				fileSize:    5,
				tdfFileSize: tc.expectedSize,
				checksum:    "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			})

			// Load TDF with specified fulfillable obligations
			readSeeker, err := os.Open(tdfFileName)
			s.Require().NoError(err)
			defer func(readSeeker *os.File) {
				err := readSeeker.Close()
				s.Require().NoError(err)
			}(readSeeker)

			var loadOpts []TDFReaderOption
			if len(tc.fulfillableObligationFQNs) > 0 {
				loadOpts = append(loadOpts, WithTDFFulfillableObligationFQNs(tc.fulfillableObligationFQNs))
			}

			r, err := s.sdk.LoadTDF(readSeeker, loadOpts...)
			s.Require().NoError(err)

			// Verify fulfillable obligations were set correctly
			if len(tc.fulfillableObligationFQNs) > 0 {
				s.Require().Len(r.config.fulfillableObligationFQNs, len(tc.fulfillableObligationFQNs), "Should have correct number of fulfillable obligations")
				for _, ob := range tc.fulfillableObligationFQNs {
					s.Require().Contains(r.config.fulfillableObligationFQNs, ob, "Should contain fulfillable obligation "+ob)
				}
			}

			if tc.prepopulatedObligations != nil {
				r.requiredObligations = &RequiredObligations{FQNs: tc.prepopulatedObligations}
			}

			// First call to Obligations() - calls Init()
			obligations, err := r.Obligations(s.T().Context())

			if tc.shouldReturnError {
				s.Require().Error(err, "Expected error for test case: %s", tc.name)
				if tc.expectedError != nil {
					s.Require().ErrorIs(err, tc.expectedError, "Error should be of expected type")
				}
				return
			}

			s.Require().NoError(err, "Should not return error for test case: %s", tc.name)
			s.Require().NotNil(obligations, "Obligations should not be nil")
			s.Require().Len(obligations.FQNs, len(tc.requiredObligations), "Should have correct number of obligations")
			for _, ob := range tc.requiredObligations {
				s.Require().Contains(obligations.FQNs, ob, "Actual obligations should contain "+ob)
			}

			// Second call to Obligations()
			obligations2, err := r.Obligations(s.T().Context())
			s.Require().NoError(err, "Second call should not return error")
			s.Require().NotNil(obligations2, "Second call obligations should not be nil")
			s.Require().Equal(obligations, obligations2, "Second call should return same obligations")
		})
	}
}

func TestDedupRequiredObligations(t *testing.T) {
	testCases := []struct {
		name           string
		kaoResults     []kaoResult
		expectedResult []string
	}{
		{
			name:           "empty input",
			kaoResults:     []kaoResult{},
			expectedResult: []string{},
		},
		{
			name: "single kao with no obligations",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{},
				},
			},
			expectedResult: []string{},
		},
		{
			name: "single kao with single obligation",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
			},
			expectedResult: []string{"https://demo.com/obl/test/value/watermark"},
		},
		{
			name: "single kao with multiple obligations",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID: "kao-1",
					RequiredObligations: []string{
						"https://demo.com/obl/test/value/watermark",
						"https://demo.com/obl/test/value/geofence",
					},
				},
			},
			expectedResult: []string{
				"https://demo.com/obl/test/value/watermark",
				"https://demo.com/obl/test/value/geofence",
			},
		},
		{
			name: "multiple kaos with same obligations - should dedupe",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
				{
					KeyAccessObjectID:   "kao-2",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
			},
			expectedResult: []string{"https://demo.com/obl/test/value/watermark"},
		},
		{
			name: "multiple kaos with different obligations",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
				{
					KeyAccessObjectID:   "kao-2",
					RequiredObligations: []string{"https://demo.com/obl/test/value/geofence"},
				},
			},
			expectedResult: []string{
				"https://demo.com/obl/test/value/watermark",
				"https://demo.com/obl/test/value/geofence",
			},
		},
		{
			name: "case insensitive deduplication",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{"https://demo.com/obl/test/value/WATERMARK"},
				},
				{
					KeyAccessObjectID:   "kao-2",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
			},
			expectedResult: []string{"https://demo.com/obl/test/value/watermark"},
		},
		{
			name: "whitespace trimming and deduplication",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID:   "kao-1",
					RequiredObligations: []string{" https://demo.com/obl/test/value/watermark "},
				},
				{
					KeyAccessObjectID:   "kao-2",
					RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
				},
			},
			expectedResult: []string{"https://demo.com/obl/test/value/watermark"},
		},
		{
			name: "complex case - mixed duplicates with case and whitespace variations",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID: "kao-1",
					RequiredObligations: []string{
						"https://demo.com/obl/test/value/WATERMARK",
						"https://demo.com/obl/test/value/geofence",
					},
				},
				{
					KeyAccessObjectID: "kao-2",
					RequiredObligations: []string{
						" https://demo.com/obl/test/value/watermark ",
						"https://demo.com/obl/test/value/ENCRYPTION",
					},
				},
				{
					KeyAccessObjectID: "kao-3",
					RequiredObligations: []string{
						"https://demo.com/obl/test/value/geofence",
						"https://demo.com/obl/test/value/encryption",
					},
				},
			},
			expectedResult: []string{
				"https://demo.com/obl/test/value/watermark",
				"https://demo.com/obl/test/value/geofence",
				"https://demo.com/obl/test/value/encryption",
			},
		},
		{
			name: "empty string obligations should be normalized",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID: "kao-1",
					RequiredObligations: []string{
						"",
						"   ",
						"https://demo.com/obl/test/value/watermark",
					},
				},
			},
			expectedResult: []string{
				"https://demo.com/obl/test/value/watermark",
			},
		},
		{
			name: "preserve order of first occurrence",
			kaoResults: []kaoResult{
				{
					KeyAccessObjectID: "kao-1",
					RequiredObligations: []string{
						"https://demo.com/obl/test/value/geofence",
						"https://demo.com/obl/test/value/watermark",
					},
				},
				{
					KeyAccessObjectID: "kao-2",
					RequiredObligations: []string{
						"https://demo.com/obl/test/value/watermark",
						"https://demo.com/obl/test/value/geofence",
					},
				},
			},
			expectedResult: []string{
				"https://demo.com/obl/test/value/geofence",
				"https://demo.com/obl/test/value/watermark",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := dedupRequiredObligations(tc.kaoResults)
			assert.Equal(t, tc.expectedResult, result, "Deduplication result should match expected")
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
			policy:           []AttributeValueFQN{clsA},
			expectedPlanSize: 1,
		},
		{
			n:                "ac-relto",
			fileSize:         5,
			tdfFileSize:      2517,
			checksum:         "ed968e840d10d2d313a870bc131a4e2c311d7ad09bdf32b3418147221f51a6e2",
			policy:           []AttributeValueFQN{rel2aus, rel2usa},
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
			s.sdk.kasKeyCache.store(KASInfo{})

			// test encrypt
			tdo := s.testEncrypt(s.sdk, []TDFOption{WithKasInformation(kasInfoList...)}, plaintTextFileName, tdfFileName, test)
			s.Len(tdo.manifest.KeyAccessObjs, test.expectedPlanSize)

			// test decrypt with reader
			s.testDecryptWithReader(s.sdk, tdfFileName, decryptedTdfFileName, test)
		})
	}
}

func (s *TDFSuite) Test_PopulateBaseKey_Success() {
	tdfConfig := &TDFConfig{
		preferredKeyWrapAlg: ocrypto.RSA2048Key,
		kasInfoList:         []KASInfo{},
	}

	baseKey := policy.SimpleKasKey{
		KasUri: s.kasTestURLLookup[baseKeyURL],
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       baseKeyKID,
			Pem:       mockRSAPublicKey1,
		},
	}

	// Call populateBaseKey, should succeed
	err := populateKasInfoFromBaseKey(&baseKey, tdfConfig)
	s.Require().NoError(err, "populateBaseKey should succeed with valid base key")

	expectedURL := s.kasTestURLLookup[baseKeyURL]
	s.Require().NotEmpty(expectedURL, "Expected KAS URL should not be empty")

	// Verify KAS info list has been populated correctly
	s.Require().Len(tdfConfig.kasInfoList, 1, "KAS info list should have one entry")
	s.Require().Equal(expectedURL, tdfConfig.kasInfoList[0].URL, "KAS URL should match")
	s.Require().Equal(baseKeyKID, tdfConfig.kasInfoList[0].KID, "KAS KID should match")
	s.Require().Equal(string(ocrypto.RSA2048Key), tdfConfig.kasInfoList[0].Algorithm, "Algorithm should match")
	s.Require().Equal(mockRSAPublicKey1, tdfConfig.kasInfoList[0].PublicKey, "Public key should match")
	s.Require().Equal(ocrypto.KeyType("rsa:2048"), tdfConfig.preferredKeyWrapAlg, "Key type should be set")
}

func rotateKey(k *FakeKas, kid, private, public string) func() {
	old := *k
	k.privateKey = private
	k.KID = kid
	k.KASInfo.PublicKey = public
	k.legakeys[old.KID] = keyInfo{old.KID, old.privateKey, old.KASInfo.PublicKey}
	return func() {
		delete(k.legakeys, old.KID)
		k.privateKey = old.privateKey
		k.KID = old.KID
		k.KASInfo.PublicKey = old.KASInfo.PublicKey
	}
}

func (s *TDFSuite) Test_LargeManifest_WithMaxManifest() {
	const maxManifestSize = 1024 * 1024 // 1MB

	// Helper to create a large manifest JSON string
	createLargeManifest := func(size int) []byte {
		manifest := map[string]interface{}{
			"payload": map[string]interface{}{
				"data": string(bytes.Repeat([]byte{'a'}, size)),
			},
			"tdf_spec_version": TDFSpecVersion,
		}
		b, err := json.Marshal(manifest)
		s.Require().NoError(err)
		return b
	}

	// Helper to create a TDF file in memory for testing
	createTestTDF := func(manifest []byte, payload []byte) *bytes.Reader {
		tdfBuffer := new(bytes.Buffer)
		tdfWriter := archive.NewTDFWriter(tdfBuffer)

		// Add payload
		err := tdfWriter.SetPayloadSize(int64(len(payload)))
		s.Require().NoError(err)
		err = tdfWriter.AppendPayload(payload)
		s.Require().NoError(err)

		// Add manifest
		err = tdfWriter.AppendManifest(string(manifest))
		s.Require().NoError(err)

		_, err = tdfWriter.Finish()
		s.Require().NoError(err)

		return bytes.NewReader(tdfBuffer.Bytes())
	}

	// Case 1: Manifest just below the limit
	manifestBelow := createLargeManifest(maxManifestSize - 100)
	tdfBelow := createTestTDF(manifestBelow, []byte("payload"))
	_, err := s.sdk.LoadTDF(tdfBelow, WithMaxManifestSize(maxManifestSize))
	s.Require().NoError(err, "Manifest below max size should load successfully")

	// Case 2: Manifest just above the limit
	manifestAbove := createLargeManifest(maxManifestSize + 100)
	tdfAbove := createTestTDF(manifestAbove, []byte("payload"))
	_, err = s.sdk.LoadTDF(tdfAbove, WithMaxManifestSize(maxManifestSize))
	s.Require().Error(err, "Manifest above max size should fail to load")
	s.Require().ErrorContains(err, "size too large")
}

// create tdf
func (s *TDFSuite) testEncrypt(sdk *SDK, encryptOpts []TDFOption, plainTextFilename, tdfFileName string, test tdfTest) *TDFObject {
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

	r, err := sdk.LoadTDF(readSeeker, test.opts...)
	s.Require().NoError(err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(300*time.Minute))
	defer cancel()
	err = r.Init(ctx)
	s.Require().NoError(err)
	s.Require().NotNil(r.payloadKey)

	if test.mimeType != "" {
		s.Equal(test.mimeType, r.Manifest().MimeType, "mimeType does not match")
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

func createWellKnown(baseKey map[string]interface{}) map[string]interface{} {
	wellKnown := map[string]interface{}{
		"health": map[string]interface{}{
			"endpoint": "/healthz",
		},
		"idp": map[string]interface{}{
			"issuer": "http://localhost:65432/auth",
		},
	}

	if baseKey != nil {
		wellKnown[baseKeyWellKnown] = baseKey
	}

	// Create a stub for wellknown
	return wellKnown
}

func (s *TDFSuite) startBackend() {
	defer resolver.SetDefaultScheme(resolver.GetDefaultScheme())
	resolver.SetDefaultScheme("passthrough")

	baseKey := createTestBaseKeyMap(&s.Suite, policy.Algorithm_ALGORITHM_RSA_2048, baseKeyKID, mockRSAPublicKey1, "")
	s.fakeWellKnown = createWellKnown(baseKey)
	fwk := &FakeWellKnown{s: s}
	fa := &FakeAttributes{s: s}

	kasesToMake := []struct {
		url, private, public, kid string
	}{
		{"http://localhost:65432/", mockRSAPrivateKey1, mockRSAPublicKey1, defaultKID},
		{"http://[::1]:65432/", mockRSAPrivateKey1, mockRSAPublicKey1, defaultKID},
		{"https://a.kas/", mockRSAPrivateKey1, mockRSAPublicKey1, defaultKID},
		{"https://b.kas/", mockRSAPrivateKey2, mockRSAPublicKey2, defaultKID},
		{"https://c.kas/", mockRSAPrivateKey3, mockRSAPublicKey3, defaultKID},
		{"https://d.kas/", mockECPrivateKey1, mockECPublicKey1, "e1"},
		{"https://e.kas/", mockECPrivateKey2, mockECPublicKey2, defaultKID},
		{kasAu, mockRSAPrivateKey1, mockRSAPublicKey1, defaultKID},
		{kasCa, mockRSAPrivateKey2, mockRSAPublicKey2, defaultKID},
		{kasUk, mockRSAPrivateKey2, mockRSAPublicKey2, defaultKID},
		{kasNz, mockRSAPrivateKey3, mockRSAPublicKey3, defaultKID},
		{kasUs, mockRSAPrivateKey1, mockRSAPublicKey1, defaultKID},
		{baseKeyURL, mockRSAPrivateKey1, mockRSAPublicKey1, baseKeyKID},
		{evenMoreSpecificKas, mockRSAPrivateKey3, mockRSAPublicKey3, "r3"},
		{obligationKas, mockRSAPrivateKey3, mockRSAPublicKey3, "r3"},
	}
	fkar := &FakeKASRegistry{kases: kasesToMake, s: s}

	s.kases = make([]FakeKas, len(kasesToMake))

	s.kasTestURLLookup = make(map[string]string, len(kasesToMake))

	var sdkPlatformURL string

	for i, ki := range kasesToMake {
		mux := http.NewServeMux()

		s.kases[i] = FakeKas{
			s: s, privateKey: ki.private, KASInfo: KASInfo{
				URL: ki.url, PublicKey: ki.public, KID: ki.kid, Algorithm: "rsa:2048",
			},
			legakeys:                  map[string]keyInfo{},
			attrToRequiredObligations: obligationMap,
		}
		path, handler := attributesconnect.NewAttributesServiceHandler(fa)
		mux.Handle(path, handler)
		kasPath, kasHandler := kasconnect.NewAccessServiceHandler(&s.kases[i])
		mux.Handle(kasPath, kasHandler)
		path, handler = wellknownconnect.NewWellKnownServiceHandler(fwk)
		mux.Handle(path, handler)
		path, handler = kasregistryconnect.NewKeyAccessServerRegistryServiceHandler(fkar)
		mux.Handle(path, handler)

		server := httptest.NewServer(mux)

		// add to lookup reg
		s.kasTestURLLookup[s.kases[i].URL] = server.URL
		// replace kasinfo url with httptest server url
		s.kases[i].URL = server.URL

		if i == 0 {
			sdkPlatformURL = server.URL
		}
	}

	ats := getTokenSource(s.T())

	sdk, err := New(sdkPlatformURL,
		WithClientCredentials("test", "test", nil),
		withCustomAccessTokenSource(&ats),
		WithTokenEndpoint("http://localhost:65432/auth/token"),
		WithInsecurePlaintextConn(),
	)
	s.Require().NoError(err)
	s.sdk = sdk
}

type FakeWellKnown struct {
	wellknownconnect.UnimplementedWellKnownServiceHandler
	s *TDFSuite
}

func (f *FakeWellKnown) GetWellKnownConfiguration(_ context.Context, _ *connect.Request[wellknownpb.GetWellKnownConfigurationRequest]) (*connect.Response[wellknownpb.GetWellKnownConfigurationResponse], error) {
	cfg, err := structpb.NewStruct(f.s.fakeWellKnown)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&wellknownpb.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}), nil
}

type FakeAttributes struct {
	attributesconnect.UnimplementedAttributesServiceHandler
	s *TDFSuite
}

func (f *FakeAttributes) GetAttributeValuesByFqns(_ context.Context, in *connect.Request[attributespb.GetAttributeValuesByFqnsRequest]) (*connect.Response[attributespb.GetAttributeValuesByFqnsResponse], error) {
	r := make(map[string]*attributespb.GetAttributeValuesByFqnsResponse_AttributeAndValue)
	for _, fqn := range in.Msg.GetFqns() {
		av, err := NewAttributeValueFQN(fqn)
		if err != nil {
			slog.Error("invalid fqn",
				slog.String("fqn", fqn),
				slog.Any("error", err),
			)
			return nil, status.New(codes.InvalidArgument, fmt.Sprintf("invalid attribute fqn [%s]", fqn)).Err()
		}
		v := mockValueFor(av)
		for i := range v.GetGrants() {
			v.Grants[i].Uri = f.s.kasTestURLLookup[v.GetGrants()[i].GetUri()]
		}
		for i := range v.GetKasKeys() {
			v.KasKeys[i].KasUri = f.s.kasTestURLLookup[v.GetKasKeys()[i].GetKasUri()]
		}
		r[fqn] = &attributespb.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Attribute: v.GetAttribute(),
			Value:     v,
		}
	}
	return connect.NewResponse(&attributespb.GetAttributeValuesByFqnsResponse{FqnAttributeValues: r}), nil
}

type FakeKASRegistry struct {
	kasregistryconnect.UnimplementedKeyAccessServerRegistryServiceHandler
	s     *TDFSuite
	kases []struct {
		url, private, public, kid string
	}
}

func (f *FakeKASRegistry) ListKeyAccessServers(_ context.Context, _ *connect.Request[kasregistry.ListKeyAccessServersRequest]) (*connect.Response[kasregistry.ListKeyAccessServersResponse], error) {
	resp := &kasregistry.ListKeyAccessServersResponse{
		KeyAccessServers: make([]*policy.KeyAccessServer, 0, len(f.kases)),
	}

	for _, k := range f.kases {
		kas := &policy.KeyAccessServer{
			Uri: f.s.kasTestURLLookup[k.url],
		}
		resp.KeyAccessServers = append(resp.KeyAccessServers, kas)
	}

	return connect.NewResponse(resp), nil
}

type FakeKas struct {
	kasconnect.UnimplementedAccessServiceHandler
	KASInfo
	privateKey                string
	s                         *TDFSuite
	legakeys                  map[string]keyInfo
	attrToRequiredObligations map[string]string
}

func (f *FakeKas) Rewrap(_ context.Context, in *connect.Request[kaspb.RewrapRequest]) (*connect.Response[kaspb.RewrapResponse], error) {
	signedRequestToken := in.Msg.GetSignedRequestToken()

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

	// Extract fulfillable obligations from header
	var fulfillableObligations []string
	if val := in.Header().Get("X-Rewrap-Additional-Context"); val != "" {
		decoded, err := base64.StdEncoding.DecodeString(val)
		if err == nil {
			var rewrapContext struct {
				Obligations struct {
					FulfillableFQNs []string `json:"fulfillableFQNs"`
				} `json:"obligations"`
			}
			if json.Unmarshal(decoded, &rewrapContext) == nil {
				fulfillableObligations = rewrapContext.Obligations.FulfillableFQNs
			}
		}
	}

	result := f.getRewrapResponse(requestBodyStr, fulfillableObligations)

	return connect.NewResponse(result), nil
}

func (f *FakeKas) PublicKey(_ context.Context, _ *connect.Request[kaspb.PublicKeyRequest]) (*connect.Response[kaspb.PublicKeyResponse], error) {
	return connect.NewResponse(&kaspb.PublicKeyResponse{PublicKey: f.KASInfo.PublicKey, Kid: f.KID}), nil
}

func (f *FakeKas) getRewrapResponse(rewrapRequest string, fulfillableObligations []string) *kaspb.RewrapResponse {
	bodyData := kaspb.UnsignedRewrapRequest{}
	err := protojson.Unmarshal([]byte(rewrapRequest), &bodyData)
	f.s.Require().NoError(err, "json.Unmarshal failed")
	resp := &kaspb.RewrapResponse{}

	for _, req := range bodyData.GetRequests() {
		requiredObligations := f.s.checkPolicyObligations(f.attrToRequiredObligations, req)
		if f.URL == f.s.kasTestURLLookup[obligationKas] {
			// Only return failures for obligation kas URL
			if !f.s.checkObligationsFulfillment(requiredObligations, fulfillableObligations) {
				results := &kaspb.PolicyRewrapResult{PolicyId: req.GetPolicy().GetId()}
				for _, kaoReq := range req.GetKeyAccessObjects() {
					kaoResult := &kaspb.KeyAccessRewrapResult{
						Result: &kaspb.KeyAccessRewrapResult_Error{
							Error: "forbidden",
						},
						Status:            "deny",
						KeyAccessObjectId: kaoReq.GetKeyAccessObjectId(),
						Metadata:          createMetadataWithObligations(requiredObligations),
					}
					results.Results = append(results.Results, kaoResult)
				}
				resp.Responses = append(resp.Responses, results)
				continue
			}
		}

		results := &kaspb.PolicyRewrapResult{PolicyId: req.GetPolicy().GetId()}
		resp.Responses = append(resp.Responses, results)
		for _, kaoReq := range req.GetKeyAccessObjects() {
			kao := kaoReq.GetKeyAccessObject()
			wrappedKey := kaoReq.GetKeyAccessObject().GetWrappedKey()

			var entityWrappedKey []byte
			switch kaoReq.GetKeyAccessObject().GetKeyType() {
			case "ec-wrapped":
				// Get the ephemeral public key in PEM format
				ephemeralPubKeyPEM := kaoReq.GetKeyAccessObject().GetEphemeralPublicKey()

				// Get EC key size and convert to mode
				keySize, err := ocrypto.GetECKeySize([]byte(ephemeralPubKeyPEM))
				f.s.Require().NoError(err, "failed to get EC key size")

				mode, err := ocrypto.ECSizeToMode(keySize)
				f.s.Require().NoError(err, "failed to convert key size to mode")

				// Parse the PEM public key
				block, _ := pem.Decode([]byte(ephemeralPubKeyPEM))
				f.s.Require().NoError(err, "failed to decode PEM block")

				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				f.s.Require().NoError(err, "failed to parse public key")

				ecPub, ok := pub.(*ecdsa.PublicKey)
				if !ok {
					f.s.Require().Error(err, "not an EC public key")
				}

				// Compress the public key
				compressedKey, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
				f.s.Require().NoError(err, "failed to compress public key")

				kasPrivateKey := strings.ReplaceAll(f.privateKey, "\n\t", "\n")
				if kao.GetKid() != "" && kao.GetKid() != f.KID {
					// old kid
					lk, found := f.legakeys[kaoReq.GetKeyAccessObject().GetKid()]
					f.s.Require().True(found, "unable to find key [%s]", kao.GetKid())
					kasPrivateKey = strings.ReplaceAll(lk.private, "\n\t", "\n")
				}

				privateKey, err := ocrypto.ECPrivateKeyFromPem([]byte(kasPrivateKey))
				f.s.Require().NoError(err, "failed to extract private key from PEM")

				ed, err := ocrypto.NewSaltedECDecryptor(privateKey, tdfSalt(), nil)
				f.s.Require().NoError(err, "failed to create EC decryptor")

				symmetricKey, err := ed.DecryptWithEphemeralKey(wrappedKey, compressedKey)
				f.s.Require().NoError(err, "failed to decrypt")

				asymEncrypt, err := ocrypto.FromPublicPEMWithSalt(bodyData.GetClientPublicKey(), tdfSalt(), nil)
				f.s.Require().NoError(err, "ocrypto.FromPublicPEMWithSalt failed")

				var sessionKey string
				if e, found := asymEncrypt.(ocrypto.ECEncryptor); found {
					sessionKey, err = e.PublicKeyInPemFormat()
					f.s.Require().NoError(err, "unable to serialize ephemeral key")
				}
				resp.SessionPublicKey = sessionKey
				entityWrappedKey, err = asymEncrypt.Encrypt(symmetricKey)
				f.s.Require().NoError(err, "ocrypto.AsymEncryption.encrypt failed")

			case "wrapped":
				kasPrivateKey := strings.ReplaceAll(f.privateKey, "\n\t", "\n")
				if kao.GetKid() != "" && kao.GetKid() != f.KID {
					// old kid
					lk, ok := f.legakeys[kaoReq.GetKeyAccessObject().GetKid()]
					f.s.Require().True(ok, "unable to find key [%s]", kao.GetKid())
					kasPrivateKey = strings.ReplaceAll(lk.private, "\n\t", "\n")
				}

				asymDecrypt, err := ocrypto.NewAsymDecryption(kasPrivateKey)
				f.s.Require().NoError(err, "ocrypto.NewAsymDecryption failed")
				symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
				f.s.Require().NoError(err, "ocrypto.Decrypt failed for kao:[%s # %s (%s)] kas:[%s # %s (%s)]", kao.GetKasUrl(), kao.GetKid(), kao.GetSplitId(), f.URL, f.KID, f.Algorithm)
				asymEncrypt, err := ocrypto.NewAsymEncryption(bodyData.GetClientPublicKey())
				f.s.Require().NoError(err, "ocrypto.NewAsymEncryption failed")
				entityWrappedKey, err = asymEncrypt.Encrypt(symmetricKey)
				f.s.Require().NoError(err, "ocrypto.encrypt failed")

			default:
				f.s.Require().FailNowf("unknown key type %s", kaoReq.GetKeyAccessObject().GetKeyType())
			}

			kaoResult := &kaspb.KeyAccessRewrapResult{
				Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: entityWrappedKey},
				Status:            "permit",
				KeyAccessObjectId: kaoReq.GetKeyAccessObjectId(),
				Metadata:          createMetadataWithObligations(requiredObligations),
			}
			results.Results = append(results.Results, kaoResult)
		}
	}

	return resp
}

func (s *TDFSuite) checkPolicyObligations(obligationsMap map[string]string, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest) []string {
	var requiredObligations []string
	sDecPolicy, policyErr := base64.StdEncoding.DecodeString(req.GetPolicy().GetBody())
	policy := &Policy{}
	if policyErr == nil {
		policyErr = json.Unmarshal(sDecPolicy, policy)
		if policyErr != nil {
			return requiredObligations
		}
	}
	for _, attr := range policy.Body.DataAttributes {
		if val, found := obligationsMap[attr.URI]; found {
			requiredObligations = append(requiredObligations, val)
		}
	}
	return requiredObligations
}

func (s *TDFSuite) checkObligationsFulfillment(requiredObligations, fulfillableObligations []string) bool {
	// Create a set of fulfillable obligations for fast lookup
	fulfillableSet := make(map[string]bool)
	for _, obligation := range fulfillableObligations {
		fulfillableSet[obligation] = true
	}

	// Check if all required obligations are in the fulfillable set
	for _, required := range requiredObligations {
		if !fulfillableSet[required] {
			return false
		}
	}

	return true
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
	return checksum == hex.EncodeToString(c)
}

func createTestBaseKeyMap(s *suite.Suite, algorithm policy.Algorithm, kid string, pem string, kasURI string) map[string]any {
	baseKey := &policy.SimpleKasKey{
		KasUri: kasURI,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: algorithm,
			Kid:       kid,
			Pem:       pem,
		},
		KasId: "",
	}
	keyMapBytes, err := json.Marshal(baseKey)
	s.Require().NoError(err)
	var keyMap map[string]any
	err = json.Unmarshal(keyMapBytes, &keyMap)
	s.Require().NoError(err)
	algoStr, err := formatAlg(baseKey.GetPublicKey().GetAlgorithm())
	s.Require().NoError(err)
	publicKey, ok := keyMap[baseKeyPublicKey].(map[string]any)
	s.Require().True(ok)
	publicKey[baseKeyAlg] = algoStr
	keyMap[baseKeyPublicKey] = publicKey

	return keyMap
}

func TestIsLessThanSemver(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		target      string
		expected    bool
		expectError bool
	}{
		{
			name:        "Version is less than target",
			version:     "1.0.0",
			target:      "2.0.0",
			expected:    true,
			expectError: false,
		},
		{
			name:        "Version is equal to target",
			version:     "2.0.0",
			target:      "2.0.0",
			expected:    false,
			expectError: false,
		},
		{
			name:        "Version is greater than target",
			version:     "3.0.0",
			target:      "2.0.0",
			expected:    false,
			expectError: false,
		},
		{
			name:        "Different version format",
			version:     "v1.41.29",
			target:      "2.0.0",
			expected:    true,
			expectError: false,
		},
		{
			name:        "without patch version",
			version:     "1.41",
			target:      "2.0.0",
			expected:    true,
			expectError: false,
		},
		{
			name:        "only major",
			version:     "1",
			target:      "2.0.0",
			expected:    true,
			expectError: false,
		},
		{
			name:        "only major greater",
			version:     "3",
			target:      "2.0.0",
			expected:    false,
			expectError: false,
		},
		{
			name:        "only major v",
			version:     "v1",
			target:      "2.0.0",
			expected:    true,
			expectError: false,
		},
		{
			name:        "only major greater v",
			version:     "v3",
			target:      "2.0.0",
			expected:    false,
			expectError: false,
		},
		{
			name:        "Invalid version format",
			version:     "invalid",
			target:      "2.0.0",
			expected:    false,
			expectError: true,
		},
		{
			name:        "Invalid target format",
			version:     "1.0.0",
			target:      "invalid",
			expected:    false,
			expectError: true,
		},
		{
			name:        "Both version and target are invalid",
			version:     "invalid",
			target:      "invalid",
			expected:    false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := isLessThanSemver(tt.version, tt.target)
			if tt.expectError {
				require.Error(t, err, "Expected an error for test case: %s", tt.name)
			} else {
				require.NoError(t, err, "Did not expect an error for test case: %s", tt.name)
				assert.Equal(t, tt.expected, result, "Unexpected result for test case: %s", tt.name)
			}
		})
	}
}

func TestGetKasErrorToReturn(t *testing.T) {
	defaultError := errors.New("default KAS error")

	t.Run("InvalidArgument error returns ErrRewrapBadRequest", func(t *testing.T) {
		inputError := errors.New("rpc error: code = InvalidArgument desc = invalid request")
		result := getKasErrorToReturn(inputError, defaultError)
		require.ErrorIs(t, result, ErrRewrapBadRequest)
		require.ErrorIs(t, result, defaultError)
	})

	t.Run("PermissionDenied error returns ErrRewrapForbidden", func(t *testing.T) {
		inputError := errors.New("rpc error: code = PermissionDenied desc = access denied")
		result := getKasErrorToReturn(inputError, defaultError)
		require.ErrorIs(t, result, ErrRewrapForbidden)
		require.ErrorIs(t, result, defaultError)
	})

	t.Run("Other error returns default error unchanged", func(t *testing.T) {
		inputError := errors.New("rpc error: code = Internal desc = internal server error")
		result := getKasErrorToReturn(inputError, defaultError)
		require.Equal(t, defaultError, result)
	})
}
