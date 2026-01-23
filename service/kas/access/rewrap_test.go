package access

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/grpc/metadata"
)

type fakeKeyDetails struct {
	id        trust.KeyIdentifier
	algorithm string
	legacy    bool
}

func (f *fakeKeyDetails) ID() trust.KeyIdentifier { return f.id }
func (f *fakeKeyDetails) Algorithm() ocrypto.KeyType {
	return ocrypto.KeyType(f.algorithm)
}
func (f *fakeKeyDetails) IsLegacy() bool { return f.legacy }
func (f *fakeKeyDetails) ExportPrivateKey(_ context.Context) (*trust.PrivateKey, error) {
	return &trust.PrivateKey{}, nil
}

func (f *fakeKeyDetails) ExportPublicKey(context.Context, trust.KeyType) (string, error) {
	return "", nil
}
func (f *fakeKeyDetails) ExportCertificate(context.Context) (string, error) { return "", nil }
func (f *fakeKeyDetails) System() string                                    { return "" }
func (f *fakeKeyDetails) ProviderConfig() *policy.KeyProviderConfig {
	return &policy.KeyProviderConfig{}
}

type fakeKeyIndex struct {
	keys []trust.KeyDetails
	err  error
}

func (f *fakeKeyIndex) String() string {
	return "fakeKeyIndex"
}

func (f *fakeKeyIndex) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Indexer", f.String()),
	)
}

func (f *fakeKeyIndex) FindKeyByAlgorithm(context.Context, string, bool) (trust.KeyDetails, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeKeyIndex) FindKeyByID(context.Context, trust.KeyIdentifier) (trust.KeyDetails, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeKeyIndex) ListKeys(context.Context) ([]trust.KeyDetails, error) {
	return f.keys, f.err
}

func (f *fakeKeyIndex) ListKeysWith(_ context.Context, opts trust.ListKeyOptions) ([]trust.KeyDetails, error) {
	if opts.LegacyOnly {
		var legacyKeys []trust.KeyDetails
		for _, key := range f.keys {
			if key.IsLegacy() {
				legacyKeys = append(legacyKeys, key)
			}
		}
		return legacyKeys, f.err
	}
	return f.keys, f.err
}

func newBufferLogger() (*logger.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return &logger.Logger{
		Logger: slog.New(handler),
	}, buf
}

func extractLastLogRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	data := strings.TrimSpace(buf.String())
	require.NotEmpty(t, data)
	lines := strings.Split(data, "\n")
	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &record))
	return record
}

func toStringSlice(t *testing.T, raw any) []string {
	t.Helper()
	if raw == nil {
		return nil
	}
	interfaceSlice, ok := raw.([]any)
	require.True(t, ok)
	result := make([]string, 0, len(interfaceSlice))
	for _, v := range interfaceSlice {
		str, strOK := v.(string)
		require.True(t, strOK)
		result = append(result, str)
	}
	return result
}

func TestListLegacyKeys_KeyringPopulated(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	// Simulate a Provider with Keyring containing legacy RSA keys
	p := &Provider{
		Logger: testLogger,
		KASConfig: KASConfig{
			Keyring: []CurrentKeyFor{
				{KID: "legacy1", Algorithm: "rsa:2048", Legacy: true},
				{KID: "notlegacy", Algorithm: "rsa:2048", Legacy: false},
				{KID: "legacy2", Algorithm: "rsa:2048", Legacy: true},
				{KID: "legacy3", Algorithm: "ec:secp256r1", Legacy: true}, // not RSA
			},
		},
	}

	kids := p.listLegacyKeys(t.Context())
	assert.ElementsMatch(t, []trust.KeyIdentifier{"legacy1", "legacy2"}, kids)
}

func TestListLegacyKeys_KeyIndexPopulated(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	fakeKeys := []trust.KeyDetails{
		&fakeKeyDetails{id: "id1", algorithm: "rsa:2048", legacy: true},
		&fakeKeyDetails{id: "id2", algorithm: "rsa:2048", legacy: false},
		&fakeKeyDetails{id: "id3", algorithm: "ec:secp256r1", legacy: true},
		&fakeKeyDetails{id: "id4", algorithm: "rsa:2048", legacy: true},
	}
	delegator := trust.NewDelegatingKeyService(&fakeKeyIndex{
		keys: fakeKeys,
	}, logger.CreateTestLogger(), nil)
	p := &Provider{
		Logger:       testLogger,
		KeyDelegator: delegator,
	}
	kids := p.listLegacyKeys(t.Context())
	assert.ElementsMatch(t, []trust.KeyIdentifier{"id1", "id4"}, kids)
}

func TestListLegacyKeys_Empty(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	delegator := trust.NewDelegatingKeyService(&fakeKeyIndex{}, logger.CreateTestLogger(), nil)
	p := &Provider{
		Logger:       testLogger,
		KeyDelegator: delegator,
	}
	kids := p.listLegacyKeys(t.Context())
	assert.Empty(t, kids)
}

func TestListLegacyKeys_KeyIndexError(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	delegator := trust.NewDelegatingKeyService(&fakeKeyIndex{
		err: errors.New("fail"),
	}, logger.CreateTestLogger(), nil)
	p := &Provider{
		Logger:       testLogger,
		KeyDelegator: delegator,
	}
	kids := p.listLegacyKeys(t.Context())
	assert.Empty(t, kids)
}

func TestProviderApplyConfig_DefaultAndWarning(t *testing.T) {
	log, buf := newBufferLogger()
	p := &Provider{
		Logger: log,
	}

	security := &config.SecurityConfig{}
	p.ApplyConfig(KASConfig{}, security)
	require.Equal(t, config.DefaultUnsafeClockSkew, p.acceptableSkew())
	require.Empty(t, strings.TrimSpace(buf.String()))

	buf.Reset()

	custom := 2 * time.Minute
	security.Unsafe.ClockSkew = custom
	p.ApplyConfig(KASConfig{}, security)
	require.Equal(t, custom, p.acceptableSkew())
	require.Contains(t, buf.String(), "configured SRT acceptable skew exceeds default")
}

const (
	ecCert = `-----BEGIN CERTIFICATE-----
MIIB5DCBzQIUZsQqf2nfB0JuxsKBwrVjfCVjjmUwDQYJKoZIhvcNAQELBQAwGzEZ
MBcGA1UEAwwQY2Eub3BlbnRkZi5sb2NhbDAeFw0yMzA3MTgxOTM5NTJaFw0yMzA3
MTkxOTM5NTJaMA4xDDAKBgNVBAMMA2thczBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABDc+h0JhF0uUuXYY6mKHXTt81nBsBFnb0j+JWcBosyWBqC9GrQaiyfZxJXgX
XkEV8eULg7BztVhjK/qVNG4x5pIwDQYJKoZIhvcNAQELBQADggEBAGP1pPFNpx/i
N3skt5hVVYHPpGAUBxElbIRGx/NEPQ38q3RQ5QFMFHU9rCgQd/27lPZKS6+RLCbM
IsWPNtyPVlD9oPkVWydPiIKdRNJbKsv4FEHl0c5ik80E5er7B5TwzttR/t5B54m+
D0yZnKKXtqEi9KeStxCJKHcdibGuO+OtYJkl1uUhsX+6hDazdAX1jWq22j8L9hNS
buwEf498deOfNt/9PkT3MardMgQR492VPYJd4Ocj7drJEX0t2EeWouuoX9WijZi9
0umFuYEUo0VaLgv00k3hJuqBAUngzqlyepj8FKMsP6dkPpjjp/s9VTKHg2pmxeku
qX8+pZNixMc=
-----END CERTIFICATE-----
`
	ecPrivate = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdDFmn9LlJUTalXe8
S6/DnZELbJRo+NTpFKfs8VC2SK2hRANCAAQ3PodCYRdLlLl2GOpih107fNZwbARZ
29I/iVnAaLMlgagvRq0Gosn2cSV4F15BFfHlC4Owc7VYYyv6lTRuMeaS
-----END PRIVATE KEY-----
`
	rsaPrivate = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2+frLbHZOoUcdS3PWtPRkKrXQpMTKLR3B6dKDJwGnMU3jkr3
k5GK4wFnPv0G3fB8Duh/P8qtO8yORQXbSp6Fl6lCvciYMDE5qrPFYa/49iNHeeFM
WvdmRBDvr659UmfrZ+Fh9d2fN3hj7legiaa9kkD8YhJQ+zHplGMC2xMWnAy6NnlB
XAjKB57DtVckxb8SBFUqkSEFZGpl7tm87bPds2YzGwdhoy7eOuvhWb0XeBFt7RWz
98Dir9oB4CxW4YnQGZR2zL/2y6a+jf5kwYl9c+IGR81BPaPzHnrzo55MgmRUSq10
+odecl37TuFP+maU1Iq3jsVvXS5DbipxxPe8kwIDAQABAoIBAQCkdC0xkAZnODLP
AwJF55CagtjWhczXLRazF41OHsTnKqngdPnvVvGp0FvZBDrFcVolgAPhvf2Nce2X
esjDZgd8Iu2xpjkCGV4J5cUfyA0Ebd+/KxkCEnBdSNkm5fP805B9sFSlHSc7wYHi
NY/uQU8V+BmGcjIzmOEYwm7ZTM4kxhBEUyfczd41D0E312j/+J+Y2JFoLDugmyh7
KjYu79OCVvZU+snwcBDlnhdxoXnQTjlO68PDfXxqJmN94Jw/8+GYcA6N74uSwCp9
FZYD0X9AVQm7V/8t865S2UWcoHDNOZwW2IyBjaW37E20NGPx1PcAX9oZW3QsxSxG
gf7uj/zZAoGBAPz3RJq66CSXmcRMnNKk0CAu4LE3FrhKt9UsnGW1I1zzOfLylpHW
EfhCllb9Zsx92SeW6XDXBLEWIJmEQ6/c79cpaMMYkpfi4CsOLceZ3EoON22PsjNF
vSQ72oA6ueSnAC1rSPZV310YmkHgC0JPD+3W0wNe1+4OKR68bDxKNtxPAoGBAN6L
I9oK8AsQFJfTMlZ6SRCXarHVMo7uQZ2x+c5+n/DTlzcl5sk2o7iIuOyY2YFpJwYu
3fdiGohXPi5XnVzkFJTqSoOs6pKCRlD9TgEbNLF5JdnQvCuXDopc7s8BoIAVoQnV
da7L4fDeO6SpkmUd7ZdkegeY5zFL9m8qMPfWErZ9An85T8w7Qh1WLQKpdrIRB0Yg
BH7jp5d+KW983J6SbHeWl4SJhmyWnel0VaG6E682pUyNq6M37X8in+DC5zRuo5+z
H66chPSxdLVVC+FTV4iRPqdQKz40X5h6nRTj+GolY7CmmafuJ4ZzkR9hzWC/pSn2
uLUWDmbdiFfInufmwOmtAoGARghjb+qhP9n/oQfFf5FcDOyZlv0QvAoefBHWGzWd
/5uWqrQyvH+FZj0gdNRlHmSI81ksYP1ufBl4Z/0KeIEOOQ7CBE4WQ6TbnAEa2x5E
ptUJJFKb5NvUp5Y3UM2iRKyJ0R5rumZO5A4LlvYGK+wPKOVlwZ5MoybUlocggd3M
ZcECgYEAia0FTcXO8J1wZCYBTqFi+yvhVWPdn9kjK2ldWrsuJwO1llujjM3AqUto
awYnM8c/bPESvSLtl6+uuG3HcQRPIHz77dxvhRAyv4gltjyni3EYMreQGQwf5PNR
hgm3BlxwSujE0rKUwGCr5ol91yqiVojF/qyY4EwKP646AyMiJSQ=
-----END RSA PRIVATE KEY-----
`
	rsaPublic = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2+frLbHZOoUcdS3PWtPR
kKrXQpMTKLR3B6dKDJwGnMU3jkr3k5GK4wFnPv0G3fB8Duh/P8qtO8yORQXbSp6F
l6lCvciYMDE5qrPFYa/49iNHeeFMWvdmRBDvr659UmfrZ+Fh9d2fN3hj7legiaa9
kkD8YhJQ+zHplGMC2xMWnAy6NnlBXAjKB57DtVckxb8SBFUqkSEFZGpl7tm87bPd
s2YzGwdhoy7eOuvhWb0XeBFt7RWz98Dir9oB4CxW4YnQGZR2zL/2y6a+jf5kwYl9
c+IGR81BPaPzHnrzo55MgmRUSq10+odecl37TuFP+maU1Iq3jsVvXS5DbipxxPe8
kwIDAQAB
-----END PUBLIC KEY-----
`
	rsaPublicAlt = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZcnlPNj3EHr7/LIYa8WSyRW5r
YkxOo3Mwu5Uuj94Ht4zDkR/RGDFLnVsKdwUxGWb+/bBrWK7X5S6HwZCQospbsBMc
Mi/hapSJ6CsE9wPuCvnUAqNNv90LijcYrAiCMLtOESweIassGj4e8neoyum4U2+b
bmqZPkN152tF9YWMoQIDAQAB
-----END PUBLIC KEY-----
`
	rsaPrivateAlt = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDZcnlPNj3EHr7/LIYa8WSyRW5rYkxOo3Mwu5Uuj94Ht4zDkR/R
GDFLnVsKdwUxGWb+/bBrWK7X5S6HwZCQospbsBMcMi/hapSJ6CsE9wPuCvnUAqNN
v90LijcYrAiCMLtOESweIassGj4e8neoyum4U2+bbmqZPkN152tF9YWMoQIDAQAB
AoGAHe1/fMN+ZMvGheBe5L5smYys0eLJldkxNXfb5HiwmmdM3G3Q7zphLoMN0Lbo
5AUXA+luqpeeGODWMqEVgJKnPw42NQ2K6D74Z3fKAjldCbVZ9fV4PBuzX7h1hzPe
P6UZYQVk27wTZgxDEJ70Q9xFiUrAYEzjNjY9UgCaQac3OUECQQD89/5KNdmZLNdk
t3ejUE9gq6m63G3OhOhZoXfwxiNQQ//XZzKyPJuxA3olxJZnSWLxEUnX4cMVaAPV
bhFUxmzNAkEA3A2DvuGvcR3zN7AeFvyHjUCPydCX2xulEVRcPGj7rI5Kg574WcXr
IKeaaVbsOres53yLHA3p/EFFZnHYhFcfJQJBAPoZzWVdXCceuE2xPi1Ox0vSLFq8
eCvIJ1gGVejMXDmNITK7qtmhJmSaBXe1puWzHoksCI/Reuh9D91BlwzzqLkCQDUO
CRqnnT4fo3lkvAx8vE3hKAnXghVw196SwV5LTYqwD+UmGejDIEqSPldxfqk1ibmS
PJP6AtUwA4SMpFBcFQUCQQDafTeVfGXrjWTq71/qrn34dUIDcqjHoqXly6m6Pw25
Dzq7D9lqeqSK/ds7r7hpbs4iIr6KrSuXwlXmYtnhRvKT
-----END RSA PRIVATE KEY-----
`
	plainKey      = "This-is-128-bits"
	mockIDPOrigin = "https://keycloak-http/"
)

func fauxPolicy() *Policy {
	return &Policy{
		UUID: uuid.MustParse("12345678-1234-1234-1234-1234567890AB"),
		Body: PolicyBody{DataAttributes: []Attribute{
			{URI: "https://example.com/attr/Classification/value/S"},
			{URI: "https://example.com/attr/COI/value/PRX"},
		}},
	}
}

func emptyPolicyBytes() []byte {
	data, err := json.Marshal(Policy{
		UUID: uuid.MustParse("12345678-1234-1234-1234-1234567890AB"),
		Body: PolicyBody{},
	})
	if err != nil {
		panic(err)
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

func fauxPolicyBytes(t *testing.T) []byte {
	data, err := json.Marshal(fauxPolicy())
	require.NoError(t, err)
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

func privateKey(t *testing.T) *rsa.PrivateKey {
	b, rest := pem.Decode([]byte(rsaPrivate))
	require.NotNil(t, b)
	assert.Empty(t, rest)

	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	require.NoError(t, err)
	require.NotNil(t, k)
	return k
}

func publicKeyTest(t *testing.T) *rsa.PublicKey {
	b, rest := pem.Decode([]byte(rsaPublic))
	require.NotNil(t, b)
	assert.Empty(t, rest)

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	require.NotNil(t, pub)
	require.NoError(t, err)

	pubKey, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	return pubKey
}

func entityPrivateKey(t *testing.T) *rsa.PrivateKey {
	b, rest := pem.Decode([]byte(rsaPrivateAlt))
	require.NotNil(t, b)
	assert.Empty(t, rest)

	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	require.NotNil(t, k)
	require.NoError(t, err)
	return k
}

func entityPublicKey(t *testing.T) *rsa.PublicKey {
	b, rest := pem.Decode([]byte(rsaPublicAlt))
	require.NotNil(t, b)
	assert.Empty(t, rest)

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	require.NotNil(t, pub)
	require.NoError(t, err)

	pubKey, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	return pubKey
}

type PolicyBinding struct {
	Alg  string `json:"alg"`
	Hash string `json:"hash"`
}

func keyAccessWrappedRaw(t *testing.T, policyBindingAsString bool) kaspb.UnsignedRewrapRequest_WithKeyAccessObject {
	policyBytes := fauxPolicyBytes(t)
	asym, err := ocrypto.NewAsymEncryption(rsaPublicAlt)
	require.NoError(t, err, "rewrap: NewAsymEncryption failed")
	wrappedKey, err := asym.Encrypt([]byte(plainKey))
	require.NoError(t, err, "rewrap: encryptWithPublicKey failed")

	logger := logger.CreateTestLogger()
	bindingBytes, err := generateHMACDigest(t.Context(), policyBytes, []byte(plainKey), *logger)
	require.NoError(t, err)

	dst := make([]byte, hex.EncodedLen(len(bindingBytes)))
	hex.Encode(dst, bindingBytes)

	var policyBinding *kaspb.PolicyBinding

	if policyBindingAsString {
		policyBinding = &kaspb.PolicyBinding{
			Hash: base64.StdEncoding.EncodeToString(dst),
		}
	} else {
		policyBinding = &kaspb.PolicyBinding{
			Algorithm: "HS256",
			Hash:      base64.StdEncoding.EncodeToString(dst),
		}
	}
	require.NoError(t, err)

	return kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
		KeyAccessObjectId: "123",
		KeyAccessObject: &kaspb.KeyAccess{
			KeyType:       "wrapped",
			KasUrl:        "http://127.0.0.1:4000",
			Protocol:      "kas",
			WrappedKey:    []byte(base64.StdEncoding.EncodeToString(wrappedKey)),
			PolicyBinding: policyBinding,
		},
	}
}

type RSAPublicKey rsa.PublicKey

func (publicKey *RSAPublicKey) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	tok, err := jws.Verify([]byte(raw), jws.WithKey(jwa.RS256, rsa.PublicKey(*publicKey)))
	if err != nil {
		slog.ErrorContext(ctx, "jws.Verify fail", slog.String("raw", raw))
		return nil, err
	}
	return tok, nil
}

func signedMockJWT(t *testing.T, signer *rsa.PrivateKey) []byte {
	tok := mockJWT(t)
	raw, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signer))
	require.NoError(t, err)
	return raw
}

func mockJWT(t *testing.T) jwt.Token {
	tok := jwt.New()

	var err error
	set := func(k string, v interface{}) {
		if err != nil {
			return
		}
		err = tok.Set(k, v)
	}
	set(jwt.IssuerKey, mockIDPOrigin)
	set(jwt.AudienceKey, `testonly`)
	set(jwt.SubjectKey, `testuser1`)
	require.NoError(t, err)
	return tok
}

func jwtStandard(t *testing.T) []byte {
	return signedMockJWT(t, privateKey(t))
}

func jwtWrongKey(t *testing.T) []byte {
	return signedMockJWT(t, entityPrivateKey(t))
}

func makeRewrapRequests(t *testing.T, policy []byte, bindingAsString bool) []*kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	kaoReq := keyAccessWrappedRaw(t, bindingAsString)
	return []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{&kaoReq},
			Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
				Id:   "123",
				Body: string(policy),
			},
		},
	}
}

func makeRewrapBody(t *testing.T, policy []byte, policyBindingAsString bool) []byte {
	mockBody := &kaspb.UnsignedRewrapRequest{
		Requests:        makeRewrapRequests(t, policy, policyBindingAsString),
		ClientPublicKey: rsaPublicAlt,
	}
	bodyData, err := protojson.Marshal(mockBody)

	require.NoError(t, err)
	tok := jwt.New()
	err = tok.Set("requestBody", string(bodyData))
	require.NoError(t, err)

	s, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, entityPrivateKey(t)))
	require.NoError(t, err)
	return s
}

func TestParseAndVerifyRequest(t *testing.T) {
	srt := makeRewrapBody(t, fauxPolicyBytes(t), false)
	srt2 := makeRewrapBody(t, fauxPolicyBytes(t), true)
	badPolicySrt := makeRewrapBody(t, emptyPolicyBytes(), true)

	tests := []struct {
		name        string
		body        []byte
		goodDPoP    bool
		shouldError bool
		addDPoP     bool
	}{
		{"good w/ string policy binding", srt, true, false, true},
		{"good w/ object policy binding", srt2, true, false, true},
		{"different policy", badPolicySrt, true, true, true},
		{"no dpop token included", srt, true, false, false},
		{"wrong dpop token included", srt, false, false, true},
	}
	// The execution loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			bearer := string(jwtStandard(t))
			if tt.addDPoP {
				var key jwk.Key
				var err error
				if tt.goodDPoP {
					key, err = jwk.FromRaw(entityPublicKey(t))
				} else {
					key, err = jwk.FromRaw(publicKeyTest(t))
				}
				require.NoError(t, err, "couldn't get JWK from key")
				err = key.Set(jwk.AlgorithmKey, jwa.RS256) // Check the error return value
				require.NoError(t, err, "failed to set algorithm key")
				ctx = ctxAuth.ContextWithAuthNInfo(ctx, key, mockJWT(t), bearer)
			}

			md := metadata.New(map[string]string{"token": bearer})
			ctx = metadata.NewIncomingContext(ctx, md)

			testLogger := logger.CreateTestLogger()
			p := &Provider{
				Logger: testLogger,
			}

			verified, _, err := p.extractSRTBody(
				ctx,
				http.Header{},
				&kaspb.RewrapRequest{
					SignedRequestToken: string(tt.body),
				},
			)
			if tt.goodDPoP {
				require.NoError(t, err, "failed to parse srt=[%s], tok=[%s]", tt.body, bearer)
				require.NotNil(t, verified, "unable to load request body")
				require.NotNil(t, verified.GetClientPublicKey(), "unable to load public key")

				for _, req := range verified.GetRequests() {
					err := verifyPolicyBinding(t.Context(), []byte(req.GetPolicy().GetBody()), req.GetKeyAccessObjects()[0], []byte(plainKey), *testLogger)
					if !tt.shouldError {
						require.NoError(t, err, "failed to verify policy body=[%v]", tt.body)
					} else {
						require.Error(t, err, "failed to fail policy body=[%v]", tt.body)
					}
				}
			} else {
				require.Error(t, err, "failed to fail srt=[%s], tok=[%s]", tt.body, bearer)
			}
		})
	}
}

func Test_SignedRequestBody_When_Bad_Signature_Expect_Failure(t *testing.T) {
	ctx := t.Context()
	key, err := jwk.FromRaw([]byte("bad key"))
	require.NoError(t, err, "couldn't get JWK from key")

	err = key.Set(jwk.AlgorithmKey, jwa.NoSignature)
	require.NoError(t, err, "failed to set algorithm key")
	ctx = ctxAuth.ContextWithAuthNInfo(ctx, key, mockJWT(t), string(jwtStandard(t)))

	md := metadata.New(map[string]string{"token": string(jwtWrongKey(t))})
	ctx = metadata.NewIncomingContext(ctx, md)

	badLogger := logger.CreateTestLogger()
	p := &Provider{
		Logger: badLogger,
	}
	verified, _, err := p.extractSRTBody(
		ctx,
		http.Header{},
		&kaspb.RewrapRequest{
			SignedRequestToken: string(makeRewrapBody(t, fauxPolicyBytes(t), false)),
		},
	)
	require.Error(t, err)
	require.Nil(t, verified)
}

func TestValidateSRTClaims_LogsFutureIAT(t *testing.T) {
	log, buf := newBufferLogger()
	p := &Provider{Logger: log}

	token := jwt.New()
	future := time.Now().Add(2 * time.Minute)
	require.NoError(t, token.Set(jwt.IssuedAtKey, future))

	err := p.validateSRTClaims(t.Context(), token, false)
	require.Error(t, err)

	record := extractLastLogRecord(t, buf)
	require.Equal(t, "srt validation failure", record["msg"])
	require.NotNil(t, record["iat"])
	require.NotNil(t, record["iat_delta"])
	require.Equal(t, "unable to validate or parse token", record["failure_reason"])

	claims := toStringSlice(t, record["validation_failure_claims"])
	assert.Contains(t, claims, "iat")
}

func TestValidateSRTClaims_LogsExpired(t *testing.T) {
	log, buf := newBufferLogger()
	p := &Provider{Logger: log}

	token := jwt.New()
	past := time.Now().Add(-2 * time.Minute)
	require.NoError(t, token.Set(jwt.ExpirationKey, past))

	err := p.validateSRTClaims(t.Context(), token, false)
	require.Error(t, err)

	record := extractLastLogRecord(t, buf)
	require.Equal(t, "srt validation failure", record["msg"])
	require.NotNil(t, record["exp"])
	require.NotNil(t, record["exp_delta"])
	require.Equal(t, "unable to validate or parse token", record["failure_reason"])

	claims := toStringSlice(t, record["validation_failure_claims"])
	assert.Contains(t, claims, "exp")
}

func TestValidateSRTClaims_CustomSkewAllowsFutureIAT(t *testing.T) {
	log, _ := newBufferLogger()
	p := &Provider{Logger: log}
	custom := 3 * time.Minute
	security := &config.SecurityConfig{}
	security.Unsafe.ClockSkew = custom
	p.ApplyConfig(KASConfig{}, security)

	token := jwt.New()
	future := time.Now().Add(2 * time.Minute)
	require.NoError(t, token.Set(jwt.IssuedAtKey, future))

	err := p.validateSRTClaims(t.Context(), token, false)
	require.NoError(t, err)
}

func Test_GetEntityInfo_When_Missing_MD_Expect_Error(t *testing.T) {
	ctx := t.Context()
	_, err := getEntityInfo(ctx, logger.CreateTestLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing")
}

func Test_GetEntityInfo_When_Authorization_MD_Missing_Expect_Error(t *testing.T) {
	ctx := t.Context()
	ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{"token": "test"}))

	_, err := getEntityInfo(ctx, logger.CreateTestLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing")
}

func Test_GetEntityInfo_When_Authorization_MD_Invalid_Expect_Error(t *testing.T) {
	ctx := t.Context()
	ctx = metadata.NewIncomingContext(ctx, metadata.New(map[string]string{"authorization": "pop test"}))

	_, err := getEntityInfo(ctx, logger.CreateTestLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing")
}

func TestGetAdditionalRewrapContext(t *testing.T) {
	tests := []struct {
		name           string
		header         http.Header
		expectedResult *AdditionalRewrapContext
		expectedError  error
		errorContains  string
	}{
		{
			name:   "nil header",
			header: nil,
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name:   "empty header",
			header: make(http.Header),
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name: "header without obligations",
			header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name: "valid single watermark obligation",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark"]}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{"https://demo.com/obl/test/value/watermark"},
				},
			},
			expectedError: nil,
		},
		{
			name: "valid multiple obligations",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","https://demo.com/obl/test/value/geofence"]}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{"https://demo.com/obl/test/value/watermark", "https://demo.com/obl/test/value/geofence"},
				},
			},
			expectedError: nil,
		},
		{
			name: "mixed valid and invalid fqns",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","https://example.com/attr/Classification/value/restricted","https://virtru.com/obl/test/value/audit"]}}`))},
			},
			expectedResult: nil,
			expectedError:  identifier.ErrInvalidFQNFormat,
			errorContains:  "https://example.com/attr/Classification/value/restricted",
		},
		{
			name: "empty obligations array",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": []}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name: "no fulfillableFQNs array",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name: "no obligations array",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
		{
			name: "obligations with empty values filtered out",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","","https://demo.com/obl/test/value/geofence"]}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{"https://demo.com/obl/test/value/watermark", "https://demo.com/obl/test/value/geofence"},
				},
			},
			expectedError: nil,
		},
		{
			name: "obligations with whitespace trimmed",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": [" https://demo.com/obl/test/value/watermark "," https://demo.com/obl/test/value/geofence "]}}`))},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{"https://demo.com/obl/test/value/watermark", "https://demo.com/obl/test/value/geofence"},
				},
			},
			expectedError: nil,
		},
		{
			name: "invalid FQN format obligation",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["invalid-obligation-format"]}}`))},
			},
			expectedResult: nil,
			expectedError:  identifier.ErrInvalidFQNFormat,
			errorContains:  "invalid-obligation-format",
		},
		{
			name: "mixed invalid FQN format obligation",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","invalid-obligation-format"]}}`))},
			},
			expectedResult: nil,
			expectedError:  identifier.ErrInvalidFQNFormat,
			errorContains:  "invalid-obligation-format",
		},
		{
			name: "invalid base64 encoding",
			header: http.Header{
				additionalRewrapContextHeader: []string{`{"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","invalid-obligation-format"]}}`},
			},
			expectedResult: nil,
			expectedError:  ErrDecodingRewrapContext,
		},
		{
			name: "invalid JSON format",
			header: http.Header{
				additionalRewrapContextHeader: []string{base64.StdEncoding.EncodeToString([]byte(`{invalid json}`))},
			},
			expectedResult: nil,
			expectedError:  ErrUnmarshalingRewrapContext,
		},
		{
			name: "empty base64 string",
			header: http.Header{
				additionalRewrapContextHeader: []string{""},
			},
			expectedResult: &AdditionalRewrapContext{
				Obligations: ObligationCtx{
					FulfillableFQNs: []string{},
				},
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getAdditionalRewrapContext(tt.header)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				if tt.errorContains != "" {
					require.ErrorContains(t, err, tt.errorContains)
				}
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestCreateKAOMetadata(t *testing.T) {
	tests := []struct {
		name        string
		obligations []string
		expected    map[string]*structpb.Value
	}{
		{
			name:        "single obligation",
			obligations: []string{"https://demo.com/obl/test/value/watermark"},
			expected: map[string]*structpb.Value{
				requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
					Values: []*structpb.Value{
						structpb.NewStringValue("https://demo.com/obl/test/value/watermark"),
					},
				}),
			},
		},
		{
			name: "multiple obligations",
			obligations: []string{
				"https://demo.com/obl/test/value/watermark",
				"https://demo.com/obl/test/value/geofence",
				"https://example.com/obl/test/value/mfa",
			},
			expected: map[string]*structpb.Value{
				requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
					Values: []*structpb.Value{
						structpb.NewStringValue("https://demo.com/obl/test/value/watermark"),
						structpb.NewStringValue("https://demo.com/obl/test/value/geofence"),
						structpb.NewStringValue("https://example.com/obl/test/value/mfa"),
					},
				}),
			},
		},
		{
			name:        "empty obligations list",
			obligations: []string{},
			expected: map[string]*structpb.Value{
				requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
					Values: []*structpb.Value{},
				}),
			},
		},
		{
			name:        "nil obligations list",
			obligations: nil,
			expected: map[string]*structpb.Value{
				requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
					Values: []*structpb.Value{},
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createKAOMetadata(tt.obligations)

			// Verify the result has the correct structure
			require.NotNil(t, result)
			require.Contains(t, result, requiredObligationsHeader)

			// Get the list value from both result and expected
			resultList := result[requiredObligationsHeader].GetListValue()
			expectedList := tt.expected[requiredObligationsHeader].GetListValue()

			require.NotNil(t, resultList)
			require.NotNil(t, expectedList)

			// Verify the number of values matches
			require.Len(t, resultList.GetValues(), len(expectedList.GetValues()))

			// Verify each obligation value
			for i, expectedValue := range expectedList.GetValues() {
				actualValue := resultList.GetValues()[i]
				require.Equal(t, expectedValue.GetStringValue(), actualValue.GetStringValue())
			}
		})
	}
}

func TestAddResultsToResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    policyKAOResults
		expected *kaspb.RewrapResponse
	}{
		{
			name: "single policy with successful KAO",
			input: policyKAOResults{
				"policy-1": {
					"kao-1": kaoResult{
						ID:                  "kao-1",
						Encapped:            []byte("encrypted-key-data"),
						RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
					},
				},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-1",
								Status:            kPermitStatus,
								Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: []byte("encrypted-key-data")},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("https://demo.com/obl/test/value/watermark"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "single policy with failed KAO and obligations",
			input: policyKAOResults{
				"policy-1": {
					"kao-1": kaoResult{
						ID:                  "kao-1",
						Error:               errors.New("access denied"),
						RequiredObligations: []string{"https://demo.com/obl/test/value/watermark"},
					},
				},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-1",
								Status:            kFailedStatus,
								Result:            &kaspb.KeyAccessRewrapResult_Error{Error: "access denied"},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("https://demo.com/obl/test/value/watermark"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "single policy with failed KAO and no obligations",
			input: policyKAOResults{
				"policy-1": {
					"kao-1": kaoResult{
						ID:    "kao-1",
						Error: errors.New("invalid key"),
					},
				},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-1",
								Status:            kFailedStatus,
								Result:            &kaspb.KeyAccessRewrapResult_Error{Error: "invalid key"},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "single policy with unprocessed KAO",
			input: policyKAOResults{
				"policy-1": {
					"kao-1": kaoResult{
						ID: "kao-1",
						// No Error and no Encapped data
					},
				},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-1",
								Status:            kFailedStatus,
								Result:            &kaspb.KeyAccessRewrapResult_Error{Error: "kao not processed by kas"},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple policies with mixed results",
			input: policyKAOResults{
				"policy-1": {
					"kao-1": kaoResult{
						ID:       "kao-1",
						Encapped: []byte("encrypted-key-1"),
					},
					"kao-2": kaoResult{
						ID:                  "kao-2",
						Error:               errors.New("forbidden"),
						RequiredObligations: []string{"https://demo.com/obl/test/value/watermark", "https://demo.com/obl/test/value/geofence"},
					},
				},
				"policy-2": {
					"kao-3": kaoResult{
						ID:       "kao-3",
						Encapped: []byte("encrypted-key-3"),
					},
				},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-1",
								Status:            kPermitStatus,
								Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: []byte("encrypted-key-1")},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{},
									}),
								},
							},
							{
								KeyAccessObjectId: "kao-2",
								Status:            kFailedStatus,
								Result:            &kaspb.KeyAccessRewrapResult_Error{Error: "forbidden"},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("https://demo.com/obl/test/value/watermark"),
											structpb.NewStringValue("https://demo.com/obl/test/value/geofence"),
										},
									}),
								},
							},
						},
					},
					{
						PolicyId: "policy-2",
						Results: []*kaspb.KeyAccessRewrapResult{
							{
								KeyAccessObjectId: "kao-3",
								Status:            kPermitStatus,
								Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: []byte("encrypted-key-3")},
								Metadata: map[string]*structpb.Value{
									requiredObligationsHeader: structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name:  "empty input",
			input: policyKAOResults{},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{},
			},
		},
		{
			name: "policy with empty KAO map",
			input: policyKAOResults{
				"policy-1": {},
			},
			expected: &kaspb.RewrapResponse{
				Responses: []*kaspb.PolicyRewrapResult{
					{
						PolicyId: "policy-1",
						Results:  []*kaspb.KeyAccessRewrapResult{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := &kaspb.RewrapResponse{}
			addResultsToResponse(response, tt.input)

			// Verify the number of policy responses
			require.Len(t, response.GetResponses(), len(tt.expected.GetResponses()))

			// Sort both responses by PolicyId for consistent comparison
			actualPolicies := make(map[string]*kaspb.PolicyRewrapResult)
			for _, policyResult := range response.GetResponses() {
				actualPolicies[policyResult.GetPolicyId()] = policyResult
			}

			expectedPolicies := make(map[string]*kaspb.PolicyRewrapResult)
			for _, policyResult := range tt.expected.GetResponses() {
				expectedPolicies[policyResult.GetPolicyId()] = policyResult
			}

			// Verify each policy response
			for policyID, expectedPolicy := range expectedPolicies {
				actualPolicy, exists := actualPolicies[policyID]
				require.True(t, exists, "Expected policy %s not found in response", policyID)
				require.Equal(t, expectedPolicy.GetPolicyId(), actualPolicy.GetPolicyId())

				// Verify the number of KAO results
				require.Len(t, actualPolicy.GetResults(), len(expectedPolicy.GetResults()))

				// Sort KAO results by KeyAccessObjectId for consistent comparison
				actualKAOs := make(map[string]*kaspb.KeyAccessRewrapResult)
				for _, kaoResult := range actualPolicy.GetResults() {
					actualKAOs[kaoResult.GetKeyAccessObjectId()] = kaoResult
				}

				expectedKAOs := make(map[string]*kaspb.KeyAccessRewrapResult)
				for _, kaoResult := range expectedPolicy.GetResults() {
					expectedKAOs[kaoResult.GetKeyAccessObjectId()] = kaoResult
				}

				// Verify each KAO result
				for kaoID, expectedKAO := range expectedKAOs {
					actualKAO, actualKAOExists := actualKAOs[kaoID]
					require.True(t, actualKAOExists, "Expected KAO %s not found in policy %s", kaoID, policyID)

					require.Equal(t, expectedKAO.GetKeyAccessObjectId(), actualKAO.GetKeyAccessObjectId())
					require.Equal(t, expectedKAO.GetStatus(), actualKAO.GetStatus())

					// Verify result content
					switch expectedResult := expectedKAO.GetResult().(type) {
					case *kaspb.KeyAccessRewrapResult_KasWrappedKey:
						actualResult, ok := actualKAO.GetResult().(*kaspb.KeyAccessRewrapResult_KasWrappedKey)
						require.True(t, ok, "Expected KasWrappedKey result for KAO %s", kaoID)
						require.Equal(t, expectedResult.KasWrappedKey, actualResult.KasWrappedKey)
					case *kaspb.KeyAccessRewrapResult_Error:
						actualResult, ok := actualKAO.GetResult().(*kaspb.KeyAccessRewrapResult_Error)
						require.True(t, ok, "Expected Error result for KAO %s", kaoID)
						require.Equal(t, expectedResult.Error, actualResult.Error)
					}

					// Verify metadata if expected
					if expectedKAO.GetMetadata() != nil {
						require.NotNil(t, actualKAO.GetMetadata(), "Expected metadata for KAO %s", kaoID)

						// Verify required obligations header
						if expectedObligations, oblExists := expectedKAO.GetMetadata()[requiredObligationsHeader]; oblExists {
							actualObligations, actualExists := actualKAO.GetMetadata()[requiredObligationsHeader]
							require.True(t, actualExists, "Expected obligations header in metadata for KAO %s", kaoID)

							expectedList := expectedObligations.GetListValue()
							actualList := actualObligations.GetListValue()
							require.NotNil(t, expectedList)
							require.NotNil(t, actualList)
							require.Len(t, actualList.GetValues(), len(expectedList.GetValues()))

							for i, expectedValue := range expectedList.GetValues() {
								actualValue := actualList.GetValues()[i]
								require.Equal(t, expectedValue.GetStringValue(), actualValue.GetStringValue())
							}
						}
					} else if actualKAO.GetMetadata() != nil {
						// If no metadata is expected, actualKAO.Metadata should be nil or empty
						require.Empty(t, actualKAO.GetMetadata(), "Unexpected metadata for KAO %s", kaoID)
					}
				}
			}
		})
	}
}

func TestVerifyRewrapRequests(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	// Valid policy for testing
	validPolicy := &Policy{
		UUID: uuid.New(),
		Body: PolicyBody{
			DataAttributes: []Attribute{
				{
					URI:  "https://example.com/attr/test",
					Name: "test",
				},
			},
		},
	}
	validPolicyJSON, _ := json.Marshal(validPolicy)
	validPolicyB64 := base64.StdEncoding.EncodeToString(validPolicyJSON)

	tests := []struct {
		name          string
		setupProvider func() *Provider
		request       *kaspb.UnsignedRewrapRequest_WithPolicyRequest
		expectError   bool
		errorMessage  string
	}{
		{
			name: "nil request should return error",
			setupProvider: func() *Provider {
				return &Provider{
					Logger: testLogger,
				}
			},
			request:      nil,
			expectError:  true,
			errorMessage: "request is nil",
		},
		{
			name: "nil policy should return error",
			setupProvider: func() *Provider {
				return &Provider{
					Logger: testLogger,
				}
			},
			request: &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				Policy: nil, // nil policy
				KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
					{
						KeyAccessObjectId: "test-kao",
						KeyAccessObject: &kaspb.KeyAccess{
							KeyType: "wrapped",
							Kid:     "test-kid",
						},
					},
				},
			},
			expectError:  true,
			errorMessage: "policy is nil", // The function returns "policy is nil" for nil policy
		},
		{
			name: "nil policy body should return error",
			setupProvider: func() *Provider {
				return &Provider{
					Logger: testLogger,
				}
			},
			request: &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
					Id:   "test-policy",
					Body: "", // empty body will cause JSON decode to fail
				},
				KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
					{
						KeyAccessObjectId: "test-kao",
						KeyAccessObject: &kaspb.KeyAccess{
							KeyType: "wrapped",
							Kid:     "test-kid",
						},
					},
				},
			},
			expectError:  true,
			errorMessage: "unexpected end of JSON input", // Actual error from JSON decode
		},
		{
			name: "nil key access object should return error",
			setupProvider: func() *Provider {
				return &Provider{
					Logger:       testLogger,
					KeyDelegator: &trust.DelegatingKeyService{}, // Use minimal implementation
				}
			},
			request: &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
					Id:   "test-policy",
					Body: validPolicyB64,
				},
				KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
					{
						KeyAccessObjectId: "test-kao",
						KeyAccessObject:   nil, // nil key access object
					},
				},
			},
			expectError:  true,
			errorMessage: "no valid KAOs", // Actual error message
		},
		{
			name: "empty key access objects should return error",
			setupProvider: func() *Provider {
				return &Provider{
					Logger: testLogger,
				}
			},
			request: &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
					Id:   "test-policy",
					Body: validPolicyB64,
				},
				KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{}, // empty slice
			},
			expectError:  true,
			errorMessage: "no valid KAOs", // Actual error message
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := tt.setupProvider()
			ctx := t.Context()

			// Test that the function doesn't panic and returns appropriate errors
			var err error
			var policy *Policy
			var results map[string]kaoResult

			assert.NotPanics(t, func() {
				policy, results, err = provider.verifyRewrapRequests(ctx, tt.request)
			}, "Function should not panic: "+tt.name)

			if tt.expectError {
				require.Error(t, err, "Expected error but got none: "+tt.name)
				assert.Contains(t, err.Error(), tt.errorMessage, "Error message should contain expected text: "+tt.errorMessage)
			} else {
				require.NoError(t, err, "Unexpected error: "+tt.name)
				assert.NotNil(t, policy, "Policy should not be nil on success")
				assert.NotNil(t, results, "Results should not be nil on success")
			}
		})
	}
}
