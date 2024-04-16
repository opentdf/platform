package access

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/kas/tdf3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

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
	mockIdPOrigin = "https://keycloak-http/"
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

func publicKey(t *testing.T) *rsa.PublicKey {
	b, rest := pem.Decode([]byte(rsaPublic))
	require.NotNil(t, b)
	assert.Empty(t, rest)

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	require.NotNil(t, pub)
	require.NoError(t, err)
	return pub.(*rsa.PublicKey)
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
	return pub.(*rsa.PublicKey)
}

func keyAccessWrappedRaw(t *testing.T) tdf3.KeyAccess {
	policyBytes := fauxPolicyBytes(t)

	wrappedKey, err := tdf3.EncryptWithPublicKey([]byte(plainKey), entityPublicKey(t))
	require.NoError(t, err, "rewrap: encryptWithPublicKey failed")

	bindingBytes, err := generateHMACDigest(context.Background(), policyBytes, []byte(plainKey))
	require.NoError(t, err)

	dst := make([]byte, hex.EncodedLen(len(bindingBytes)))
	hex.Encode(dst, bindingBytes)
	policyBinding := base64.StdEncoding.EncodeToString(dst)
	slog.Debug("Generated binding", "binding", bindingBytes, "encodedBinding", policyBinding)

	return tdf3.KeyAccess{
		Type:          "wrapped",
		URL:           "http://127.0.0.1:4000",
		Protocol:      "kas",
		WrappedKey:    []byte(base64.StdEncoding.EncodeToString(wrappedKey)),
		PolicyBinding: policyBinding,
	}
}

type RSAPublicKey rsa.PublicKey

func (publicKey *RSAPublicKey) VerifySignature(ctx context.Context, raw string) (payload []byte, err error) {
	slog.Debug("Verifying key")
	tok, err := jws.Verify([]byte(raw), jws.WithKey(jwa.RS256, rsa.PublicKey(*publicKey)))
	if err != nil {
		slog.Error("jws.Verify fail", "raw", raw)
		return nil, err
	}
	return tok, nil
}

func standardClaims() ClaimsObject {
	return ClaimsObject{
		ClientPublicSigningKey: rsaPublicAlt,
		Entitlements: []Entitlement{
			{
				EntityID: "clientsubjectId1-14443434-1111343434-asdfdffff",
				EntityAttributes: []Attribute{
					{
						URI:  "https://example.com/attr/COI/value/PRX",
						Name: "category of intent",
					},
					{
						URI:  "https://example.com/attr/Classification/value/S",
						Name: "classification",
					},
				},
			},
			{
				EntityID: "testuser1",
				EntityAttributes: []Attribute{
					{
						URI:  "https://example.com/attr/COI/value/PRX",
						Name: "category of intent",
					},
					{
						URI:  "https://example.com/attr/Classification/value/S",
						Name: "classification",
					},
				},
			},
		},
	}
}

func signedMockJWT(t *testing.T, signer *rsa.PrivateKey) []byte {
	tok := jwt.New()

	var err error
	set := func(k string, v interface{}) {
		if err != nil {
			return
		}
		err = tok.Set(k, v)
	}
	set(jwt.IssuerKey, mockIdPOrigin)
	set(jwt.AudienceKey, `testonly`)
	set(jwt.SubjectKey, `testuser1`)
	set("tdf_claims", standardClaims())
	require.NoError(t, err)

	raw, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signer))
	require.NoError(t, err)
	return raw
}

func jwtStandard(t *testing.T) []byte {
	return signedMockJWT(t, privateKey(t))
}

func jwtWrongIssuer(t *testing.T) []byte {
	tok := jwt.New()

	var err error
	set := func(k string, v interface{}) {
		if err != nil {
			return
		}
		err = tok.Set(k, v)
	}
	set(jwt.IssuerKey, "https://someone.else/")
	set(jwt.AudienceKey, `testonly`)
	set(jwt.SubjectKey, `testuser1`)
	set("tdf_claims", standardClaims())
	require.NoError(t, err)

	raw, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privateKey(t)))
	require.NoError(t, err)
	return raw
}

func jwtWrongKey(t *testing.T) []byte {
	return signedMockJWT(t, entityPrivateKey(t))
}

func mockVerifier(t *testing.T) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(
		mockIdPOrigin,
		(*RSAPublicKey)(publicKey(t)),
		&oidc.Config{SkipExpiryCheck: true, ClientID: "testonly"},
	)
}

func makeRewrapBody(t *testing.T, policy []byte) []byte {
	mockBody := RequestBody{
		KeyAccess:       keyAccessWrappedRaw(t),
		Policy:          string(policy),
		ClientPublicKey: rsaPublicAlt,
	}
	bodyData, err := json.Marshal(mockBody)
	require.NoError(t, err)
	tok := jwt.New()
	err = tok.Set("requestBody", string(bodyData))
	require.NoError(t, err)

	s, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, entityPrivateKey(t)))
	require.NoError(t, err)
	return s
}

func TestParseAndVerifyRequest(t *testing.T) {
	srt := makeRewrapBody(t, fauxPolicyBytes(t))
	badPolicySrt := makeRewrapBody(t, emptyPolicyBytes())

	p := &Provider{
		OIDCVerifier: mockVerifier(t),
	}

	var tests = []struct {
		name    string
		bearer  []byte
		body    []byte
		bearish bool
		polite  bool
		addDPoP bool
	}{
		{"good", jwtStandard(t), srt, true, true, true},
		{"bad bearer wrong issuer", jwtWrongIssuer(t), srt, false, true, true},
		{"bad bearer signature", jwtWrongKey(t), srt, false, true, true},
		{"different policy", jwtStandard(t), badPolicySrt, true, false, true},
		// once we start always requiring auth then add this test back {"no dpop token included", jwtStandard(), srt, false, true, false},
	}
	// The execution loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.addDPoP {
				key, err := jwk.FromRaw(entityPublicKey(t))
				require.NoError(t, err, "couldn't get JWK from key")

				ctx = auth.ContextWithJWK(ctx, key)
			}

			verified, err := p.verifyBearerAndParseRequestBody(
				ctx,
				&kaspb.RewrapRequest{
					Bearer:             string(tt.bearer),
					SignedRequestToken: string(tt.body),
				},
			)
			slog.Info("verifiy repspponse", "v", verified, "e", err)
			if tt.bearish {
				require.NoError(t, err, "failed to parse srt=[%s], tok=[%s]", tt.body, tt.bearer)
				require.NotNil(t, verified.publicKey, "unable to load public key")
				require.NotNil(t, verified.requestBody, "unable to load request body")

				policy, err := p.verifyAndParsePolicy(context.Background(), verified.requestBody, []byte(plainKey))
				if tt.polite {
					require.NoError(t, err, "failed to verify policy body=[%v]", tt.body)
					assert.Len(t, policy.Body.DataAttributes, 2, "incorrect policy body=[%v]", policy.Body)
				} else {
					require.Error(t, err, "failed to fail policy body=[%v]", tt.body)
				}
			} else {
				require.Error(t, err, "failed to fail srt=[%s], tok=[%s]", tt.body, tt.bearer)
			}
		})
	}
}

func TestLegacyBearerTokenFails(t *testing.T) {
	var tests = []struct {
		name     string
		metadata []string
		msg      string
	}{
		{"no auth header", []string{}, "no auth token"},
		{"multiple auth", []string{"Authorization", "a", "Authorization", "b"}, "auth fail"},
		{"no bearer", []string{"Authorization", "a"}, "auth fail"},
		{"no token", []string{"Authorization", "Bearer "}, "auth fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(tt.metadata...))
			p, err := legacyBearerToken(ctx, "")
			assert.Empty(t, p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.msg)
		})
	}
}

func TestLegacyBearerTokenEtc(t *testing.T) {
	p, err := legacyBearerToken(context.Background(), "")
	assert.Empty(t, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no auth token")

	p, err = legacyBearerToken(context.Background(), "something")
	assert.Equal(t, "something", p)
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Authorization", "Bearer TOKEN"))
	p, err = legacyBearerToken(ctx, "")
	assert.Equal(t, "TOKEN", p)
	require.NoError(t, err)
}

func TestHandlerAuthFailure0(t *testing.T) {
	hsmSession, _ := security.New(&security.HSMConfig{})
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: hsmSession,
		OIDCVerifier:   nil,
	}

	body := `{"mock": "value"}`
	_, err := kas.Rewrap(context.Background(), &kaspb.RewrapRequest{SignedRequestToken: body})
	status, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, status.Code())
}

func TestHandlerAuthFailure1(t *testing.T) {
	hsmSession, _ := security.New(&security.HSMConfig{})
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: hsmSession,
		OIDCVerifier:   nil,
	}

	body := `{"mock": "value"}`
	md := map[string][]string{
		"Authorization": {"Bearer invalidToken"},
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := kas.Rewrap(ctx, &kaspb.RewrapRequest{SignedRequestToken: body})
	status, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, status.Code())
}

func TestHandlerAuthFailure2(t *testing.T) {
	hsmSession, _ := security.New(&security.HSMConfig{})
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:            *kasURI,
		CryptoProvider: hsmSession,
		OIDCVerifier:   nil,
	}

	body := `{"mock": "value"}`
	_, err := kas.Rewrap(context.Background(), &kaspb.RewrapRequest{SignedRequestToken: body, Bearer: "invalidToken"})
	status, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, status.Code())
}
