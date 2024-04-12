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
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/security"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/kas/tdf3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
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

func fauxPolicyBytes() []byte {
	data, err := json.Marshal(fauxPolicy())
	if err != nil {
		panic(err)
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst
}

func privateKey() *rsa.PrivateKey {
	b, rest := pem.Decode([]byte(rsaPrivate))
	if b == nil || len(rest) > 0 {
		slog.Error("failed private key", "bytes", b, "rest", rest)
		panic(len(rest))
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if k == nil || err != nil {
		panic(err)
	}
	return k
}

func publicKey() *rsa.PublicKey {
	b, rest := pem.Decode([]byte(rsaPublic))
	if b == nil || len(rest) > 0 {
		slog.Error("failed public key", "bytes", b, "rest", rest)
		panic(len(rest))
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if pub == nil || err != nil {
		panic(err)
	}
	return pub.(*rsa.PublicKey)
}

func entityPrivateKey() *rsa.PrivateKey {
	b, rest := pem.Decode([]byte(rsaPrivateAlt))
	if b == nil || len(rest) > 0 {
		slog.Error("failed entity private key", "bytes", b, "rest", rest)
		panic(len(rest))
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if k == nil || err != nil {
		panic(err)
	}
	return k
}

func entityPublicKey() *rsa.PublicKey {
	b, rest := pem.Decode([]byte(rsaPublicAlt))
	if b == nil || len(rest) > 0 {
		slog.Error("failed entity public key", "bytes", b, "rest", rest)
		panic(len(rest))
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if pub == nil || err != nil {
		panic(err)
	}
	return pub.(*rsa.PublicKey)
}

func keyAccessWrappedRaw() tdf3.KeyAccess {
	policyBytes := fauxPolicyBytes()

	wrappedKey, err := tdf3.EncryptWithPublicKey([]byte(plainKey), entityPublicKey())
	if err != nil {
		slog.Warn("rewrap: encryptWithPublicKey failed", "err", err, "clientPublicKey", rsaPublicAlt)
		panic(err)
	}
	bindingBytes, err := generateHMACDigest(context.Background(), policyBytes, []byte(plainKey))
	if err != nil {
		panic(err)
	}

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
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		slog.Error("jwt parse fail", "raw", raw)
		return nil, err
	}

	out := make(map[string]interface{})
	if err := tok.Claims((*rsa.PublicKey)(publicKey), &out); err != nil {
		slog.Error("claim fail")
		return nil, err
	}
	jsonString, err := json.Marshal(out)
	if err != nil {
		slog.Error("marshal fail")
		return nil, err
	}
	return []byte(jsonString), nil
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

func signedMockJWT(signer *rsa.PrivateKey) string {
	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       signer,
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(err)
	}
	cl := customClaimsHeader{
		Subject:   "testuser1",
		ClientID:  "testonly",
		TDFClaims: standardClaims(),
	}

	raw, err := jwt.Signed(sig).Claims(jwt.Claims{Issuer: mockIdPOrigin, Audience: jwt.Audience{"testonly"}}).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func jwtStandard() string {
	return signedMockJWT(privateKey())
}

func jwtWrongIssuer() string {
	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       privateKey(),
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(err)
	}
	cl := customClaimsHeader{
		Subject:   "testuser1",
		ClientID:  "testonly",
		TDFClaims: standardClaims(),
	}

	raw, err := jwt.Signed(sig).Claims(jwt.Claims{Issuer: "https://someone.else/", Audience: jwt.Audience{"testonly"}}).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func jwtWrongKey() string {
	return signedMockJWT(entityPrivateKey())
}

func mockVerifier() *oidc.IDTokenVerifier {
	return oidc.NewVerifier(
		mockIdPOrigin,
		(*RSAPublicKey)(publicKey()),
		&oidc.Config{SkipExpiryCheck: true, ClientID: "testonly"},
	)
}

func makeRewrapBody(_ *testing.T, policy []byte) (string, error) {
	mockBody := RequestBody{
		KeyAccess:       keyAccessWrappedRaw(),
		Policy:          string(policy),
		ClientPublicKey: rsaPublicAlt,
	}
	bodyData, err := json.Marshal(mockBody)
	if err != nil {
		panic(err)
	}
	cl := customClaimsBody{
		RequestBody: string(bodyData),
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       entityPrivateKey(),
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(cl).CompactSerialize()
}

func TestParseAndVerifyRequest(t *testing.T) {
	srt, err := makeRewrapBody(t, fauxPolicyBytes())
	if err != nil {
		t.Errorf("failed to generate srt=[%s], err=[%v]", srt, err)
	}
	badPolicySrt, err := makeRewrapBody(t, emptyPolicyBytes())
	if err != nil {
		t.Errorf("failed to generate badPolicySrt=[%s], err=[%v]", badPolicySrt, err)
	}

	p := &Provider{
		OIDCVerifier: mockVerifier(),
	}

	var tests = []struct {
		name    string
		tok     string
		body    string
		bearish bool
		polite  bool
		addDPoP bool
	}{
		{"good", jwtStandard(), srt, true, true, true},
		{"bad bearer wrong issuer", jwtWrongIssuer(), srt, false, true, true},
		{"bad bearer signature", jwtWrongKey(), srt, false, true, true},
		{"different policy", jwtStandard(), badPolicySrt, true, false, true},
		// once we start always requiring auth then add this test back {"no dpop token included", jwtStandard(), srt, false, true, false},
	}
	// The execution loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.addDPoP {
				key, err := jwk.FromRaw(entityPublicKey())
				if err != nil {
					t.Fatalf("couldn't get JWK from key")
				}
				ctx = auth.ContextWithJWK(ctx, key)
			}

			verified, err := p.verifyBearerAndParseRequestBody(
				ctx,
				&kaspb.RewrapRequest{
					Bearer:             tt.tok,
					SignedRequestToken: tt.body,
				},
			)
			if tt.bearish {
				if err != nil {
					t.Errorf("failed to parse srt=[%s], tok=[%s], err=[%v]", tt.body, tt.tok, err)
				}
				if verified.publicKey == nil {
					t.Error("unable to load public key")
				}
				if verified.requestBody == nil {
					t.Error("unable to load request body")
				}
				policy, err := p.verifyAndParsePolicy(context.Background(), verified.requestBody, []byte(plainKey))
				if tt.polite {
					if err != nil || len(policy.Body.DataAttributes) != 2 {
						t.Errorf("failed to verify policy body=[%v], err=[%v]", tt.body, err)
					}
				} else {
					if err == nil {
						t.Errorf("failed to fail policy body=[%v], err=[%v]", tt.body, err)
					}
				}
			} else {
				if err == nil {
					t.Errorf("failed to fail srt=[%s], tok=[%s]", tt.body, tt.tok)
				}
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
			if p != "" || err == nil || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("should fail p=[%s], err=[%s], expected [%s]", p, err, tt.msg)
			}
		})
	}
}

func TestSignedRequestTokenVerification(t *testing.T) {

}

func TestLegacyBearerTokenEtc(t *testing.T) {
	p, err := legacyBearerToken(context.Background(), "")
	if p != "" || err == nil || !strings.Contains(err.Error(), "no auth token") {
		t.Errorf("should fail p=[%s], err=[%s], expected 'no auth token'", p, err)
	}

	p, err = legacyBearerToken(context.Background(), "something")
	if p != "something" || err != nil {
		t.Errorf("should succeed p=[%s], err=[%s], expected 'something' in p", p, err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Authorization", "Bearer TOKEN"))
	p, err = legacyBearerToken(ctx, "")
	if p != "TOKEN" || err != nil {
		t.Errorf("should succeed p=[%s], err=[%s], expected p='TOKEN'", p, err)
	}
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
	if !ok || status.Code() != codes.Unauthenticated {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
	}
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
	if !ok || status.Code() != codes.PermissionDenied {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
	}
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
	if !ok || status.Code() != codes.PermissionDenied {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
	}
}
