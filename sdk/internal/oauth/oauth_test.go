package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/fixtures"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type OAuthSuite struct {
	suite.Suite
	dpopJWK               jwk.Key
	keycloakContainer     tc.Container
	keycloakEndpoint      string
	keycloakHTTPSEndpoint string
}

func TestOAuthTestSuite(t *testing.T) {
	suite.Run(t, new(OAuthSuite))
}

func (s *OAuthSuite) SetupSuite() {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	dpopJWK, err := jwk.FromRaw(dpopKey)
	s.Require().NoError(err)
	s.Require().NoError(dpopJWK.Set("use", "sig"))
	s.Require().NoError(dpopJWK.Set("alg", jwa.RS256.String()))

	s.dpopJWK = dpopJWK
	ctx := context.Background()

	keycloak, idpEndpoint, idpHTTPSEndpoint := setupKeycloak(ctx, s.T())
	s.keycloakContainer = keycloak
	s.keycloakEndpoint = idpEndpoint
	s.keycloakHTTPSEndpoint = idpHTTPSEndpoint
}

func (s *OAuthSuite) TearDownSuite() {
	_ = s.keycloakContainer.Terminate(context.Background())
}

//go:embed testdata/keycloak-ca.pem
var ca []byte

func (s *OAuthSuite) TestCertExchangeFromKeycloak() {
	clientCredentials := ClientCredentials{
		ClientID:   "opentdf-sdk",
		ClientAuth: "secret",
	}
	cert, err := tls.LoadX509KeyPair("testdata/sampleuser.crt", "testdata/sampleuser.key")
	rootCAs, _ := x509.SystemCertPool()
	rootCAs.AppendCertsFromPEM(ca)
	s.Require().NoError(err)
	tlsConfig := tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}
	exhcangeInfo := CertExchangeInfo{TLSConfig: &tlsConfig, Audience: []string{"opentdf-sdk"}}

	tok, err := DoCertExchange(
		context.Background(),
		s.keycloakHTTPSEndpoint,
		exhcangeInfo,
		clientCredentials,
		s.dpopJWK)
	s.Require().NoError(err)

	tokenDetails, err := jwt.ParseString(tok.AccessToken, jwt.WithVerify(false))
	s.Require().NoError(err)

	cnfClaim, ok := tokenDetails.Get("cnf")
	s.Require().True(ok)
	cnfClaimsMap, ok := cnfClaim.(map[string]interface{})
	s.Require().True(ok)
	idpKeyFingerprint, ok := cnfClaimsMap["jkt"].(string)
	s.Require().True(ok)
	s.Require().NotEmpty(idpKeyFingerprint)
	pk, err := s.dpopJWK.PublicKey()
	s.Require().NoError(err)
	hash, err := pk.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)

	expectedThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)
	s.Equal(expectedThumbprint, idpKeyFingerprint, "didn't get expected fingerprint")
	s.Positivef(tok.ExpiresIn, "invalid expiration is before current time: %v", tok)
	s.Falsef(tok.Expired(), "got a token that is currently expired: %v", tok)

	name, ok := tokenDetails.Get("name")
	s.Require().True(ok)
	s.Equal("sample user", name, "got unexpected name")
}

func (s *OAuthSuite) TestGettingAccessTokenFromKeycloak() {
	clientCredentials := ClientCredentials{
		ClientID:   "opentdf-sdk",
		ClientAuth: "secret",
	}

	tok, err := GetAccessToken(
		http.DefaultClient,
		s.keycloakEndpoint,
		[]string{"testscope"},
		clientCredentials,
		s.dpopJWK)

	s.Require().NoError(err)

	tokenDetails, err := jwt.ParseString(tok.AccessToken, jwt.WithVerify(false))
	s.Require().NoError(err)

	cnfClaim, ok := tokenDetails.Get("cnf")
	s.Require().True(ok)
	cnfClaimsMap, ok := cnfClaim.(map[string]interface{})
	s.Require().True(ok)
	idpKeyFingerprint, ok := cnfClaimsMap["jkt"].(string)
	s.Require().True(ok)
	s.Require().NotEmpty(idpKeyFingerprint)
	pk, err := s.dpopJWK.PublicKey()
	s.Require().NoError(err)
	hash, err := pk.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)

	scope, ok := tokenDetails.Get("scope")
	s.Require().True(ok)
	scopeString, ok := scope.(string)
	s.Require().True(ok)
	s.Require().True(strings.Contains(scopeString, "testscope"))

	expectedThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)
	s.Equal(expectedThumbprint, idpKeyFingerprint, "didn't get expected fingerprint")
	s.Positivef(tok.ExpiresIn, "invalid expiration is before current time: %v", tok)
	s.Falsef(tok.Expired(), "got a token that is currently expired: %v", tok)

	// verify that we got a token that has the opentdf-standard role, which only the sdk client has
	ra, ok := tokenDetails.Get("realm_access")
	s.Require().True(ok)
	raMap, ok := ra.(map[string]interface{})
	s.Require().True(ok)
	roles, ok := raMap["roles"]
	s.Require().True(ok)
	rolesList, ok := roles.([]interface{})
	s.Require().True(ok)
	s.Require().True(slices.Contains(rolesList, "opentdf-standard"), "missing the `opentdf-standard` role")
}

func (s *OAuthSuite) TestDoingTokenExchangeWithKeycloak() {
	ctx := context.Background()

	clientCredentials := ClientCredentials{
		ClientID:   "opentdf-sdk",
		ClientAuth: "secret",
	}

	subjectToken, err := GetAccessToken(
		http.DefaultClient,
		s.keycloakEndpoint,
		[]string{"testscope"},
		clientCredentials,
		s.dpopJWK)
	s.Require().NoError(err)

	exchangeCredentials := ClientCredentials{
		ClientID:   "opentdf",
		ClientAuth: "secret",
	}

	tokenExchange := TokenExchangeInfo{
		SubjectToken: subjectToken.AccessToken,
		Audience:     []string{"opentdf-sdk"},
	}

	exchangedTok, err := DoTokenExchange(ctx, http.DefaultClient, s.keycloakEndpoint, []string{}, exchangeCredentials, tokenExchange, s.dpopJWK)
	s.Require().NoError(err)

	tokenDetails, err := jwt.ParseString(exchangedTok.AccessToken, jwt.WithVerify(false))
	s.Require().NoError(err)

	cnfClaim, ok := tokenDetails.Get("cnf")
	s.Require().True(ok)
	cnfClaimsMap, ok := cnfClaim.(map[string]interface{})
	s.Require().True(ok)
	idpKeyFingerprint, ok := cnfClaimsMap["jkt"].(string)
	s.Require().True(ok)
	s.Require().NotEmpty(idpKeyFingerprint)
	pk, err := s.dpopJWK.PublicKey()
	s.Require().NoError(err)
	hash, err := pk.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)

	expectedThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)
	s.Equal(expectedThumbprint, idpKeyFingerprint, "didn't get expected fingerprint")
	s.Positivef(subjectToken.ExpiresIn, "invalid expiration is before current time: %v", subjectToken)
	s.Falsef(subjectToken.Expired(), "got a token that is currently expired: %v", subjectToken)

	// verify that we got a token that has the opentdf-standard role, which only the sdk client has
	ra, ok := tokenDetails.Get("realm_access")
	s.Require().True(ok)
	raMap, ok := ra.(map[string]interface{})
	s.Require().True(ok)
	roles, ok := raMap["roles"]
	s.Require().True(ok)
	rolesList, ok := roles.([]interface{})
	s.Require().True(ok)
	s.Require().True(slices.Contains(rolesList, "opentdf-standard"), "missing the `opentdf-standard` role")

	// verify that the calling client is the authorized party
	azpClaim, ok := tokenDetails.Get("azp")
	s.Require().True(ok)
	s.Require().Equal(exchangeCredentials.ClientID, azpClaim)

	// verify that the exchanged token has a scope that is only allowed for the client that got the original token
	scope, ok := tokenDetails.Get("scope")
	s.Require().True(ok)
	scopeString, ok := scope.(string)
	s.Require().True(ok)
	s.Require().True(strings.Contains(scopeString, "testscope"))
}

func (s *OAuthSuite) TestClientSecretNoNonce() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Equal("/token", r.URL.Path)
		s.NoError(r.ParseForm())

		validateBasicAuth(r, s.T())
		extractDPoPToken(r, s.T())

		tok, err := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()
		s.NoError(err)

		responseBytes, err := json.Marshal(tok)
		s.NoError(err, "error writing response")

		w.Header().Add("Content-Type", "application/json")
		_, err = w.Write(responseBytes)
		s.NoError(err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err := GetAccessToken(http.DefaultClient, server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, s.dpopJWK)
	s.Require().NoError(err, "didn't get a token back from the IdP")
}

func (s *OAuthSuite) TestClientSecretWithNonce() {
	timesCalled := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled++
		s.Equal("/token", r.URL.Path, "surprise http request to mock oauth service")
		err := r.ParseForm()
		s.NoError(err, "error parsing oauth request")

		validateBasicAuth(r, s.T())

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte{})
			s.NoError(err, "error writing response")
			return
		} else if timesCalled > 2 {
			s.T().Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDPoPToken(r, s.T())

		nonce, exists := clientTok.Get("nonce")
		if !exists {
			s.T().Logf("didn't get nonce assertion")
		}

		if nonceStr, ok := nonce.(string); ok {
			if nonceStr != "dfdffdfddf" {
				s.T().Errorf("Got incorrect nonce: %v", nonce)
			}
		} else {
			s.T().Errorf("Nonce is not a string")
		}

		tok, _ := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()

		responseBytes, err := json.Marshal(tok)
		if err != nil {
			s.T().Errorf("error writing response: %v", err)
		}

		w.Header().Add("Content-Type", "application/json")
		l, err := w.Write(responseBytes)
		s.Len(responseBytes, l)
		s.NoError(err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err := GetAccessToken(http.DefaultClient, server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, s.dpopJWK)
	if err != nil {
		s.T().Errorf("didn't get a token back from the IdP: %v", err)
	}
}

func TestTokenExpiration_RespectsLeeway(t *testing.T) {
	expiredToken := Token{
		received:  time.Now().Add(-tokenExpirationBuffer - 10*time.Second),
		ExpiresIn: 5,
	}
	if !expiredToken.Expired() {
		t.Fatalf("token should be expired")
	}

	goodToken := Token{
		received:  time.Now(),
		ExpiresIn: 2 * int64(tokenExpirationBuffer/time.Second),
	}

	if goodToken.Expired() {
		t.Fatalf("token should not be expired")
	}

	justOverBorderToken := Token{
		received:  time.Now(),
		ExpiresIn: int64(tokenExpirationBuffer/time.Second) - 1,
	}

	if !justOverBorderToken.Expired() {
		t.Fatalf("token should not be expired")
	}
}

func (s *OAuthSuite) TestSignedJWTWithNonce() {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err, "error generating dpop key")
	dpopJWK, err := jwk.FromRaw(dpopKey)
	s.Require().NoError(err)
	s.Require().NoError(dpopJWK.Set("use", "sig"))
	s.Require().NoError(dpopJWK.Set("alg", jwa.RS256.String()))

	clientAuthKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err, "error generating clientAuth key")
	clientAuthJWK, err := jwk.FromRaw(clientAuthKey)
	s.Require().NoError(err, "error constructing raw JWK")
	s.Require().NoError(clientAuthJWK.Set("use", "sig"))
	s.Require().NoError(clientAuthJWK.Set("alg", jwa.RS256.String()))
	clientPublicKey, err := clientAuthJWK.PublicKey()
	s.Require().NoError(err, "error getting public JWK from client auth JWK [%v]", clientAuthJWK)

	timesCalled := 0

	var url string
	getURL := func() string {
		return url
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled++

		if r.URL.Path != "/token" {
			s.T().Errorf("Expected to request '/token', got: %s", r.URL.Path)
		}
		s.NoError(r.ParseForm())

		validateClientAssertionAuth(r, s.T(), getURL, "theclient", clientPublicKey)

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte{}); err != nil {
				s.T().Errorf("error writing response: %v", err)
			}
			return
		} else if timesCalled > 2 {
			s.T().Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDPoPToken(r, s.T())

		nonce, exists := clientTok.Get("nonce")
		if exists {
			value, ok := nonce.(string)
			if !ok {
				s.T().Errorf("Nonce is not a string")
			} else if value != "dfdffdfddf" {
				s.T().Errorf("Got incorrect nonce: %v", value)
			}
		} else {
			s.T().Logf("didn't get nonce assertion")
		}

		tok, _ := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()

		responseBytes, err := json.Marshal(tok)
		if err != nil {
			s.T().Errorf("error writing response: %v", err)
		}

		w.Header().Add("Content-Type", "application/json")
		l, err := w.Write(responseBytes)
		s.Len(responseBytes, l)
		s.NoError(err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: clientAuthJWK,
	}

	url = server.URL + "/token"

	_, err = GetAccessToken(http.DefaultClient, url, []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	if err != nil {
		s.T().Errorf("didn't get a token back from the IdP: %v", err)
	}
}

/*
*
the token endpoint is a string _but_ we only have the value after we create the server
so we need a way get the value of the url after the server has started
*
*/
func validateClientAssertionAuth(r *http.Request, t *testing.T, tokenEndpoint func() string, clientID string, key jwk.Key) {
	if grant := r.Form.Get("grant_type"); grant != "client_credentials" {
		t.Logf("got the wrong grant type: %s, expected client_credentials", grant)
	}
	if assertionType := r.Form.Get("client_assertion_type"); assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("incorrect client assertion type: %s", assertionType)
	}

	clientAssertion := r.Form.Get("client_assertion")
	if clientAssertion == "" {
		t.Errorf("missing client assertion")
	}

	alg := key.Algorithm()
	if alg == nil {
		t.Logf("no key algorithm specified, using RS256 to verify client signature")
		alg = jwa.RS256
	}

	tok, err := jwt.ParseString(clientAssertion, jwt.WithVerify(true), jwt.WithKey(alg, key))
	if err != nil {
		t.Fatalf("error verifying client signature on token [%s]: %v", clientAssertion, err)
	}

	if tok.Subject() != clientID {
		t.Fatalf("incorrect subject: %s", tok.Subject())
	}

	if tok.Issuer() != clientID {
		t.Fatalf("incorrect issuer: %s", tok.Issuer())
	}

	expectedAudience := tokenEndpoint()
	if len(tok.Audience()) != 1 || tok.Audience()[0] != expectedAudience {
		t.Fatalf("incorrect audience: %v", tok.Audience())
	}
}

func validateBasicAuth(r *http.Request, t *testing.T) {
	if grant := r.Form.Get("grant_type"); grant != "client_credentials" {
		t.Logf("got the wrong grant type: %s, expected client_credentials", grant)
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		t.Errorf("missing basic auth")
	}
	if username != "theclient" || password != "thesecret" {
		t.Errorf("failed to pass correct username and password. got %s:%s", username, password)
	}
}

func extractDPoPToken(r *http.Request, t *testing.T) jwt.Token {
	dpop := r.Header.Get("dpop")
	jwsMessage, err := jws.ParseString(dpop)
	if err != nil {
		t.Errorf("error parsing dpop payload as JWS: %v", err)
	}

	sig := jwsMessage.Signatures()[0]
	signingKey := sig.ProtectedHeaders().JWK()

	clientTok, err := jwt.ParseString(dpop, jwt.WithVerify(true), jwt.WithKey(signingKey.Algorithm(), signingKey))
	if err != nil {
		t.Errorf("failed to parse/verify the dpop token: %v", err)
	}

	return clientTok
}

func setupKeycloak(ctx context.Context, t *testing.T) (tc.Container, string, string) {
	containerReq := tc.ContainerRequest{
		Image:        "ghcr.io/opentdf/keycloak:sha-8a6d35a",
		ExposedPorts: []string{"8082/tcp", "8083/tcp"},
		Cmd: []string{"start-dev", "--http-port=8082", "--https-port=8083", "--features=preview", "--verbose",
			"-Djavax.net.ssl.trustStorePassword=password", "-Djavax.net.ssl.HostnameVerifier=AllowAll",
			"-Djavax.net.debug=ssl",
			"-Djavax.net.ssl.trustStore=/truststore/truststore.p12",
			"--spi-truststore-file-hostname-verification-policy=ANY",
		},
		Files: []tc.ContainerFile{
			{HostFilePath: "testdata/ca.p12", ContainerFilePath: "/truststore/truststore.p12", FileMode: int64(0o777)},
			{HostFilePath: "testdata/localhost.crt", ContainerFilePath: "/etc/x509/tls/localhost.crt", FileMode: int64(0o777)},
			{HostFilePath: "testdata/localhost.key", ContainerFilePath: "/etc/x509/tls/localhost.key", FileMode: int64(0o777)},
		},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":                "admin",
			"KEYCLOAK_ADMIN_PASSWORD":       "admin",
			"KC_HTTPS_KEY_STORE_PASSWORD":   "password",
			"KC_HTTPS_KEY_STORE_FILE":       "/truststore/truststore.p12",
			"KC_HTTPS_CERTIFICATE_FILE":     "/etc/x509/tls/localhost.crt",
			"KC_HTTPS_CERTIFICATE_KEY_FILE": "/etc/x509/tls/localhost.key",
			"KC_HTTPS_CLIENT_AUTH":          "request",
		},

		WaitingFor: wait.ForLog("Running the server"),
	}

	var providerType tc.ProviderType

	if os.Getenv("TESTCONTAINERS_PODMAN") == "true" {
		providerType = tc.ProviderPodman
	} else {
		providerType = tc.ProviderDocker
	}

	keycloak, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ProviderType:     providerType,
		ContainerRequest: containerReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("error starting keycloak container: %v", err)
	}
	port, _ := keycloak.MappedPort(ctx, "8082")
	keycloakBase := fmt.Sprintf("http://localhost:%s", port.Port())

	httpPort, _ := keycloak.MappedPort(ctx, "8083")
	keycloakHTTPSBase := fmt.Sprintf("https://localhost:%s", httpPort.Port())

	realm := "test"

	connectParams := fixtures.KeycloakConnectParams{
		BasePath:         keycloakBase,
		Username:         "admin",
		Password:         "admin",
		Realm:            realm,
		Audience:         "https://test.example.org",
		AllowInsecureTLS: true,
	}

	err = fixtures.SetupKeycloak(ctx, connectParams)
	require.NoError(t, err)

	return keycloak, keycloakBase + "/realms/" + realm + "/protocol/openid-connect/token", keycloakHTTPSBase + "/realms/" + realm + "/protocol/openid-connect/token"
}
