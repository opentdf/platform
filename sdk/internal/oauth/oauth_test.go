package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestGettingAccessTokenFromKeycloak(t *testing.T) {
	ctx := context.Background()

	keycloak, idpEndpoint := setupKeycloak(ctx, t)
	defer func() {
		require.NoError(t, keycloak.Terminate(ctx))
	}()

	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	dpopJWK, err := jwk.FromRaw(dpopKey)
	require.NoError(t, err)
	require.NoError(t, dpopJWK.Set("use", "sig"))
	require.NoError(t, dpopJWK.Set("alg", jwa.RS256.String()))

	clientCredentials := ClientCredentials{
		ClientID:   "opentdf-sdk",
		ClientAuth: "secret",
	}

	tok, err := GetAccessToken(
		idpEndpoint,
		[]string{"testscope"},
		clientCredentials,
		dpopJWK)
	require.NoError(t, err)

	tokenDetails, err := jwt.ParseString(tok.AccessToken, jwt.WithVerify(false))
	require.NoError(t, err)

	cnfClaim, ok := tokenDetails.Get("cnf")
	require.True(t, ok)
	cnfClaimsMap, ok := cnfClaim.(map[string]interface{})
	require.True(t, ok)
	idpKeyFingerprint, ok := cnfClaimsMap["jkt"].(string)
	require.True(t, ok)
	require.NotEmpty(t, idpKeyFingerprint)
	pk, err := dpopJWK.PublicKey()
	require.NoError(t, err)
	hash, err := pk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	scope, ok := tokenDetails.Get("scope")
	require.True(t, ok)
	scopeString, ok := scope.(string)
	require.True(t, ok)
	require.True(t, strings.Contains(scopeString, "testscope"))

	expectedThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)
	assert.Equal(t, expectedThumbprint, idpKeyFingerprint, "didn't get expected fingerprint")
	assert.Greaterf(t, tok.ExpiresIn, int64(0), "invalid expiration is before current time: %v", tok)
	assert.Falsef(t, tok.Expired(), "got a token that is currently expired: %v", tok)
}

func TestDoingTokenExchangeWithKeycloak(t *testing.T) {
	ctx := context.Background()

	keycloak, idpEndpoint := setupKeycloak(ctx, t)
	defer func() { require.NoError(t, keycloak.Terminate(ctx)) }()

	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	dpopJWK, err := jwk.FromRaw(dpopKey)
	require.NoError(t, err)
	require.NoError(t, dpopJWK.Set("use", "sig"))
	require.NoError(t, dpopJWK.Set("alg", jwa.RS256.String()))

	clientCredentials := ClientCredentials{
		ClientID:   "opentdf-sdk",
		ClientAuth: "secret",
	}

	subjectToken, err := GetAccessToken(
		idpEndpoint,
		[]string{},
		clientCredentials,
		dpopJWK)
	require.NoError(t, err)

	exchangeCredentials := ClientCredentials{
		ClientID:   "opentdf",
		ClientAuth: "secret",
	}

	tokenExchange := TokenExchangeInfo{
		SubjectToken: subjectToken.AccessToken,
		Audience:     "opentdf-sdk",
	}

	exchangedTok, err := DoTokenExchange(ctx, idpEndpoint, []string{}, exchangeCredentials, tokenExchange, dpopJWK)
	require.NoError(t, err)

	tokenDetails, err := jwt.ParseString(exchangedTok.AccessToken, jwt.WithVerify(false))
	require.NoError(t, err)

	cnfClaim, ok := tokenDetails.Get("cnf")
	require.True(t, ok)
	cnfClaimsMap, ok := cnfClaim.(map[string]interface{})
	require.True(t, ok)
	idpKeyFingerprint, ok := cnfClaimsMap["jkt"].(string)
	require.True(t, ok)
	require.NotEmpty(t, idpKeyFingerprint)
	pk, err := dpopJWK.PublicKey()
	require.NoError(t, err)
	hash, err := pk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	expectedThumbprint := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)
	assert.Equal(t, expectedThumbprint, idpKeyFingerprint, "didn't get expected fingerprint")
	assert.Greaterf(t, subjectToken.ExpiresIn, int64(0), "invalid expiration is before current time: %v", subjectToken)
	assert.Falsef(t, subjectToken.Expired(), "got a token that is currently expired: %v", subjectToken)

	// verify that we got a token that has the opentdf-readonly role, which only the sdk client has
	ra, ok := tokenDetails.Get("realm_access")
	require.True(t, ok)
	raMap, ok := ra.(map[string]interface{})
	require.True(t, ok)
	roles, ok := raMap["roles"]
	require.True(t, ok)
	rolesList, ok := roles.([]interface{})
	require.True(t, ok)
	require.True(t, slices.Contains(rolesList, "opentdf-readonly"), "missing the `opentdf-readonly` role")

	// verify that the calling client is the authorized party
	azpClaim, ok := tokenDetails.Get("azp")
	require.True(t, ok)
	require.Equal(t, exchangeCredentials.ClientID, azpClaim)

	// verify that the exchanged token has a scope that is only allowed for the client that got the original token
	scope, ok := tokenDetails.Get("scope")
	require.True(t, ok)
	scopeString, ok := scope.(string)
	require.True(t, ok)
	require.True(t, strings.Contains(scopeString, "testscope"))
}

func TestClientSecretNoNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}

	dpopJWK, err := jwk.FromRaw(dpopKey)
	require.NoError(t, err)
	require.NoError(t, dpopJWK.Set("use", "sig"))
	require.NoError(t, dpopJWK.Set("alg", jwa.RS256.String()))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/token", r.URL.Path)
		require.NoError(t, r.ParseForm())

		validateBasicAuth(r, t)
		extractDPoPToken(r, t)

		tok, err := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()
		require.NoError(t, err)

		responseBytes, err := json.Marshal(tok)
		require.NoError(t, err, "error writing response")

		w.Header().Add("content-type", "application/json")
		_, err = w.Write(responseBytes)
		require.NoError(t, err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err = GetAccessToken(server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	require.NoError(t, err, "didn't get a token back from the IdP")
}

func TestClientSecretWithNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}

	dpopJWK, err := jwk.FromRaw(dpopKey)
	require.NoError(t, err)
	require.NoError(t, dpopJWK.Set("use", "sig"))
	require.NoError(t, dpopJWK.Set("alg", jwa.RS256.String()))

	timesCalled := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled++
		assert.Equal(t, "/token", r.URL.Path, "surprise http request to mock oauth service")
		err := r.ParseForm()
		require.NoError(t, err, "error parsing oauth request")

		validateBasicAuth(r, t)

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte{})
			require.NoError(t, err, "error writing response")
			return
		} else if timesCalled > 2 {
			t.Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDPoPToken(r, t)

		nonce, exists := clientTok.Get("nonce")
		if !exists {
			t.Logf("didn't get nonce assertion")
		}

		if nonceStr, ok := nonce.(string); ok {
			if nonceStr != "dfdffdfddf" {
				t.Errorf("Got incorrect nonce: %v", nonce)
			}
		} else {
			t.Errorf("Nonce is not a string")
		}

		tok, _ := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()

		responseBytes, err := json.Marshal(tok)
		if err != nil {
			t.Errorf("error writing response: %v", err)
		}

		w.Header().Add("content-type", "application/json")
		l, err := w.Write(responseBytes)
		assert.Equal(t, len(responseBytes), l)
		require.NoError(t, err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err = GetAccessToken(server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	if err != nil {
		t.Errorf("didn't get a token back from the IdP: %v", err)
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

func TestSignedJWTWithNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err, "error generating dpop key")
	dpopJWK, err := jwk.FromRaw(dpopKey)
	require.NoError(t, err)
	require.NoError(t, dpopJWK.Set("use", "sig"))
	require.NoError(t, dpopJWK.Set("alg", jwa.RS256.String()))

	clientAuthKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err, "error generating clientAuth key")
	clientAuthJWK, err := jwk.FromRaw(clientAuthKey)
	require.NoError(t, err, "error constructing raw JWK")
	require.NoError(t, clientAuthJWK.Set("use", "sig"))
	require.NoError(t, clientAuthJWK.Set("alg", jwa.RS256.String()))
	clientPublicKey, err := clientAuthJWK.PublicKey()
	require.NoError(t, err, "error getting public JWK from client auth JWK [%v]", clientAuthJWK)

	timesCalled := 0

	var url string
	getURL := func() string {
		return url
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled++

		if r.URL.Path != "/token" {
			t.Errorf("Expected to request '/token', got: %s", r.URL.Path)
		}
		require.NoError(t, r.ParseForm())

		validateClientAssertionAuth(r, t, getURL, "theclient", clientPublicKey)

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte{}); err != nil {
				t.Errorf("error writing response: %v", err)
			}
			return
		} else if timesCalled > 2 {
			t.Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDPoPToken(r, t)

		nonce, exists := clientTok.Get("nonce")
		if exists {
			value, ok := nonce.(string)
			if !ok {
				t.Errorf("Nonce is not a string")
			} else if value != "dfdffdfddf" {
				t.Errorf("Got incorrect nonce: %v", value)
			}
		} else {
			t.Logf("didn't get nonce assertion")
		}

		tok, _ := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()

		responseBytes, err := json.Marshal(tok)
		if err != nil {
			t.Errorf("error writing response: %v", err)
		}

		w.Header().Add("content-type", "application/json")
		l, err := w.Write(responseBytes)
		assert.Equal(t, len(responseBytes), l)
		require.NoError(t, err)
	}))
	defer server.Close()

	clientCredentials := ClientCredentials{
		ClientID:   "theclient",
		ClientAuth: clientAuthJWK,
	}

	url = server.URL + "/token"

	_, err = GetAccessToken(url, []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	if err != nil {
		t.Errorf("didn't get a token back from the IdP: %v", err)
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

func setupKeycloak(ctx context.Context, t *testing.T) (tc.Container, string) {
	containerReq := tc.ContainerRequest{
		Image:        "ghcr.io/opentdf/keycloak:sha-8a6d35a",
		ExposedPorts: []string{"8082/tcp"},
		Cmd:          []string{"start-dev", "--http-port=8082", "--features=preview"},
		Files:        []tc.ContainerFile{},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
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

	return keycloak, keycloakBase + "/realms/" + realm + "/protocol/openid-connect/token"
}
