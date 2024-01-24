package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/opentdf-v2-poc/internal/oauth"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupKeycloak(t *testing.T, claimsProviderUrl *url.URL, ctx context.Context) (tc.Container, string) {
	containerReq := tc.ContainerRequest{
		Image:        "ghcr.io/opentdf/keycloak:sha-ce2f709",
		ExposedPorts: []string{"8082/tcp"},
		Cmd:          []string{"start-dev --http-port=8082"},
		Files:        []tc.ContainerFile{},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForLog("Running the server"),
	}
	keycloak, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: containerReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("error starting keycloak container: %v", err)
	}
	_, _ = keycloak.ContainerIP(ctx)
	port, _ := keycloak.MappedPort(ctx, "8082")
	keycloakBase := fmt.Sprintf("http://localhost:%s", port.Port())

	client := http.Client{}

	formData := url.Values{}
	formData.Add("username", "admin")
	formData.Add("password", "admin")
	formData.Add("grant_type", "password")
	formData.Add("client_id", "admin-cli")

	req, _ := http.NewRequest("POST", keycloakBase+"/realms/master/protocol/openid-connect/token", strings.NewReader(formData.Encode()))
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	var responseMap map[string]interface{}
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&responseMap)
	if err != nil {
		t.Fatalf("error decoding response: %v", err)
	}
	accessToken := responseMap["access_token"].(string)

	realmFile, err := os.ReadFile("./realm.json")
	if err != nil {
		panic(err)
	}

	realmJson := strings.Replace(string(realmFile), "<claimsprovider url>", claimsProviderUrl.String(), -1)

	req, _ = http.NewRequest("POST", keycloakBase+"/admin/realms", strings.NewReader(realmJson))
	req.Header.Add("authorization", "Bearer "+accessToken)
	req.Header.Add("content-type", "application/json")

	res, err = client.Do(req)
	if err != nil {
		panic(err)
	}

	if res.StatusCode != 201 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("error creating realm: %s", string(body))
	}

	req, _ = http.NewRequest("GET", keycloakBase+"/admin/realms/test/clients/14228007-9004-4ff8-a239-d7117f54e452/client-secret", nil)
	req.Header.Add("authorization", "Bearer "+accessToken)
	res, err = client.Do(req)
	body, _ := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("error setting test credentials: %s", string(body))
	}

	return keycloak, keycloakBase + "/realms/test/protocol/openid-connect/token"
}

func setupWiremock(t *testing.T, ctx context.Context) (tc.Container, *url.URL) {
	listenPort, _ := nat.NewPort("tcp", "8181")
	req := tc.ContainerRequest{
		Image:      "wiremock/wiremock:3.3.1",
		Cmd:        []string{fmt.Sprintf("--port=%s", listenPort.Port())},
		WaitingFor: wait.ForLog("extensions:"),
		Files: []tc.ContainerFile{
			{
				HostFilePath:      "./claims.json",
				ContainerFilePath: "/home/wiremock/mappings/claims.json",
				FileMode:          0o444,
			},
		},
	}
	wiremock, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}
	containerIP, err := wiremock.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("error getting endpoint from keycloak: %v", err)
	}

	wiremockUrl, err := url.Parse(fmt.Sprintf("http://%s:8181/claims", containerIP))
	if err != nil {
		panic(err)
	}
	return wiremock, wiremockUrl
}

func TestGettingAccessTokenFromKeycloak(t *testing.T) {
	ctx := context.Background()

	wiremock, wiremockUrl := setupWiremock(t, ctx)
	defer wiremock.Terminate(ctx)

	keycloak, idpEndpoint := setupKeycloak(t, wiremockUrl, ctx)
	defer keycloak.Terminate(ctx)

	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	dpopJWK, _ := jwk.FromRaw(dpopKey)
	dpopJWK.Set("use", "sig")
	dpopJWK.Set("alg", jwa.RS256.String())

	clientCredentials := oauth.ClientCredentials{
		ClientId:   "testclient",
		ClientAuth: "abcd1234",
	}

	tok, err := oauth.GetAccessToken(
		idpEndpoint,
		[]string{"testscope"},
		clientCredentials,
		dpopJWK)

	if err != nil {
		t.Fatalf("error: %v", err)
	}
	tokenDetails, err := jwt.ParseString(tok.AccessToken, jwt.WithVerify(false))
	if err != nil {
		t.Errorf("error parsing token received from IDP: %v", err)
	}

	// if this is our custom implementation from keycloak then we know what the
	//    structure is and can verify that we are getting back something that has
	//    our public key embedded in a particular way
	if claims, ok := tokenDetails.Get("tdf_claims"); ok {
		claimsMap := claims.(map[string]interface{})
		tokenDpopKey := claimsMap["client_public_signing_key"].(string)
		if tokenDpopKey == "" {
			t.Fatalf("no client_public_signing key in claims: %v", claimsMap)
		} else {
			keyDER, _ := pem.Decode([]byte(tokenDpopKey))
			if keyDER == nil {
				t.Fatalf("error parsing key from IDP token")
			} else {
				tokenPublicKey, err := x509.ParsePKIXPublicKey(keyDER.Bytes)
				if err != nil {
					t.Fatalf("error parsing public key from DER: %v", err)
				} else {
					pubkey := tokenPublicKey.(*rsa.PublicKey)
					if pubkey.E != dpopKey.E || pubkey.N.String() != dpopKey.N.String() {
						t.Fatalf("didn't get back the same key in the dpop header: (%d, %d) != (%d, %d)", pubkey.E, pubkey.N, dpopKey.E, dpopKey.N)
					}
				}
			}
		}
	} else if strings.EqualFold(tok.Type(), "DPoP") {
		// if not, just make sure that they gave us a token that has the right type
		t.Fatalf("got the wrong kind of access token: %s: %v", tok.Type(), tok)
	}
}

func TestClientSecretNoNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}

	dpopJWK, _ := jwk.FromRaw(dpopKey)
	dpopJWK.Set("use", "sig")
	dpopJWK.Set("alg", jwa.RS256.String())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Errorf("Expected to request '/token', got: %s", r.URL.Path)
		}
		r.ParseForm()

		validateBasicAuth(r, t)
		extractDpopToken(r, t)

		tok, _ := jwt.NewBuilder().
			Issuer("example.org/fake").
			IssuedAt(time.Now()).
			Build()

		responseBytes, err := json.Marshal(tok)
		if err != nil {
			t.Errorf("error writing response: %v", err)
		}

		w.Header().Add("content-type", "application/json")
		w.Write(responseBytes)

	}))
	defer server.Close()

	clientCredentials := oauth.ClientCredentials{
		ClientId:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err = oauth.GetAccessToken(server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	if err != nil {
		t.Errorf("didn't get a token back from the IdP: %v", err)
	}
}

func TestClientSecretWithNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}

	dpopJWK, _ := jwk.FromRaw(dpopKey)
	dpopJWK.Set("use", "sig")
	dpopJWK.Set("alg", jwa.RS256.String())

	timesCalled := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled += 1
		if r.URL.Path != "/token" {
			t.Errorf("Expected to request '/token', got: %s", r.URL.Path)
		}
		r.ParseForm()

		validateBasicAuth(r, t)

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(400)
			if _, err := w.Write([]byte{}); err != nil {
				t.Errorf("error writing response: %v", err)
			}
			return
		} else if timesCalled > 2 {
			t.Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDpopToken(r, t)

		if nonce, ok := clientTok.Get("nonce"); ok {
			if nonce.(string) != "dfdffdfddf" {
				t.Errorf("Got incorrect nonce: %v", nonce)
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
		w.Write(responseBytes)

	}))
	defer server.Close()

	clientCredentials := oauth.ClientCredentials{
		ClientId:   "theclient",
		ClientAuth: "thesecret",
	}
	_, err = oauth.GetAccessToken(server.URL+"/token", []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
	if err != nil {
		t.Errorf("didn't get a token back from the IdP: %v", err)
	}
}

func TestSignedJWTWithNonce(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}
	dpopJWK, _ := jwk.FromRaw(dpopKey)
	dpopJWK.Set("use", "sig")
	dpopJWK.Set("alg", jwa.RS256.String())

	clientAuthKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("error generating dpop key: %v", err)
	}
	clientAuthJWK, _ := jwk.FromRaw(clientAuthKey)
	clientAuthJWK.Set("use", "sig")
	clientAuthJWK.Set("alg", jwa.RS256.String())
	clientPublicKey, err := clientAuthJWK.PublicKey()
	if err != nil {
		t.Fatalf("error getting public JWK from client auth JWK: %v", err)
	}

	timesCalled := 0

	var url string
	getUrl := func() string {
		return url
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timesCalled += 1

		if r.URL.Path != "/token" {
			t.Errorf("Expected to request '/token', got: %s", r.URL.Path)
		}
		r.ParseForm()

		validateClientAssertionAuth(r, t, getUrl, "theclient", clientPublicKey)

		if timesCalled == 1 {
			w.Header().Add("DPoP-Nonce", "dfdffdfddf")
			w.WriteHeader(400)
			if _, err := w.Write([]byte{}); err != nil {
				t.Errorf("error writing response: %v", err)
			}
			return
		} else if timesCalled > 2 {
			t.Logf("made more than two calls to the server: %d", timesCalled)
			return
		}

		// get the key we used to sign the DPoP token from the header
		clientTok := extractDpopToken(r, t)

		if nonce, ok := clientTok.Get("nonce"); ok {
			if nonce.(string) != "dfdffdfddf" {
				t.Errorf("Got incorrect nonce: %v", nonce)
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
		w.Write(responseBytes)

	}))
	defer server.Close()

	clientCredentials := oauth.ClientCredentials{
		ClientId:   "theclient",
		ClientAuth: clientAuthJWK,
	}

	url = server.URL + "/token"

	_, err = oauth.GetAccessToken(url, []string{"scope1", "scope2"}, clientCredentials, dpopJWK)
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
func validateClientAssertionAuth(r *http.Request, t *testing.T, tokenEndpoint func() string, clientId string, key jwk.Key) {
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

	if tok.Subject() != clientId {
		t.Fatalf("incorrect subject: %s", tok.Subject())
	}

	if tok.Issuer() != clientId {
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

func extractDpopToken(r *http.Request, t *testing.T) jwt.Token {
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
