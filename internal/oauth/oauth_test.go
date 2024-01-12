package oauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/opentdf-v2-poc/internal/oauth"
)

/*
*

	To run set these envvars:
	IDP_TOKEN_ENDPOINT: the url that provides DPoP
	IDP_SCOPES: the list of (space-separated scopes that the access token should provide)
	IDP_CLIENT_ID: the ID of the client
	One of:
	  * IDP_CLIENT_SECRET: the client secret, if using client secret credentials
		* IDP_PRIVATE_KEY: if using private_key_jwt authentication (we currently assume RS256)

//
*
*/
func TestGettingAccessToken(t *testing.T) {
	// Generate RSA Key to use for DPoP
	dpopKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	dpopJWK, _ := jwk.FromRaw(dpopKey)
	dpopJWK.Set("use", "sig")
	dpopJWK.Set("alg", jwa.RS256.String())

	var idpEndpoint = os.Getenv("IDP_TOKEN_ENDPOINT")
	if idpEndpoint == "" {
		t.Fatal("cannot run test if IDP_TOKEN_ENDPOINT is not specified")
	}

	idpScopes := os.Getenv("IDP_SCOPES")
	scopes := []string{}
	if idpScopes == "" {
		t.Log("No scopes for the access token specified")
	} else {
		scopes = strings.Split(idpScopes, " ")
	}

	var clientId = os.Getenv("IDP_CLIENT_ID")
	if clientId == "" {
		t.Fatal("cannot run test if IDP_CLIENT_ID not specified")
	}

	var clientCredentials oauth.ClientCredentials
	if pkBase64 := os.Getenv("IDP_PRIVATE_KEY"); pkBase64 != "" {
		pkPEM, err := base64.StdEncoding.DecodeString(pkBase64)
		if err != nil {
			t.Fatalf("error base64 decoding private PEM key: %v", err)
		}
		pkDER, _ := pem.Decode([]byte(pkPEM))
		if pkDER == nil {
			t.Fatalf("could not get private key from IDP_PRIVATE_KEY")
		}
		pk, err := x509.ParsePKCS8PrivateKey(pkDER.Bytes)
		if err != nil {
			t.Fatalf("error parsing IDP_PRIVATE_KEY PEM: %v", err)
		}

		privateJWK, err := jwk.FromRaw(pk)
		if err != nil {
			t.Fatalf("couldn't create private jwk from value in IDP_PRIVATE_KEY_JWT")
		}
		privateJWK.Set("alg", jwa.RS256.String())

		clientCredentials = oauth.ClientCredentials{
			ClientId:   clientId,
			ClientAuth: privateJWK,
		}
	} else if clientSecret := os.Getenv("IDP_CLIENT_SECRET"); clientSecret != "" {
		clientCredentials = oauth.ClientCredentials{
			ClientId:   clientId,
			ClientAuth: clientSecret,
		}
	} else {
		t.Fatalf("one of IDP_PRIVATE_KEY or IDP_CLIENT_SECRET must be specified")
	}

	tok, err := oauth.GetAccessToken(
		idpEndpoint,
		scopes,
		clientCredentials,
		dpopJWK)

	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if tok.Type() != "DPoP" {
		t.Fatalf("got the wrong kind of access token: %s", tok.Type())
	}
}

func TestGettingAccessTokenWithClientCredentials(t *testing.T) {
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

		if grant := r.Form.Get("grant_type"); grant != "client_credentials" {
			t.Errorf("got the wrong grant type: %s, expected client_credentials", grant)
		}

		dpop := r.Header.Get("dpop")
		jwsMessage, err := jws.ParseString(dpop)
		if err != nil {
			t.Errorf("error parsing dpop payload as JWS: %v", err)
		}

		// get the key we used to sign the DPoP token from the header
		sig := jwsMessage.Signatures()[0]
		signingKey := sig.ProtectedHeaders().JWK()

		_, err = jwt.ParseString(dpop, jwt.WithVerify(true), jwt.WithKey(signingKey.Algorithm(), signingKey))
		if err != nil {
			t.Errorf("failed to parse/verify the dpop token: %v", err)
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			t.Errorf("failed to pass correct authentication")
		}
		if username != "theclient" || password != "thesecret" {
			t.Errorf("failed to pass correct username and password. got %s:%s", username, password)
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
