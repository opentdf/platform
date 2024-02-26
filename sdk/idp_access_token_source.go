package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/sdk/internal/crypto"
	"github.com/opentdf/platform/sdk/internal/oauth"
	"golang.org/x/oauth2"
)

const (
	dpopKeySize = 2048
)

func getNewDPoPKey() (string, jwk.Key, *crypto.AsymDecryption, error) { //nolint:ireturn // this is only internal
	dpopPrivate, err := rsa.GenerateKey(rand.Reader, dpopKeySize)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating DPoP keypair: %w", err)
	}
	dpopKey, err := jwk.FromRaw(dpopPrivate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating JWK: %w", err)
	}
	err = dpopKey.Set("alg", jwa.RS256)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error setting the key algorithm: %w", err)
	}

	dpopKeyDER, err := x509.MarshalPKCS8PrivateKey(dpopPrivate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error marshalling private key: %w", err)
	}

	var dpopPrivatePEM strings.Builder

	err = pem.Encode(&dpopPrivatePEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: dpopKeyDER,
	})
	if err != nil {
		return "", nil, nil, fmt.Errorf("error encoding private key to PEM")
	}

	dpopPublic := dpopPrivate.Public()
	dpopPublicDER, err := x509.MarshalPKIXPublicKey(dpopPublic)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error marshalling public key: %w", err)
	}

	var dpopPublicKeyPEM strings.Builder
	err = pem.Encode(&dpopPublicKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: dpopPublicDER,
	})
	if err != nil {
		return "", nil, nil, fmt.Errorf("error encoding public key to PEM")
	}

	asymDecryption, err := crypto.NewAsymDecryption(dpopPrivatePEM.String())
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating asymmetric decryptor: %w", err)
	}

	return dpopPublicKeyPEM.String(), dpopKey, &asymDecryption, nil
}

/*
Credentials that allow us to connect to an IDP and obtain an access token that is bound
to a DPOP key
*/
type IDPAccessTokenSource struct {
	credentials      oauth.ClientCredentials
	idpTokenEndpoint url.URL
	token            *oauth2.Token
	scopes           []string
	dpopKey          jwk.Key
	asymDecryption   crypto.AsymDecryption
	dpopPEM          string
	tokenMutex       *sync.Mutex
}

func NewIDPAccessTokenSource(
	credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string) (IDPAccessTokenSource, error) {
	endpoint, err := url.Parse(idpTokenEndpoint)
	if err != nil {
		return IDPAccessTokenSource{}, fmt.Errorf("invalid url [%s]: %w", idpTokenEndpoint, err)
	}

	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey()
	if err != nil {
		return IDPAccessTokenSource{}, err
	}

	creds := IDPAccessTokenSource{
		credentials:      credentials,
		idpTokenEndpoint: *endpoint,
		token:            nil,
		scopes:           scopes,
		asymDecryption:   *asymDecryption,
		dpopKey:          dpopKey,
		dpopPEM:          dpopPublicKeyPEM,
		tokenMutex:       &sync.Mutex{},
	}

	return creds, nil
}

// use a pointer receiver so that the token state is shared
func (t *IDPAccessTokenSource) GetAccessToken() (AccessToken, error) {
	if t.token == nil {
		err := t.RefreshAccessToken()
		if err != nil {
			return AccessToken(""), err
		}
	}

	return AccessToken(t.token.AccessToken), nil
}

func (t *IDPAccessTokenSource) GetAsymDecryption() crypto.AsymDecryption {
	return t.asymDecryption
}

func (t *IDPAccessTokenSource) RefreshAccessToken() error {
	t.tokenMutex.Lock()
	defer t.tokenMutex.Unlock()

	tok, err := oauth.GetAccessToken(t.idpTokenEndpoint.String(), t.scopes, t.credentials, t.dpopKey)
	if err != nil {
		return fmt.Errorf("error getting access token: %w", err)
	}
	t.token = tok

	return nil
}

func (t *IDPAccessTokenSource) SignToken(tok jwt.Token) ([]byte, error) {
	signed, err := jwt.Sign(tok, jwt.WithKey(t.dpopKey.Algorithm(), t.dpopKey))
	if err != nil {
		return nil, fmt.Errorf("error signing DPOP token: %w", err)
	}

	return signed, nil
}

func (t *IDPAccessTokenSource) GetDPoPPublicKeyPEM() string {
	return t.dpopPEM
}
