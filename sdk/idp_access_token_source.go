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
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/crypto"
	"github.com/opentdf/platform/sdk/internal/oauth"
	"golang.org/x/oauth2"
)

const (
	dpopKeySize = 2048
)

func GenerateKeyPair() (string, string, jwk.Key, error) {
	rawPrivateKey, err := rsa.GenerateKey(rand.Reader, dpopKeySize)
	if err != nil {
		return "", "", nil, fmt.Errorf("error creating DPoP keypair: %w", err)
	}
	jwkPrivateKey, err := jwk.FromRaw(rawPrivateKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("error creating JWK: %w", err)
	}
	err = jwkPrivateKey.Set("alg", jwa.RS256)
	if err != nil {
		return "", "", nil, fmt.Errorf("error setting the key algorithm: %w", err)
	}

	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(rawPrivateKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("error marshalling private key: %w", err)
	}

	var privateKeyPem strings.Builder

	err = pem.Encode(&privateKeyPem, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derPrivateKey,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("error encoding private key to PEM")
	}

	rawPublicKey := rawPrivateKey.Public()
	derPublicKey, err := x509.MarshalPKIXPublicKey(rawPublicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("error marshalling public key: %w", err)
	}

	var publicKeyPem strings.Builder
	err = pem.Encode(&publicKeyPem, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPublicKey,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("error encoding public key to PEM")
	}

	return publicKeyPem.String(), privateKeyPem.String(), jwkPrivateKey, nil
}

/*
Credentials that allow us to connect to an IDP and obtain an access token that is bound
to a DPoP key
*/
type IDPAccessTokenSource struct {
	credentials            oauth.ClientCredentials
	idpTokenEndpoint       url.URL
	token                  *oauth2.Token
	scopes                 []string
	dpopKey                jwk.Key
	encryptionPublicKeyPEM string
	asymDecryption         crypto.AsymDecryption
	dpopPEM                string
	tokenMutex             *sync.Mutex
}

func NewIDPAccessTokenSource(
	credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string) (IDPAccessTokenSource, error) {
	endpoint, err := url.Parse(idpTokenEndpoint)

	if err != nil {
		return IDPAccessTokenSource{}, fmt.Errorf("invalid url [%s]: %w", idpTokenEndpoint, err)
	}

	dpopPublicKeyPem, _, dpopKey, err := GenerateKeyPair()
	if err != nil {
		return IDPAccessTokenSource{}, err
	}

	encryptionPublicKeyPem, encryptionPrivateKeyPem, _, err := GenerateKeyPair()
	if err != nil {
		return IDPAccessTokenSource{}, err
	}

	asymDecryption, err := crypto.NewAsymDecryption(encryptionPrivateKeyPem)
	if err != nil {
		return IDPAccessTokenSource{}, err
	}

	creds := IDPAccessTokenSource{
		credentials:            credentials,
		idpTokenEndpoint:       *endpoint,
		token:                  nil,
		scopes:                 scopes,
		asymDecryption:         asymDecryption,
		encryptionPublicKeyPEM: encryptionPublicKeyPem,
		dpopKey:                dpopKey,
		dpopPEM:                dpopPublicKeyPem,
		tokenMutex:             &sync.Mutex{},
	}

	return creds, nil
}

// use a pointer receiver so that the token state is shared
func (t *IDPAccessTokenSource) AccessToken() (auth.AccessToken, error) {
	if t.token == nil {
		err := t.RefreshAccessToken()
		if err != nil {
			return auth.AccessToken(""), err
		}
	}

	return auth.AccessToken(t.token.AccessToken), nil
}

func (t *IDPAccessTokenSource) DecryptWithDPoPKey(data []byte) ([]byte, error) {
	return t.asymDecryption.Decrypt(data)
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

func (t *IDPAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(t.dpopKey)
}

func (t *IDPAccessTokenSource) DPoPPublicKeyPEM() string {
	return t.dpopPEM
}

func (t *IDPAccessTokenSource) EncryptionPublicKeyPEM() string {
	return t.encryptionPublicKeyPEM
}
