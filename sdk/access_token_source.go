package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/opentdf-v2-poc/internal/oauth"
	"github.com/opentdf/opentdf-v2-poc/sdk/internal/crypto"
	"golang.org/x/oauth2"
)

type AccessToken string

type AccessTokenSource interface {
	GetAccessToken() (AccessToken, error)
	// probably better to use `crypto.AsymDecryption` here than roll our own since this should be
	// more closely linked to what happens in KAS in terms of crypto params
	GetAsymDecryption() crypto.AsymDecryption
	GetDPoPKey() jwk.Key
	GetDPoPPublicKeyPEM() string
	RefreshAccessToken() error
}

type FixedAccessTokenSource struct {
	token          AccessToken
	dpopKey        jwk.Key
	dpopPEM        string
	asymDecryption crypto.AsymDecryption
}

func (ts FixedAccessTokenSource) GetAccessToken() (AccessToken, error) {
	return ts.token, nil
}

func (ts FixedAccessTokenSource) GetAsymDecryption() crypto.AsymDecryption {
	return ts.asymDecryption
}

func (ts FixedAccessTokenSource) GetDPoPKey() jwk.Key {
	return ts.dpopKey
}

func (ts FixedAccessTokenSource) GetDPoPPublicKeyPEM() string {
	return ts.dpopPEM
}

func (ts FixedAccessTokenSource) RefreshAccessToken() error {
	return errors.New("can't refresh a fixed access token")
}

func getNewDPoPKey() (string, jwk.Key, *crypto.AsymDecryption, error) {
	dpopPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating DPoP keypair: %w", err)
	}
	dpopKey, err := jwk.FromRaw(dpopPrivate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error creating JWK: %w", err)
	}
	dpopKey.Set("alg", jwa.RS256)

	dpopKeyDER, err := x509.MarshalPKCS8PrivateKey(dpopPrivate)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error marshalling private key: %w", err)
	}

	var dpopPrivatePEM strings.Builder

	pem.Encode(&dpopPrivatePEM, &pem.Block{
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

func NewFixedAccessTokenSource(accessToken string) (FixedAccessTokenSource, error) {
	dpopPublicKeyPEM, dpopKey, asymDecryption, err := getNewDPoPKey()
	if err != nil {
		return FixedAccessTokenSource{}, err
	}

	ts := FixedAccessTokenSource{
		token:          AccessToken(accessToken),
		dpopKey:        dpopKey,
		asymDecryption: *asymDecryption,
		dpopPEM:        dpopPublicKeyPEM,
	}

	return ts, nil
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
}

func NewIDPAccessTokenSource(credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string) (IDPAccessTokenSource, error) {
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
	}

	return creds, nil
}

// use a pointer receiver so that the token state is shared
func (creds *IDPAccessTokenSource) GetAccessToken() (AccessToken, error) {
	// TODO: make this thread-safe
	if creds.token == nil {
		err := creds.RefreshAccessToken()
		if err != nil {
			return AccessToken(""), err
		}
	}

	return AccessToken(creds.token.AccessToken), nil
}

func (creds *IDPAccessTokenSource) GetAsymDecryption() crypto.AsymDecryption {
	return creds.asymDecryption
}

func (creds *IDPAccessTokenSource) RefreshAccessToken() error {
	tok, err := oauth.GetAccessToken(creds.idpTokenEndpoint.String(), creds.scopes, creds.credentials, creds.dpopKey)
	if err != nil {
		return fmt.Errorf("error getting access token: %v", err)
	}
	creds.token = tok

	return nil
}

func (creds *IDPAccessTokenSource) GetDPoPKey() jwk.Key {
	return creds.dpopKey
}

func (creds *IDPAccessTokenSource) GetDPoPPublicKeyPEM() string {
	return creds.dpopPEM
}
