package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
	"github.com/opentdf/opentdf-v2-poc/internal/oauth"
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

/*
Credentials that allow us to connect to an IDP and obtain an access token that is bound
to a DPOP key
*/
type IDPCredentials struct {
	credentials      oauth.ClientCredentials
	idpTokenEndpoint url.URL
	token            *oauth2.Token
	scopes           []string
	dpopKey          jwk.Key
	asymDecryption   crypto.AsymDecryption
	dpopPEM          string
}

func NewAccessTokenSource(credentials oauth.ClientCredentials, idpTokenEndpoint string, scopes []string) (IDPCredentials, error) {
	endpoint, err := url.Parse(idpTokenEndpoint)
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("invalid url [%s]: %w", idpTokenEndpoint, err)
	}

	dpopPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error creating DPoP keypair: %w", err)
	}
	dpopKey, err := jwk.FromRaw(dpopPrivate)
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error creating JWK: %w", err)
	}
	dpopKey.Set("alg", jwa.RS256)

	dpopKeyDER, err := x509.MarshalPKCS8PrivateKey(dpopPrivate)
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error marshalling private key: %w", err)
	}

	var dpopPrivatePEM strings.Builder

	pem.Encode(&dpopPrivatePEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: dpopKeyDER,
	})
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error encoding private key to PEM")
	}

	dpopPublic := dpopPrivate.Public()
	dpopPublicDER, err := x509.MarshalPKIXPublicKey(dpopPublic)
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error marshalling public key: %w", err)
	}

	var dpopPublicKeyPEM strings.Builder
	err = pem.Encode(&dpopPublicKeyPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: dpopPublicDER,
	})
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error encoding public key to PEM")
	}

	asymDecryption, err := crypto.NewAsymDecryption(dpopPrivatePEM.String())
	if err != nil {
		return IDPCredentials{}, fmt.Errorf("error creating asymmetric decryptor: %w", err)
	}

	creds := IDPCredentials{
		credentials:      credentials,
		idpTokenEndpoint: *endpoint,
		token:            nil,
		scopes:           scopes,
		asymDecryption:   asymDecryption,
		dpopKey:          dpopKey,
		dpopPEM:          dpopPublicKeyPEM.String(),
	}

	return creds, nil
}

// use a pointer receiver so that the token state is shared
func (creds *IDPCredentials) GetAccessToken() (AccessToken, error) {
	// TODO: make this thread-safe
	if creds.token == nil {
		err := creds.RefreshAccessToken()
		if err != nil {
			return AccessToken(""), err
		}
	}

	return AccessToken(creds.token.AccessToken), nil
}

func (creds *IDPCredentials) GetAsymDecryption() crypto.AsymDecryption {
	return creds.asymDecryption
}

func (creds *IDPCredentials) RefreshAccessToken() error {
	tok, err := oauth.GetAccessToken(creds.idpTokenEndpoint.String(), creds.scopes, creds.credentials, creds.dpopKey)
	if err != nil {
		return fmt.Errorf("error getting access token: %v", err)
	}
	creds.token = tok

	return nil
}

func (creds *IDPCredentials) GetDPoPKey() jwk.Key {
	return creds.dpopKey
}

func (creds *IDPCredentials) GetDPoPPublicKeyPEM() string {
	return creds.dpopPEM
}
