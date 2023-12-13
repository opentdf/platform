package keycloak

import (
	"context"
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v4"
	"github.com/opentdf/opentdf-v2-poc/internal/credentials"
)

type Config struct {
	Host             string                 `yaml:"host"`
	Realm            string                 `yaml:"realm"`
	ClientID         string                 `yaml:"clientId"`
	ClientSecret     credentials.Credential `yaml:"clientSecret"`
	AttributeFilters AttributeFilters       `yaml:"attributeFilters"`
}

type AttributeFilters struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type Client struct {
	Config
	*gocloak.GoCloak
}

func NewKeycloak(c Config) (*Client, error) {
	client := gocloak.NewClient(c.Host)
	fmt.Println(c)
	return &Client{
		Config:  c,
		GoCloak: client,
	}, nil
}

func (k Client) GetAttributes(id string) (map[string]string, error) {
	var (
		attributes = make(map[string]string)
	)

	token, err := k.LoginClientSignedJWT(context.Background(), k.ClientID, k.Realm, []byte(k.ClientSecret.Get()), jwt.SigningMethodHS256, jwt.NewNumericDate(time.Now()))
	if err != nil {
		return nil, err
	}
	fmt.Println(id)
	user, err := k.GetUserByID(context.Background(), token.AccessToken, k.Realm, id)
	if err != nil {
		return nil, err
	}

	// Why does keycloak like to treat everything as [] :(
	for k, v := range *user.Attributes {
		if len(v) == 1 {
			attributes[k] = v[0]
		}
	}
	return attributes, nil
}

func (k Client) GetType() string {
	return "keycloak"
}
