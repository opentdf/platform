package ldap

import (
	"fmt"
	"slices"

	"github.com/go-ldap/ldap/v3"
	"github.com/opentdf/opentdf-v2-poc/internal/credentials"
)

type Config struct {
	BaseDN           string                 `yaml:"baseDN"`
	Host             string                 `yaml:"host"`
	Port             int                    `yaml:"port"`
	BindUsername     string                 `yaml:"bindUsername"`
	BindPassword     credentials.Credential `yaml:"bindPassword"`
	AttributeFilters AttributeFilters       `yaml:"attributeFilters"`
	// TODO: do we want to expose ldap search filter?
	// TODO: add support for ldaps
}

type AttributeFilters struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type Client struct {
	Config
	*ldap.Conn
}

func NewLDAP(c Config) (*Client, error) {
	var (
		client = new(Client)
		err    error
	)
	client.Config = c
	client.Conn, err = ldap.DialURL(c.buildURL())
	if err != nil {
		return nil, err
	}
	// Can we bind
	err = client.Bind(c.BindUsername, c.BindPassword.Get())
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c Config) buildURL() string {
	return fmt.Sprintf("ldap://%s:%d",
		c.Host,
		c.Port,
	)
}

func (l Client) GetAttributes(id string) (map[string]string, error) {
	var (
		attributes = make(map[string]string)
	)

	// TODO: add support for ldap search filter
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", id)
	searchReq := ldap.NewSearchRequest("dc=dev,dc=virtruqa,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{}, nil)
	res, err := l.Search(searchReq)
	if err != nil {
		return nil, err
	}

	for _, entry := range res.Entries {
		for _, attr := range entry.Attributes {
			if !slices.Contains(l.Config.AttributeFilters.Exclude, attr.Name) {
				attributes[attr.Name] = attr.Values[0]
			}
		}
	}
	return attributes, nil
}

func (l Client) GetType() string {
	return "ldap"
}
