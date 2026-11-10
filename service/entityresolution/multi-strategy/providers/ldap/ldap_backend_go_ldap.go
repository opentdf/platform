package ldap

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	golangldap "github.com/go-ldap/ldap/v3"
)

type goLDAPBackend struct{}

func NewGoLDAPBackend() Backend {
	return goLDAPBackend{}
}

func (goLDAPBackend) Dial(network, addr string) (Conn, error) {
	conn, err := dialLDAPURL("ldap", network, addr)
	if err != nil {
		return nil, err
	}
	return &goLDAPConn{conn: conn}, nil
}

func (goLDAPBackend) DialTLS(network, addr string, config *tls.Config) (Conn, error) {
	opts := []golangldap.DialOpt{}
	if config != nil {
		opts = append(opts, golangldap.DialWithTLSConfig(config))
	}

	conn, err := dialLDAPURL("ldaps", network, addr, opts...)
	if err != nil {
		return nil, err
	}
	return &goLDAPConn{conn: conn}, nil
}

func dialLDAPURL(scheme, network, addr string, opts ...golangldap.DialOpt) (*golangldap.Conn, error) {
	target, err := dialTargetURL(scheme, network, addr)
	if err != nil {
		return nil, err
	}

	conn, err := golangldap.DialURL(target, opts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func dialTargetURL(scheme, network, addr string) (string, error) {
	if network != "tcp" {
		return "", fmt.Errorf("unsupported LDAP network %q", network)
	}

	return (&url.URL{
		Scheme: scheme,
		Host:   addr,
	}).String(), nil
}

func (goLDAPBackend) EscapeFilter(filter string) string {
	return golangldap.EscapeFilter(filter)
}

type goLDAPConn struct {
	conn *golangldap.Conn
}

func (c *goLDAPConn) SetTimeout(timeout time.Duration) {
	c.conn.SetTimeout(timeout)
}

func (c *goLDAPConn) Bind(username, password string) error {
	return c.conn.Bind(username, password)
}

func (c *goLDAPConn) Search(request SearchRequest) (*SearchResult, error) {
	ldapReq := golangldap.NewSearchRequest(
		request.BaseDN,
		request.Scope,
		request.DerefAliases,
		request.SizeLimit,
		request.TimeLimit,
		request.TypesOnly,
		request.Filter,
		request.Attributes,
		nil,
	)

	res, err := c.conn.Search(ldapReq)
	if err != nil {
		return nil, err
	}

	return convertSearchResult(res), nil
}

func (c *goLDAPConn) Close() error {
	return c.conn.Close()
}

func convertSearchResult(res *golangldap.SearchResult) *SearchResult {
	if res == nil {
		return &SearchResult{}
	}

	out := &SearchResult{Entries: make([]*Entry, 0, len(res.Entries))}
	for _, entry := range res.Entries {
		outEntry := &Entry{
			DN: entry.DN,
		}
		if len(entry.Attributes) > 0 {
			outEntry.Attributes = make([]*Attribute, 0, len(entry.Attributes))
			for _, attr := range entry.Attributes {
				values := append([]string(nil), attr.Values...)
				outEntry.Attributes = append(outEntry.Attributes, &Attribute{
					Name:   attr.Name,
					Values: values,
				})
			}
		}
		out.Entries = append(out.Entries, outEntry)
	}

	return out
}
