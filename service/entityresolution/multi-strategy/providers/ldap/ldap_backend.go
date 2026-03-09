package ldap

import (
	"crypto/tls"
	"time"
)

type Conn interface {
	Bind(username, password string) error
	Search(request SearchRequest) (*SearchResult, error)
	Close() error
	SetTimeout(timeout time.Duration)
}

type SearchRequest interface{}

type Backend interface {
	Dial(network, addr string) (Conn, error)
	DialTLS(network, addr string, config *tls.Config) (Conn, error)
	NewSearchRequest(baseDN string, scope, derefAliases, sizeLimit, timeLimit int, typesOnly bool, filter string, attributes []string) SearchRequest
	EscapeFilter(filter string) string
}

type SearchResult struct {
	Entries []*Entry
}

type Entry struct {
	DN         string
	Attributes []*Attribute
}

type Attribute struct {
	Name   string
	Values []string
}
