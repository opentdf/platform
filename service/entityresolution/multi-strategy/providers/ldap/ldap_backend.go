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

type SearchRequest struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       string
	Attributes   []string
}

type Backend interface {
	Dial(network, addr string) (Conn, error)
	DialTLS(network, addr string, config *tls.Config) (Conn, error)
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
