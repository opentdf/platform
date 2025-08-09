package ldap

// LDAP stubs for building without the actual LDAP library
// In production, remove this file and import "github.com/go-ldap/ldap/v3"

import (
	"crypto/tls"
	"errors"
)

// LDAP constants (stubs)
const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
	NeverDerefAliases = 0
)

// LDAP types (stubs)
type Conn struct{}
type SearchRequest struct{}
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

// LDAP functions (stubs)
func Dial(network, addr string) (*Conn, error) {
	return nil, errors.New("LDAP not implemented - stub function")
}

func DialTLS(network, addr string, config *tls.Config) (*Conn, error) {
	return nil, errors.New("LDAP not implemented - stub function")
}

func NewSearchRequest(_ string, _, _, _, _ int, _ bool, _ string, _ []string, _ []interface{}) *SearchRequest {
	return &SearchRequest{}
}

func EscapeFilter(filter string) string {
	return filter
}

func (c *Conn) SetTimeout(_ interface{}) {}
func (c *Conn) Bind(_, _ string) error {
	return errors.New("LDAP not implemented - stub function")
}
func (c *Conn) Search(_ *SearchRequest) (*SearchResult, error) {
	return &SearchResult{Entries: []*Entry{}}, errors.New("LDAP not implemented - stub function")
}
func (c *Conn) Close() error {
	return nil
}
