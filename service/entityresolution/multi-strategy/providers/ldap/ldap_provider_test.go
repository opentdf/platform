package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/stretchr/testify/suite"
)

type ProviderSuite struct {
	suite.Suite
}

type mockBackend struct{}

type escapingBackend struct {
	mockBackend
}

func (mockBackend) Dial(_, _ string) (Conn, error) {
	return nil, errors.New("mock LDAP backend not configured")
}

func (mockBackend) DialTLS(_, _ string, _ *tls.Config) (Conn, error) {
	return nil, errors.New("mock LDAP backend not configured")
}

func (escapingBackend) EscapeFilter(filter string) string {
	return transformation.EscapeLDAPFilter(filter)
}

func (mockBackend) EscapeFilter(filter string) string {
	return filter
}

func TestProviderSuite(t *testing.T) {
	suite.Run(t, new(ProviderSuite))
}

func (s *ProviderSuite) TestBuildSearchFilter() {
	provider := &Provider{
		backend: escapingBackend{},
	}

	tests := []struct {
		name           string
		filterTemplate string
		params         map[string]interface{}
		expected       string
		expectError    bool
	}{
		{
			name:           "escapes raw parameter values once",
			filterTemplate: "(&(objectClass=person)(uid={username}))",
			params: map[string]interface{}{
				"username": "test(user)*",
			},
			expected: "(&(objectClass=person)(uid=test\\28user\\29\\2a))",
		},
		{
			name:           "formats non string parameters before escaping",
			filterTemplate: "(&(objectClass=person)(employeeNumber={employee_number}))",
			params: map[string]interface{}{
				"employee_number": 12345,
			},
			expected: "(&(objectClass=person)(employeeNumber=12345))",
		},
		{
			name:           "fails when placeholders remain",
			filterTemplate: "(&(objectClass=person)(uid={username})(mail={email}))",
			params: map[string]interface{}{
				"username": "testuser",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			filter, err := provider.buildSearchFilter(tt.filterTemplate, tt.params)

			if tt.expectError {
				s.Require().Error(err)
				return
			}

			s.Require().NoError(err)
			s.Equal(tt.expected, filter)
		})
	}
}

type recordingBackend struct {
	escapingBackend
	conn *recordingConn
}

func (b recordingBackend) Dial(_, _ string) (Conn, error) {
	return b.conn, nil
}

func (b recordingBackend) DialTLS(_, _ string, _ *tls.Config) (Conn, error) {
	return b.conn, nil
}

type recordingConn struct {
	request SearchRequest
	result  *SearchResult
}

func (c *recordingConn) Bind(_, _ string) error {
	return nil
}

func (c *recordingConn) Search(request SearchRequest) (*SearchResult, error) {
	c.request = request
	if c.result != nil {
		return c.result, nil
	}
	return &SearchResult{}, nil
}

func (c *recordingConn) Close() error {
	return nil
}

func (c *recordingConn) SetTimeout(time.Duration) {}

func (s *ProviderSuite) TestResolveEntityBuildsSearchRequest() {
	conn := &recordingConn{
		result: &SearchResult{
			Entries: []*Entry{
				{
					DN: "uid=alice,ou=users,dc=opentdf,dc=test",
					Attributes: []*Attribute{
						{Name: "uid", Values: []string{"alice"}},
						{Name: "mail", Values: []string{"alice@opentdf.test"}},
					},
				},
			},
		},
	}
	provider := &Provider{
		name: "ldap",
		config: Config{
			Host:           "localhost",
			Port:           389,
			RequestTimeout: 30 * time.Second,
		},
		backend: recordingBackend{conn: conn},
	}

	strategy := types.MappingStrategy{
		Name: "ldap_lookup",
		LDAPSearch: &types.LDAPSearchConfig{
			BaseDN:     "ou=users,dc=opentdf,dc=test",
			Filter:     "(&(objectClass=inetOrgPerson)(uid={username}))",
			Scope:      "subtree",
			Attributes: []string{"uid", "mail"},
		},
	}

	result, err := provider.ResolveEntity(context.Background(), strategy, map[string]interface{}{
		"username": "alice",
	})
	s.Require().NoError(err)

	s.Equal("ou=users,dc=opentdf,dc=test", conn.request.BaseDN)
	s.Equal(ScopeWholeSubtree, conn.request.Scope)
	s.Equal(NeverDerefAliases, conn.request.DerefAliases)
	s.Equal(1, conn.request.SizeLimit)
	s.Equal(30, conn.request.TimeLimit)
	s.Equal("(&(objectClass=inetOrgPerson)(uid=alice))", conn.request.Filter)

	expectedAttrs := []string{"uid", "mail"}
	s.Len(conn.request.Attributes, len(expectedAttrs))

	for index, attr := range expectedAttrs {
		s.Equal(attr, conn.request.Attributes[index])
	}

	s.Equal("alice", result.Data["uid"])
	s.Equal("alice@opentdf.test", result.Data["mail"])
}
