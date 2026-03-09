package ldap

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
)

type escapingBackend struct {
	stubBackend
}

func (escapingBackend) EscapeFilter(filter string) string {
	return transformation.EscapeLDAPFilter(filter)
}

func TestProvider_buildSearchFilter(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			filter, err := provider.buildSearchFilter(tt.filterTemplate, tt.params)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if filter != tt.expected {
				t.Fatalf("expected filter %q, got %q", tt.expected, filter)
			}
		})
	}
}
