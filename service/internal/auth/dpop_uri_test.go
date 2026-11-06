package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAbsoluteHTUMatches(t *testing.T) {
	for _, tt := range []struct {
		name, received, expected string
		match                    bool
	}{
		{"exact", "https://api.example.test/rpc", "https://api.example.test/rpc", true},
		{"scheme and host case", "HTTPS://API.EXAMPLE.TEST/rpc", "https://api.example.test/rpc", true},
		{"https default port", "https://api.example.test:443/rpc", "https://api.example.test/rpc", true},
		{"https default port on server", "https://api.example.test/rpc", "https://api.example.test:443/rpc", true},
		{"http default port", "http://api.example.test:80/rpc", "http://api.example.test/rpc", true},
		{"nondefault port", "https://api.example.test:8443/rpc", "https://api.example.test:8443/rpc", true},
		{"missing nondefault port", "https://api.example.test/rpc", "https://api.example.test:8443/rpc", false},
		{"wrong port", "https://api.example.test:8444/rpc", "https://api.example.test:8443/rpc", false},
		{"wrong host", "https://other.example.test/rpc", "https://api.example.test/rpc", false},
		{"wrong scheme", "http://api.example.test/rpc", "https://api.example.test/rpc", false},
		{"wrong path", "https://api.example.test/other", "https://api.example.test/rpc", false},
		{"path case is significant", "https://api.example.test/RPC", "https://api.example.test/rpc", false},
		{"ipv6 default port", "https://[::1]:443/rpc", "https://[::1]/rpc", true},
		{"ipv6 nondefault port", "https://[::1]:8443/rpc", "https://[::1]:8443/rpc", true},
		{"ipv6 wrong port", "https://[::1]:8444/rpc", "https://[::1]:8443/rpc", false},
		{"empty path", "https://api.example.test", "https://api.example.test/", true},
		{"query and fragment", "https://api.example.test/rpc?a=b#fragment", "https://api.example.test/rpc?x=y#other", true},
		{"unreserved escape", "https://api.example.test/%7euser", "https://api.example.test/~user", true},
		{"escape case", "https://api.example.test/a%2fb", "https://api.example.test/a%2Fb", true},
		{"reserved escape stays distinct", "https://api.example.test/a%2Fb", "https://api.example.test/a/b", false},
		{"dot segments", "https://api.example.test/a/../rpc", "https://api.example.test/rpc", true},
		{"escaped dot segment", "https://api.example.test/a/%2e%2e/rpc", "https://api.example.test/rpc", true},
		{"repeated slashes stay distinct", "https://api.example.test//rpc", "https://api.example.test/rpc", false},
		{"relative proof", "/rpc", "https://api.example.test/rpc", false},
		{"relative candidate", "https://other.example.test/rpc", "/rpc", false},
		{"scheme-relative proof", "//api.example.test/rpc", "https://api.example.test/rpc", false},
		{"missing host", "https:///rpc", "https://api.example.test/rpc", false},
		{"userinfo", "https://user@api.example.test/rpc", "https://api.example.test/rpc", false},
		{"unsupported scheme", "ftp://api.example.test/rpc", "https://api.example.test/rpc", false},
		{"invalid escape", "https://api.example.test/%zz", "https://api.example.test/rpc", false},
		{"invalid port", "https://api.example.test:bad/rpc", "https://api.example.test/rpc", false},
		{"empty", "", "https://api.example.test/rpc", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, absoluteHTUMatches(tt.received, []string{"/legacy", "https://[invalid", tt.expected}))
		})
	}
}
