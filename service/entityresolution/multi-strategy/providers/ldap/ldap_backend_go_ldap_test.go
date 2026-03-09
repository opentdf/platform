package ldap

import "testing"

func TestDialLDAPURL(t *testing.T) {
	t.Run("builds LDAP URL for TCP", func(t *testing.T) {
		target, err := dialTargetURL("ldap", "tcp", "ldap.example.com:389")
		if err != nil {
			t.Fatalf("dialTargetURL returned error: %v", err)
		}

		if target != "ldap://ldap.example.com:389" {
			t.Fatalf("unexpected target %q", target)
		}
	})

	t.Run("builds LDAPS URL for TCP", func(t *testing.T) {
		target, err := dialTargetURL("ldaps", "tcp", "ldap.example.com:636")
		if err != nil {
			t.Fatalf("dialTargetURL returned error: %v", err)
		}

		if target != "ldaps://ldap.example.com:636" {
			t.Fatalf("unexpected target %q", target)
		}
	})

	t.Run("rejects unsupported networks", func(t *testing.T) {
		_, err := dialTargetURL("ldap", "udp", "ldap.example.com:389")
		if err == nil {
			t.Fatal("expected error for unsupported network")
		}
	})
}
