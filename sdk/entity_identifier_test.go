package sdk

import (
	"testing"

	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
)

func TestEntityIdentifierForToken(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	eid := EntityIdentifierForToken(jwt)

	tok, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_Token)
	if !ok {
		t.Fatal("expected Token identifier")
	}
	if got := tok.Token.GetJwt(); got != jwt {
		t.Errorf("jwt = %q, want %q", got, jwt)
	}
}

func TestEntityIdentifierForToken_EmptyString(t *testing.T) {
	eid := EntityIdentifierForToken("")

	tok, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_Token)
	if !ok {
		t.Fatal("expected Token identifier")
	}
	if got := tok.Token.GetJwt(); got != "" {
		t.Errorf("jwt = %q, want empty string", got)
	}
}

func TestEntityIdentifierWithRequestToken(t *testing.T) {
	eid := EntityIdentifierWithRequestToken()

	wrt, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_WithRequestToken)
	if !ok {
		t.Fatal("expected WithRequestToken identifier")
	}
	if !wrt.WithRequestToken.GetValue() {
		t.Error("expected WithRequestToken value to be true")
	}
}

func TestEntityChainConstructors(t *testing.T) {
	tests := []struct {
		name        string
		constructor func(string) *authorizationv2.EntityIdentifier
		input       string
		checkType   func(*entity.Entity) (string, bool)
	}{
		{
			name:        "EntityIdentifierForClientID",
			constructor: EntityIdentifierForClientID,
			input:       "my-client",
			checkType: func(e *entity.Entity) (string, bool) {
				cid, ok := e.GetEntityType().(*entity.Entity_ClientId)
				if !ok {
					return "", false
				}
				return cid.ClientId, true
			},
		},
		{
			name:        "EntityIdentifierForClientID_EmptyString",
			constructor: EntityIdentifierForClientID,
			input:       "",
			checkType: func(e *entity.Entity) (string, bool) {
				cid, ok := e.GetEntityType().(*entity.Entity_ClientId)
				if !ok {
					return "", false
				}
				return cid.ClientId, true
			},
		},
		{
			name:        "EntityIdentifierForEmail",
			constructor: EntityIdentifierForEmail,
			input:       "user@example.com",
			checkType: func(e *entity.Entity) (string, bool) {
				em, ok := e.GetEntityType().(*entity.Entity_EmailAddress)
				if !ok {
					return "", false
				}
				return em.EmailAddress, true
			},
		},
		{
			name:        "EntityIdentifierForEmail_EmptyString",
			constructor: EntityIdentifierForEmail,
			input:       "",
			checkType: func(e *entity.Entity) (string, bool) {
				em, ok := e.GetEntityType().(*entity.Entity_EmailAddress)
				if !ok {
					return "", false
				}
				return em.EmailAddress, true
			},
		},
		{
			name:        "EntityIdentifierForUserName",
			constructor: EntityIdentifierForUserName,
			input:       "alice",
			checkType: func(e *entity.Entity) (string, bool) {
				un, ok := e.GetEntityType().(*entity.Entity_UserName)
				if !ok {
					return "", false
				}
				return un.UserName, true
			},
		},
		{
			name:        "EntityIdentifierForUserName_EmptyString",
			constructor: EntityIdentifierForUserName,
			input:       "",
			checkType: func(e *entity.Entity) (string, bool) {
				un, ok := e.GetEntityType().(*entity.Entity_UserName)
				if !ok {
					return "", false
				}
				return un.UserName, true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eid := tt.constructor(tt.input)

			chain := extractEntityChain(t, eid)
			entities := chain.GetEntities()
			if len(entities) != 1 {
				t.Fatalf("entities len = %d, want 1", len(entities))
			}

			e := entities[0]
			got, ok := tt.checkType(e)
			if !ok {
				t.Fatalf("unexpected entity type for %s", tt.name)
			}
			if got != tt.input {
				t.Errorf("%s value = %q, want %q", tt.name, got, tt.input)
			}
			if e.GetCategory() != entity.Entity_CATEGORY_SUBJECT {
				t.Errorf("category = %v, want CATEGORY_SUBJECT", e.GetCategory())
			}
		})
	}
}

func extractEntityChain(t *testing.T, eid *authorizationv2.EntityIdentifier) *entity.EntityChain {
	t.Helper()
	ec, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_EntityChain)
	if !ok {
		t.Fatal("expected EntityChain identifier")
	}
	return ec.EntityChain
}
