package authorizationv2

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/entity"
)

func TestForToken(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	eid := ForToken(jwt)

	tok, ok := eid.GetIdentifier().(*EntityIdentifier_Token)
	if !ok {
		t.Fatal("expected Token identifier")
	}
	if got := tok.Token.GetJwt(); got != jwt {
		t.Errorf("jwt = %q, want %q", got, jwt)
	}
}

func TestWithRequestToken(t *testing.T) {
	eid := WithRequestToken()

	wrt, ok := eid.GetIdentifier().(*EntityIdentifier_WithRequestToken)
	if !ok {
		t.Fatal("expected WithRequestToken identifier")
	}
	if !wrt.WithRequestToken.GetValue() {
		t.Error("expected WithRequestToken value to be true")
	}
}

func TestForClientID(t *testing.T) {
	eid := ForClientID("my-client")

	chain := extractEntityChain(t, eid)
	entities := chain.GetEntities()
	if len(entities) != 1 {
		t.Fatalf("entities len = %d, want 1", len(entities))
	}

	e := entities[0]
	cid, ok := e.GetEntityType().(*entity.Entity_ClientId)
	if !ok {
		t.Fatal("expected ClientId entity type")
	}
	if cid.ClientId != "my-client" {
		t.Errorf("ClientId = %q, want %q", cid.ClientId, "my-client")
	}
	if e.GetCategory() != entity.Entity_CATEGORY_SUBJECT {
		t.Errorf("category = %v, want CATEGORY_SUBJECT", e.GetCategory())
	}
}

func TestForEmail(t *testing.T) {
	eid := ForEmail("user@example.com")

	chain := extractEntityChain(t, eid)
	entities := chain.GetEntities()
	if len(entities) != 1 {
		t.Fatalf("entities len = %d, want 1", len(entities))
	}

	e := entities[0]
	em, ok := e.GetEntityType().(*entity.Entity_EmailAddress)
	if !ok {
		t.Fatal("expected EmailAddress entity type")
	}
	if em.EmailAddress != "user@example.com" {
		t.Errorf("EmailAddress = %q, want %q", em.EmailAddress, "user@example.com")
	}
	if e.GetCategory() != entity.Entity_CATEGORY_SUBJECT {
		t.Errorf("category = %v, want CATEGORY_SUBJECT", e.GetCategory())
	}
}

func TestForUserName(t *testing.T) {
	eid := ForUserName("alice")

	chain := extractEntityChain(t, eid)
	entities := chain.GetEntities()
	if len(entities) != 1 {
		t.Fatalf("entities len = %d, want 1", len(entities))
	}

	e := entities[0]
	un, ok := e.GetEntityType().(*entity.Entity_UserName)
	if !ok {
		t.Fatal("expected UserName entity type")
	}
	if un.UserName != "alice" {
		t.Errorf("UserName = %q, want %q", un.UserName, "alice")
	}
	if e.GetCategory() != entity.Entity_CATEGORY_SUBJECT {
		t.Errorf("category = %v, want CATEGORY_SUBJECT", e.GetCategory())
	}
}

func extractEntityChain(t *testing.T, eid *EntityIdentifier) *entity.EntityChain {
	t.Helper()
	ec, ok := eid.GetIdentifier().(*EntityIdentifier_EntityChain)
	if !ok {
		t.Fatal("expected EntityChain identifier")
	}
	return ec.EntityChain
}
