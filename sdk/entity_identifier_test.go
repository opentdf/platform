package sdk

import (
	"testing"

	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForToken(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
	eid := ForToken(jwt)

	tok, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_Token)
	require.True(t, ok, "expected Token identifier")
	assert.Equal(t, jwt, tok.Token.GetJwt())
}

func TestWithRequestToken(t *testing.T) {
	eid := WithRequestToken()

	wrt, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_WithRequestToken)
	require.True(t, ok, "expected WithRequestToken identifier")
	assert.True(t, wrt.WithRequestToken.GetValue())
}

func TestForClientID(t *testing.T) {
	eid := ForClientID("my-client")

	chain := extractEntityChain(t, eid)
	require.Len(t, chain.GetEntities(), 1)

	e := chain.GetEntities()[0]
	cid, ok := e.GetEntityType().(*entity.Entity_ClientId)
	require.True(t, ok, "expected ClientId entity type")
	assert.Equal(t, "my-client", cid.ClientId)
	assert.Equal(t, entity.Entity_CATEGORY_SUBJECT, e.GetCategory())
}

func TestForEmail(t *testing.T) {
	eid := ForEmail("user@example.com")

	chain := extractEntityChain(t, eid)
	require.Len(t, chain.GetEntities(), 1)

	e := chain.GetEntities()[0]
	em, ok := e.GetEntityType().(*entity.Entity_EmailAddress)
	require.True(t, ok, "expected EmailAddress entity type")
	assert.Equal(t, "user@example.com", em.EmailAddress)
	assert.Equal(t, entity.Entity_CATEGORY_SUBJECT, e.GetCategory())
}

func TestForUserName(t *testing.T) {
	eid := ForUserName("alice")

	chain := extractEntityChain(t, eid)
	require.Len(t, chain.GetEntities(), 1)

	e := chain.GetEntities()[0]
	un, ok := e.GetEntityType().(*entity.Entity_UserName)
	require.True(t, ok, "expected UserName entity type")
	assert.Equal(t, "alice", un.UserName)
	assert.Equal(t, entity.Entity_CATEGORY_SUBJECT, e.GetCategory())
}

func extractEntityChain(t *testing.T, eid *authorizationv2.EntityIdentifier) *entity.EntityChain {
	t.Helper()
	ec, ok := eid.GetIdentifier().(*authorizationv2.EntityIdentifier_EntityChain)
	require.True(t, ok, "expected EntityChain identifier")
	return ec.EntityChain
}
