package authorizationv2

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ForToken returns an EntityIdentifier that resolves the entity from the given JWT.
// The authorization service will parse the token to derive the entity chain.
func ForToken(jwt string) *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_Token{
			Token: &entity.Token{
				Jwt: jwt,
			},
		},
	}
}

// WithRequestToken returns an EntityIdentifier that instructs the authorization
// service to derive the entity from the request's Authorization header token.
func WithRequestToken() *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_WithRequestToken{
			WithRequestToken: wrapperspb.Bool(true),
		},
	}
}

// ForClientID returns an EntityIdentifier for a single subject entity identified by client ID.
func ForClientID(clientID string) *authorizationv2.EntityIdentifier {
	return entityIdentifierFromEntity(&entity.Entity{
		EntityType: &entity.Entity_ClientId{ClientId: clientID},
		Category:   entity.Entity_CATEGORY_SUBJECT,
	})
}

// ForEmail returns an EntityIdentifier for a single subject entity identified by email address.
func ForEmail(email string) *authorizationv2.EntityIdentifier {
	return entityIdentifierFromEntity(&entity.Entity{
		EntityType: &entity.Entity_EmailAddress{EmailAddress: email},
		Category:   entity.Entity_CATEGORY_SUBJECT,
	})
}

// ForUserName returns an EntityIdentifier for a single subject entity identified by username.
func ForUserName(username string) *authorizationv2.EntityIdentifier {
	return entityIdentifierFromEntity(&entity.Entity{
		EntityType: &entity.Entity_UserName{UserName: username},
		Category:   entity.Entity_CATEGORY_SUBJECT,
	})
}

func entityIdentifierFromEntity(e *entity.Entity) *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				Entities: []*entity.Entity{e},
			},
		},
	}
}
