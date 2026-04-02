package sdk

import (
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// EntityIdentifierForToken returns an EntityIdentifier that resolves the entity from the given JWT.
// The authorization service will parse the token to derive the entity chain.
func EntityIdentifierForToken(jwt string) *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_Token{
			Token: &entity.Token{
				Jwt: jwt,
			},
		},
	}
}

// EntityIdentifierWithRequestToken returns an EntityIdentifier that instructs the authorization
// service to derive the entity from the request's Authorization header token.
func EntityIdentifierWithRequestToken() *authorizationv2.EntityIdentifier {
	return &authorizationv2.EntityIdentifier{
		Identifier: &authorizationv2.EntityIdentifier_WithRequestToken{
			WithRequestToken: wrapperspb.Bool(true),
		},
	}
}

// EntityIdentifierForClientID returns an EntityIdentifier for a single subject entity identified by client ID.
func EntityIdentifierForClientID(clientID string) *authorizationv2.EntityIdentifier {
	return entityIdentifierFromEntity(&entity.Entity{
		EntityType: &entity.Entity_ClientId{ClientId: clientID},
		Category:   entity.Entity_CATEGORY_SUBJECT,
	})
}

// EntityIdentifierForEmail returns an EntityIdentifier for a single subject entity identified by email address.
func EntityIdentifierForEmail(email string) *authorizationv2.EntityIdentifier {
	return entityIdentifierFromEntity(&entity.Entity{
		EntityType: &entity.Entity_EmailAddress{EmailAddress: email},
		Category:   entity.Entity_CATEGORY_SUBJECT,
	})
}

// EntityIdentifierForUserName returns an EntityIdentifier for a single subject entity identified by username.
func EntityIdentifierForUserName(username string) *authorizationv2.EntityIdentifier {
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
