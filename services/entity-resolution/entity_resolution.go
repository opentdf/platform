package entity_resolution

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	entity_resolution "github.com/opentdf/opentdf-v2-poc/sdk/entity-resolution"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
)

type EntityService struct {
	entity_resolution.UnimplementedEntityResolutionServiceServer
	dbClient *db.Client
}

type KeyCloakConfg struct {
	Url            string
	Realm          string
	ClientId       string
	ClientSecret   string
	LegacyKeycloak bool `default:"false"`
	SubGroups      bool `default:"false"`
}

type KeyCloakConnector struct {
	token  *gocloak.JWT
	client gocloak.GoCloak
}

const (
	TypeEmail    = "email"
	TypeUsername = "username"
)

func (s EntityService) EntityResolution(ctx context.Context,
	req *entity_resolution.EntityResolutionRequest) (*entity_resolution.EntityResolutionResponse, error) {
	payload := req.GetEntityIdentifiers()
	var kcConfig KeyCloakConfg = KeyCloakConfg{}

	slog.Debug("EntityResolution with payload", payload)

	kcConnector, err := getKCClient(nil)
	if err != nil {
		return &entity_resolution.EntityResolutionResponse{},
			status.Error(codes.Internal, services.ErrCreatingResource)
	}

	for i, ident := range payload {
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams

		exactMatch := true
		switch ident.Type {
		case TypeEmail:
			getUserParams = gocloak.GetUsersParams{Email: &payload[i].Identifier, Exact: &exactMatch}
			fallthrough
		case TypeUsername:
			getUserParams = gocloak.GetUsersParams{Username: &payload[i].Identifier, Exact: &exactMatch}
		case "":
			return &entity_resolution.EntityResolutionResponse{},
				status.Error(codes.InvalidArgument, services.ErrNotFound)
		default:
			typeErr := fmt.Errorf("Unknown Type %s for identifier %s", ident.Type, ident.Identifier)
			return &entity_resolution.EntityResolutionResponse{},
				status.Error(codes.InvalidArgument, typeErr.Error())
		}

		users, userErr := kcConnector.client.GetUsers(ctx, kcConnector.token.AccessToken, kcConfig.Realm, getUserParams)
		if userErr != nil {
			slog.Error("Error getting user")
			return &entity_resolution.EntityResolutionResponse{},
				status.Error(codes.Internal, services.ErrGettingResource)
		} else if len(users) == 1 {
			user := users[0]
			slog.Info("User %s found for %s ", *user.ID, ident.Identifier)
			keycloakEntities = append(keycloakEntities, user)
		} else {
			slog.Error("No user found for", ident.Identifier)
			if ident.Type == TypeEmail {
				//try by group
				groups, groupErr := kcConnector.client.GetGroups(ctx, kcConnector.token.AccessToken, kcConfig.Realm, gocloak.GetGroupsParams{Search: &payload.EntityIdentifiers[i].Identifier})
				if groupErr != nil {
					slog.Error("Error getting group", groupErr)
					return &entity_resolution.EntityResolutionResponse{},
						status.Error(codes.Internal, services.ErrGettingResource)
				} else if len(groups) == 1 {
					slog.Error("Group found for", ident.Identifier)
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(*group.ID, kcConnector, &kcConfig, ctx)
					if exErr != nil {
						return &entity_resolution.EntityResolutionResponse{},
							status.Error(codes.Internal, services.ErrGettingResource)
					} else {
						keycloakEntities = expandedRepresentations
					}
				}
			}
		}
	}

	responsePayload := &entity_resolution.EntityResolutionPayload{
		EntityRepresentations: []*entity_resolution.EntityRepresentations{
			{
				AdditionalProp1: &entity_resolution.AdditionalProp{},
			},
		},
		OriginalId: &entity_resolution.OriginalId{
			Identifier: "mockID",
			Type:       "mockType",
		},
	}

	return &entity_resolution.EntityResolutionResponse{
		EntityRepresentationsPayload: []*entity_resolution.EntityResolutionPayload{responsePayload},
	}, nil
}

func getKCClient(kcConfig any) (*KeyCloakConnector, error) {
	// TODO
	slog.Info("getKCClient invoked: ", kcConfig)
	var client gocloak.GoCloak

	return &KeyCloakConnector{token: nil, client: client}, nil
}

func expandGroup(groupID string, kcConnector *KeyCloakConnector, kcConfig *KeyCloakConfg, ctx context.Context) ([]*gocloak.User, error) {
	// TODO
	slog.Info("expandGroup invoked: ", groupID, kcConnector, kcConfig, ctx)
	var entityRepresentations []*gocloak.User
	return entityRepresentations, nil
}
