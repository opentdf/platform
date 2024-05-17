package entityresolution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const ErrTextCreationFailed = "resource creation failed"
const ErrTextGetRetrievalFailed = "resource retrieval failed"
const ErrTextNotFound = "resource not found"

type KeycloakConfig struct {
	URL            string `json:"url"`
	Realm          string `json:"realm"`
	ClientID       string `json:"clientid"`
	ClientSecret   string `json:"clientsecret"`
	LegacyKeycloak bool   `json:"legacykeycloak" default:"false"`
	SubGroups      bool   `json:"subgroups" default:"false"`
}

type KeyCloakConnector struct {
	token  *gocloak.JWT
	client *gocloak.GoCloak
}

func EntityResolution(ctx context.Context,
	req *entityresolution.ResolveEntitiesRequest, kcConfig KeycloakConfig) (entityresolution.ResolveEntitiesResponse, error) {
	// note this only logs when run in test not when running in the OPE engine.
	slog.Debug("EntityResolution", "req", fmt.Sprintf("%+v", req))
	// slog.Debug("EntityResolutionConfig", "config", fmt.Sprintf("%+v", kcConfig))
	connector, err := getKCClient(ctx, kcConfig)
	if err != nil {
		return entityresolution.ResolveEntitiesResponse{},
			status.Error(codes.Internal, ErrTextCreationFailed)
	}
	payload := req.GetEntities()

	var resolvedEntities []*entityresolution.EntityRepresentation
	slog.Debug("EntityResolution invoked", "payload", payload)

	for _, ident := range payload {
		slog.Debug("Lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			slog.Debug("GetClient", "client_id", ident.GetClientId())
			clientID := ident.GetClientId()
			clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				slog.Error(err.Error())
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client)
				if err != nil {
					slog.Error("Error serializing entity representation!", "error", err)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextCreationFailed)
				}
				var mystruct, structErr = structpb.NewStruct(json)
				if structErr != nil {
					slog.Error("Error making struct!", "error", err)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			resolvedEntities = append(
				resolvedEntities,
				&entityresolution.EntityRepresentation{
					OriginalId:      ident.GetId(),
					AdditionalProps: jsonEntities,
				},
			)
			return entityresolution.ResolveEntitiesResponse{
				EntityRepresentations: resolvedEntities,
			}, nil
		case *authorization.Entity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
		case *authorization.Entity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
		}

		users, err := connector.client.GetUsers(ctx, connector.token.AccessToken, kcConfig.Realm, getUserParams)
		switch {
		case err != nil:
			slog.Error(err.Error())
			return entityresolution.ResolveEntitiesResponse{},
				status.Error(codes.Internal, ErrTextGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			slog.Debug("User found", "user", *user.ID, "entity", ident.String())
			slog.Debug("User", "details", fmt.Sprintf("%+v", user))
			slog.Debug("User", "attributes", fmt.Sprintf("%+v", user.Attributes))
			keycloakEntities = append(keycloakEntities, user)
		default:
			slog.Error("No user found for", "entity", ident.String())
			if ident.GetEmailAddress() != "" {
				// try by group
				groups, groupErr := connector.client.GetGroups(
					ctx,
					connector.token.AccessToken,
					kcConfig.Realm,
					gocloak.GetGroupsParams{Search: func() *string { t := ident.GetEmailAddress(); return &t }()},
				)
				switch {
				case groupErr != nil:
					slog.Error("Error getting group", "group", groupErr)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextGetRetrievalFailed)
				case len(groups) == 1:
					slog.Info("Group found for", "entity", ident.String())
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(ctx, *group.ID, connector, &kcConfig)
					if exErr != nil {
						return entityresolution.ResolveEntitiesResponse{},
							status.Error(codes.Internal, ErrTextNotFound)
					} else {
						keycloakEntities = expandedRepresentations
					}
				default:
					slog.Error("No group found for", "entity", ident.String())
					var entityNotFoundErr entityresolution.EntityNotFoundError
					switch ident.GetEntityType().(type) {
					case *authorization.Entity_EmailAddress:
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrTextGetRetrievalFailed, Entity: ident.GetEmailAddress()}
					case *authorization.Entity_UserName:
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrTextGetRetrievalFailed, Entity: ident.GetUserName()}
					// case "":
					// 	return &entityresolution.IdpPluginResponse{},
					// 		status.Error(codes.InvalidArgument, db.ErrTextNotFound)
					default:
						slog.Error("Unsupported/unknown type for", "entity", ident.String())
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrTextGetRetrievalFailed, Entity: ident.String()}
					}
					slog.Error(entityNotFoundErr.String())
					return entityresolution.ResolveEntitiesResponse{}, errors.New(entityNotFoundErr.String())
				}
			}
		}

		var jsonEntities []*structpb.Struct
		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er)
			if err != nil {
				slog.Error("Error serializing entity representation!", "error", err)
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}
			var mystruct, structErr = structpb.NewStruct(json)
			if structErr != nil {
				slog.Error("Error making struct!", "error", err)
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}
			jsonEntities = append(jsonEntities, mystruct)
		}

		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      ident.GetId(),
				AdditionalProps: jsonEntities},
		)
		slog.Debug("Entities", "resolved", fmt.Sprintf("%+v", resolvedEntities))
	}

	return entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

func typeToGenericJSONMap[Marshalable any](inputStruct Marshalable) (map[string]interface{}, error) {
	// For now, since we dont' know the "shape" of the entity/user record or representation we will get from a specific entity store,
	tmpDoc, err := json.Marshal(inputStruct)
	if err != nil {
		slog.Error("Error marshalling input type!", "error", err)
		return nil, err
	}

	var genericMap map[string]interface{}
	err = json.Unmarshal(tmpDoc, &genericMap)
	if err != nil {
		slog.Error("Could not deserialize generic entitlement context JSON input document!", "error", err)
		return nil, err
	}

	return genericMap, nil
}

func getKCClient(ctx context.Context, kcConfig KeycloakConfig) (*KeyCloakConnector, error) {
	var client *gocloak.GoCloak
	if kcConfig.LegacyKeycloak {
		slog.Warn("Using legacy connection mode for Keycloak < 17.x.x")
		client = gocloak.NewClient(kcConfig.URL)
	} else {
		client = gocloak.NewClient(kcConfig.URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	}
	// If needed, ability to disable tls checks for testing
	// restyClient := client.RestyClient()
	// restyClient.SetDebug(true)
	// restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	// client.SetRestyClient(restyClient)

	// For debugging
	// slog.Debug(kcConfig.ClientID)
	// slog.Debug(kcConfig.ClientSecret)
	// slog.Debug(kcConfig.URL)
	// slog.Debug(kcConfig.Realm)
	token, err := client.LoginClient(ctx, kcConfig.ClientID, kcConfig.ClientSecret, kcConfig.Realm)
	if err != nil {
		slog.Error("Error connecting to keycloak!", "error", err)
		return nil, err
	}
	keycloakConnector := KeyCloakConnector{token: token, client: client}

	return &keycloakConnector, nil
}

func expandGroup(ctx context.Context, groupID string, kcConnector *KeyCloakConnector, kcConfig *KeycloakConfig) ([]*gocloak.User, error) {
	slog.Info("expandGroup invoked: ", groupID, kcConnector, kcConfig.URL, ctx)
	var entityRepresentations []*gocloak.User

	grp, err := kcConnector.client.GetGroup(ctx, kcConnector.token.AccessToken, kcConfig.Realm, groupID)
	if err == nil {
		grpMembers, memberErr := kcConnector.client.GetGroupMembers(ctx, kcConnector.token.AccessToken, kcConfig.Realm,
			*grp.ID, gocloak.GetGroupsParams{})
		if memberErr == nil {
			slog.Debug("Adding members", "amount", len(grpMembers), "from group", *grp.Name)
			for i := 0; i < len(grpMembers); i++ {
				user := grpMembers[i]
				entityRepresentations = append(entityRepresentations, user)
			}
		} else {
			slog.Error("Error getting group members", "error", memberErr)
		}
	} else {
		slog.Error("Error getting group", "error", err)
		return nil, err
	}
	return entityRepresentations, nil
}
