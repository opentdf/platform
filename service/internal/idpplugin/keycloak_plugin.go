package idpplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Nerzal/gocloak/v11"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/service/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type KeyCloakConfig struct {
	Url            string `json:"url"`
	Realm          string `json:"realm"`
	ClientId       string `json:"clientid"`
	ClientSecret   string `json:"clientsecret"`
	LegacyKeycloak bool   `json:"legacykeycloak" default:"false"`
	SubGroups      bool   `json:"subgroups" default:"false"`
}

type KeyCloakConnector struct {
	token  *gocloak.JWT
	client gocloak.GoCloak
}

func EntityResolution(ctx context.Context,
	req *authorization.IdpPluginRequest, config *authorization.IdpConfig) (*authorization.IdpPluginResponse, error) {
	// note this only logs when run in test not when running in the OPE engine.
	slog.DebugContext(ctx, "EntityResolution", "req", fmt.Sprintf("%+v", req), "config", fmt.Sprintf("%+v", config))
	jsonString, err := json.Marshal(config.GetConfig().AsMap())
	if err != nil {
		slog.Error("Error marshalling keycloak config!", "error", err)
		return nil, err
	}
	kcConfig := KeyCloakConfig{}
	err = json.Unmarshal(jsonString, &kcConfig)
	if err != nil {
		return &authorization.IdpPluginResponse{},
			status.Error(codes.Internal, db.ErrTextCreationFailed)
	}
	connector, err := getKCClient(kcConfig, ctx)
	if err != nil {
		return &authorization.IdpPluginResponse{},
			status.Error(codes.Internal, db.ErrTextCreationFailed)
	}
	payload := req.GetEntities()

	var resolvedEntities []*authorization.IdpEntityRepresentation
	slog.DebugContext(ctx, "EntityResolution invoked", "payload", payload)

	for _, ident := range payload {
		slog.DebugContext(ctx, "Lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			slog.DebugContext(ctx, "GetClient", "client_id", ident.GetClientId())
			clientID := ident.GetClientId()
			clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				slog.Error(err.Error())
				return &authorization.IdpPluginResponse{},
					status.Error(codes.Internal, db.ErrTextGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client)
				if err != nil {
					slog.Error("Error serializing entity representation!", "error", err)
					return &authorization.IdpPluginResponse{},
						status.Error(codes.Internal, db.ErrTextCreationFailed)
				}
				var mystruct, struct_err = structpb.NewStruct(json)
				if struct_err != nil {
					slog.Error("Error making struct!", "error", err)
					return &authorization.IdpPluginResponse{},
						status.Error(codes.Internal, db.ErrTextCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			resolvedEntities = append(
				resolvedEntities,
				&authorization.IdpEntityRepresentation{
					OriginalId:      ident.GetId(),
					AdditionalProps: jsonEntities,
				},
			)
			return &authorization.IdpPluginResponse{
				EntityRepresentations: resolvedEntities,
			}, nil
		case *authorization.Entity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
		case *authorization.Entity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
		}

		users, err := connector.client.GetUsers(ctx, connector.token.AccessToken, kcConfig.Realm, getUserParams)
		if err != nil {
			slog.Error(err.Error())
			return &authorization.IdpPluginResponse{},
				status.Error(codes.Internal, db.ErrTextGetRetrievalFailed)
		} else if len(users) == 1 {
			user := users[0]
			slog.Debug("User found", "user", *user.ID, "entity", ident.String())
			slog.Debug("User", "details", fmt.Sprintf("%+v", user))
			slog.Debug("User", "attributes", fmt.Sprintf("%+v", user.Attributes))
			keycloakEntities = append(keycloakEntities, user)
		} else {
			slog.Error("No user found for", "entity", ident.String())
			if ident.GetEmailAddress() != "" {
				// try by group
				groups, groupErr := connector.client.GetGroups(
					ctx,
					connector.token.AccessToken,
					kcConfig.Realm,
					gocloak.GetGroupsParams{Search: func() *string { t := ident.GetEmailAddress(); return &t }()},
				)
				if groupErr != nil {
					slog.Error("Error getting group", "group", groupErr)
					return &authorization.IdpPluginResponse{},
						status.Error(codes.Internal, db.ErrTextGetRetrievalFailed)
				} else if len(groups) == 1 {
					slog.Info("Group found for", "entity", ident.String())
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(*group.ID, connector, &kcConfig, ctx)
					if exErr != nil {
						return &authorization.IdpPluginResponse{},
							status.Error(codes.Internal, db.ErrTextNotFound)
					} else {
						keycloakEntities = expandedRepresentations
					}
				} else {
					slog.Error("No group found for", "entity", ident.String())
					var entityNotFoundErr authorization.EntityNotFoundError
					switch ident.GetEntityType().(type) {
					case *authorization.Entity_EmailAddress:
						entityNotFoundErr = authorization.EntityNotFoundError{Code: int32(codes.NotFound), Message: db.ErrTextGetRetrievalFailed, Entity: ident.GetEmailAddress()}
					case *authorization.Entity_UserName:
						entityNotFoundErr = authorization.EntityNotFoundError{Code: int32(codes.NotFound), Message: db.ErrTextGetRetrievalFailed, Entity: ident.GetUserName()}
					// case "":
					// 	return &authorization.IdpPluginResponse{},
					// 		status.Error(codes.InvalidArgument, db.ErrTextNotFound)
					default:
						slog.Error("Unsupported/unknown type for", "entity", ident.String())
						entityNotFoundErr = authorization.EntityNotFoundError{Code: int32(codes.NotFound), Message: db.ErrTextGetRetrievalFailed, Entity: ident.String()}
					}
					slog.Error(entityNotFoundErr.String())
					return &authorization.IdpPluginResponse{}, errors.New(entityNotFoundErr.String())
				}
			}
		}

		var jsonEntities []*structpb.Struct
		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er)
			if err != nil {
				slog.Error("Error serializing entity representation!", "error", err)
				return &authorization.IdpPluginResponse{},
					status.Error(codes.Internal, db.ErrTextCreationFailed)
			}
			var mystruct, struct_err = structpb.NewStruct(json)
			if struct_err != nil {
				slog.Error("Error making struct!", "error", err)
				return &authorization.IdpPluginResponse{},
					status.Error(codes.Internal, db.ErrTextCreationFailed)
			}
			jsonEntities = append(jsonEntities, mystruct)
		}

		resolvedEntities = append(
			resolvedEntities,
			&authorization.IdpEntityRepresentation{
				OriginalId:      ident.GetId(),
				AdditionalProps: jsonEntities},
		)
		slog.DebugContext(ctx, "Entities", "resolved", fmt.Sprintf("%+v", resolvedEntities))
	}

	return &authorization.IdpPluginResponse{
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

func getKCClient(kcConfig KeyCloakConfig, ctx context.Context) (*KeyCloakConnector, error) {
	var client gocloak.GoCloak
	if kcConfig.LegacyKeycloak {
		slog.Warn("Using legacy connection mode for Keycloak < 17.x.x")
		client = gocloak.NewClient(kcConfig.Url)
	} else {
		client = gocloak.NewClient(kcConfig.Url, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	}
	// If needed, ability to disable tls checks for testing
	// restyClient := client.RestyClient()
	// restyClient.SetDebug(true)
	// restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	// client.SetRestyClient(restyClient)
	slog.Debug(kcConfig.ClientId)
	slog.Debug(kcConfig.ClientSecret)
	slog.Debug(kcConfig.Url)
	slog.Debug(kcConfig.Realm)
	token, err := client.LoginClient(ctx, kcConfig.ClientId, kcConfig.ClientSecret, kcConfig.Realm)
	if err != nil {
		slog.Error("Error connecting to keycloak!", err)
		return nil, err
	}
	keycloakConnector := KeyCloakConnector{token: token, client: client}

	return &keycloakConnector, nil
}

func expandGroup(groupID string, kcConnector *KeyCloakConnector, kcConfig *KeyCloakConfig, ctx context.Context) ([]*gocloak.User, error) {
	slog.Info("expandGroup invoked: ", groupID, kcConnector, kcConfig.Url, ctx)
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
			slog.Error("Error getting group members", memberErr)
		}
	} else {
		slog.Error("Error getting group", err)
	}
	return entityRepresentations, nil
}
