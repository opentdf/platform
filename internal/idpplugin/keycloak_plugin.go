package idpplugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"

	gocloak "github.com/Nerzal/gocloak/v11"
	authorization "github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type IdpPlugin struct {
	connector KeyCloakConnector
	config    KeyCloakConfg
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

func NewIdpPlugin(config KeyCloakConfg) (*IdpPlugin, error) {
	kcConnector, err := getKCClient(config)
	if err != nil {
		return &IdpPlugin{},
			status.Error(codes.Internal, services.ErrCreationFailed)
	}

	plugin := new(IdpPlugin)
	plugin.connector = *kcConnector
	plugin.config = config
	return plugin, nil
}

func (s IdpPlugin) EntityResolution(ctx context.Context,
	req *authorization.IdpPluginRequest) (*authorization.IdpPluginResponse, error) {
	payload := req.GetEntities()

	// var kcConfig KeyCloakConfg = KeyCloakConfg{}

	var resolvedEntities []*authorization.IdpEntityRepresentation
	slog.Debug("EntityResolution invoked with", "payload", payload)

	for i, ident := range payload {
		slog.Debug("Lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams

		exactMatch := true
		switch ident.EntityType.(type) {
		case *authorization.IdpEntity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := payload[i].GetEmailAddress(); return &t }(), Exact: &exactMatch}
		case *authorization.IdpEntity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := payload[i].GetUserName(); return &t }(), Exact: &exactMatch}
		// case "":
		// 	return &authorization.IdpPluginResponse{},
		// 		status.Error(codes.InvalidArgument, services.ErrNotFound)
		default:
			typeErr := fmt.Errorf("Unknown type for entity %s", ident.String())
			return &authorization.IdpPluginResponse{},
				status.Error(codes.InvalidArgument, typeErr.Error())
		}

		users, userErr := s.connector.client.GetUsers(ctx, s.connector.token.AccessToken, s.config.Realm, getUserParams)
		if userErr != nil {
			return &authorization.IdpPluginResponse{},
				status.Error(codes.Internal, services.ErrGetRetrievalFailed)
		} else if len(users) == 1 {
			user := users[0]
			slog.Debug("User found", "user", *user.ID, "entity", ident.String())
			keycloakEntities = append(keycloakEntities, user)
		} else {
			slog.Error("No user found for", "entity", ident.String())
			if ident.GetEmailAddress() != "" {
				//try by group
				groups, groupErr := s.connector.client.GetGroups(
					ctx,
					s.connector.token.AccessToken,
					s.config.Realm,
					gocloak.GetGroupsParams{Search: func() *string { t := payload[i].GetEmailAddress(); return &t }()},
				)
				if groupErr != nil {
					slog.Error("Error getting group", "group", groupErr)
					return &authorization.IdpPluginResponse{},
						status.Error(codes.Internal, services.ErrGetRetrievalFailed)
				} else if len(groups) == 1 {
					slog.Info("Group found for", "entity", ident.String())
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(*group.ID, &s.connector, &s.config, ctx)
					if exErr != nil {
						return &authorization.IdpPluginResponse{},
							status.Error(codes.Internal, services.ErrGetRetrievalFailed)
					} else {
						keycloakEntities = expandedRepresentations
					}
				}
			}
		}

		var jsonEntities []*structpb.Struct
		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er)
			if err != nil {
				slog.Error("Error serializing entity representation!", "error", err)
				return &authorization.IdpPluginResponse{},
					status.Error(codes.Internal, services.ErrCreationFailed)
			}
			var mystruct, struct_err = structpb.NewStruct(json)
			if struct_err != nil {
				slog.Error("Error making struct!", "error", err)
				return &authorization.IdpPluginResponse{},
					status.Error(codes.Internal, services.ErrCreationFailed)
			}
			// var entityRep = authorization.EntityRepresentation{AdditionalProps: mystruct}
			jsonEntities = append(jsonEntities, mystruct)
		}

		resolvedEntities = append(
			resolvedEntities,
			&authorization.IdpEntityRepresentation{
				OriginalId:      ident.GetId(),
				AdditionalProps: jsonEntities},
		)
	}

	return &authorization.IdpPluginResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

func typeToGenericJSONMap[Marshalable any](inputStruct Marshalable) (map[string]interface{}, error) {
	//For now, since we dont' know the "shape" of the entity/user record or representation we will get from a specific entity store,
	tmpDoc, err := json.Marshal(inputStruct)
	if err != nil {
		slog.Error("Error marshalling input type!", "error", err)
		return nil, err
	}

	// var genericER authorization.EntityRepresentation
	var genericMap map[string]interface{}

	err = json.Unmarshal(tmpDoc, &genericMap)
	if err != nil {
		// slog.Error(string(tmpDoc[:]))
		slog.Error("Could not deserialize generic entitlement context JSON input document!", "error", err)
		return nil, err
	}
	// genericER.AdditionalProps = genericMap
	// slog.Debug(genericER.String())

	return genericMap, nil
}

func getKCClient(kcConfig KeyCloakConfg) (*KeyCloakConnector, error) {
	var client gocloak.GoCloak
	if kcConfig.LegacyKeycloak {
		slog.Warn("Using legacy connection mode for Keycloak < 17.x.x")
		client = gocloak.NewClient(kcConfig.Url)
		restyClient := client.RestyClient()
		restyClient.SetDebug(true)
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		client.SetRestyClient(restyClient)
	} else {
		client = gocloak.NewClient(kcConfig.Url, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	}
	// restyClient := client.RestyClient()
	// restyClient.SetDebug(true)
	// restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	ctxb := context.Background()
	token, err := client.LoginClient(ctxb, kcConfig.ClientId, kcConfig.ClientSecret, kcConfig.Realm)
	if err != nil {
		slog.Warn("Error connecting to keycloak!", err)
		return nil, err
	}
	keycloakConnector := KeyCloakConnector{token: token, client: client}

	return &keycloakConnector, nil
}

func expandGroup(groupID string, kcConnector *KeyCloakConnector, kcConfig *KeyCloakConfg, ctx context.Context) ([]*gocloak.User, error) {
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
			err = memberErr
		}
	} else {
		slog.Error("Error getting group", err)
	}
	return entityRepresentations, nil
}
