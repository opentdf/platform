package entityresolution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	auth "github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/internal/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const ErrTextCreationFailed = "resource creation failed"
const ErrTextGetRetrievalFailed = "resource retrieval failed"
const ErrTextNotFound = "resource not found"

const ClientJwtSelector = "azp"
const UsernameJwtSelector = "preferred_username"
const UsernameConditionalSelector = "client_id"

const serviceAccountUsernamePrefix = "service-account-"

type KeycloakConfig struct {
	URL            string                 `json:"url"`
	Realm          string                 `json:"realm"`
	ClientID       string                 `json:"clientid"`
	ClientSecret   string                 `json:"clientsecret"`
	LegacyKeycloak bool                   `json:"legacykeycloak" default:"false"`
	SubGroups      bool                   `json:"subgroups" default:"false"`
	InferID        InferredIdentityConfig `json:"inferid,omitempty"`
}

type InferredIdentityConfig struct {
	From EntityImpliedFrom `json:"from,omitempty"`
}

type EntityImpliedFrom struct {
	ClientID bool `json:"clientid,omitempty"`
	Email    bool `json:"email,omitempty"`
	Username bool `json:"username,omitempty"`
}

type KeyCloakConnector struct {
	token  *gocloak.JWT
	client *gocloak.GoCloak
}

func CreateEntityChainFromJwt(
	ctx context.Context,
	req *entityresolution.CreateEntityChainFromJwtRequest,
	kcConfig KeycloakConfig,
	logger *logger.Logger,
) (entityresolution.CreateEntityChainFromJwtResponse, error) {
	var entityChains = []*authorization.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(ctx, kcConfig, tok.GetJwt(), logger)
		if err != nil {
			return entityresolution.CreateEntityChainFromJwtResponse{}, err
		}
		entityChains = append(entityChains, &authorization.EntityChain{Id: tok.GetId(), Entities: entities})
	}

	return entityresolution.CreateEntityChainFromJwtResponse{EntityChains: entityChains}, nil
}

func EntityResolution(ctx context.Context,
	req *entityresolution.ResolveEntitiesRequest, kcConfig KeycloakConfig, logger *logger.Logger) (entityresolution.ResolveEntitiesResponse, error) {
	// note this only logs when run in test not when running in the OPE engine.
	logger.Debug("EntityResolution", "req", fmt.Sprintf("%+v", req))
	// logger.Debug("EntityResolutionConfig", "config", fmt.Sprintf("%+v", kcConfig))
	connector, err := getKCClient(ctx, kcConfig, logger)
	if err != nil {
		return entityresolution.ResolveEntitiesResponse{},
			status.Error(codes.Internal, ErrTextCreationFailed)
	}
	payload := req.GetEntities()

	var resolvedEntities []*entityresolution.EntityRepresentation
	logger.Debug("EntityResolution invoked", "payload", payload)
	logger.Debug("EntityResolution invoked", "payload", len(payload))

	for idx, ident := range payload {
		logger.Debug("Lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			logger.Debug("GetClient", "client_id", ident.GetClientId())
			clientID := ident.GetClientId()
			clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				logger.Error(err.Error())
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client, logger)
				if err != nil {
					logger.Error("Error serializing entity representation!", "error", err)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextCreationFailed)
				}
				var mystruct, structErr = structpb.NewStruct(json)
				if structErr != nil {
					logger.Error("Error making struct!", "error", err)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			if len(clients) == 0 && kcConfig.InferID.From.ClientID {
				// convert entity to json
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					logger.Error("unable to make entity struct", "error", err)
					return entityresolution.ResolveEntitiesResponse{}, status.Error(codes.Internal, ErrTextCreationFailed)
				}
				jsonEntities = append(jsonEntities, entityStruct)
			}
			// make sure the id field is populated
			originialId := ident.GetId()
			if originialId == "" {
				originialId = auth.EntityIDPrefix + fmt.Sprint(idx)
			}
			resolvedEntities = append(
				resolvedEntities,
				&entityresolution.EntityRepresentation{
					OriginalId:      originialId,
					AdditionalProps: jsonEntities,
				},
			)
			continue
		case *authorization.Entity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
		case *authorization.Entity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
		}

		var jsonEntities []*structpb.Struct
		users, err := connector.client.GetUsers(ctx, connector.token.AccessToken, kcConfig.Realm, getUserParams)
		switch {
		case err != nil:
			logger.Error(err.Error())
			return entityresolution.ResolveEntitiesResponse{},
				status.Error(codes.Internal, ErrTextGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			logger.Debug("User found", "user", *user.ID, "entity", ident.String())
			logger.Debug("User", "details", fmt.Sprintf("%+v", user))
			logger.Debug("User", "attributes", fmt.Sprintf("%+v", user.Attributes))
			keycloakEntities = append(keycloakEntities, user)
		default:
			logger.Error("No user found for", "entity", ident)
			if ident.GetEmailAddress() != "" { //nolint:nestif // this case has many possible outcomes to handle
				// try by group
				groups, groupErr := connector.client.GetGroups(
					ctx,
					connector.token.AccessToken,
					kcConfig.Realm,
					gocloak.GetGroupsParams{Search: func() *string { t := ident.GetEmailAddress(); return &t }()},
				)
				switch {
				case groupErr != nil:
					logger.Error("Error getting group", "group", groupErr)
					return entityresolution.ResolveEntitiesResponse{},
						status.Error(codes.Internal, ErrTextGetRetrievalFailed)
				case len(groups) == 1:
					logger.Info("Group found for", "entity", ident.String())
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(ctx, *group.ID, connector, &kcConfig, logger)
					if exErr != nil {
						return entityresolution.ResolveEntitiesResponse{},
							status.Error(codes.Internal, ErrTextNotFound)
					} else {
						keycloakEntities = expandedRepresentations
					}
				default:
					logger.Error("No group found for", "entity", ident.String())
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
						logger.Error("Unsupported/unknown type for", "entity", ident.String())
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrTextGetRetrievalFailed, Entity: ident.String()}
					}
					logger.Error(entityNotFoundErr.String())
					if kcConfig.InferID.From.Email || kcConfig.InferID.From.Username {
						// user not found -- add json entity to resp instead
						entityStruct, err := entityToStructPb(ident)
						if err != nil {
							logger.Error("unable to make entity struct from email or username", "error", err)
							return entityresolution.ResolveEntitiesResponse{}, status.Error(codes.Internal, ErrTextCreationFailed)
						}
						jsonEntities = append(jsonEntities, entityStruct)
					} else {
						return entityresolution.ResolveEntitiesResponse{}, status.Error(codes.Code(entityNotFoundErr.GetCode()), entityNotFoundErr.GetMessage())
					}
				}
			} else if ident.GetUserName() != "" {
				if kcConfig.InferID.From.Username {
					// user not found -- add json entity to resp instead
					entityStruct, err := entityToStructPb(ident)
					if err != nil {
						logger.Error("unable to make entity struct from username", "error", err)
						return entityresolution.ResolveEntitiesResponse{}, status.Error(codes.Internal, ErrTextCreationFailed)
					}
					jsonEntities = append(jsonEntities, entityStruct)
				} else {
					entityNotFoundErr := entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrTextGetRetrievalFailed, Entity: ident.GetUserName()}
					return entityresolution.ResolveEntitiesResponse{}, status.Error(codes.Code(entityNotFoundErr.GetCode()), entityNotFoundErr.GetMessage())
				}
			}
		}

		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er, logger)
			if err != nil {
				logger.Error("Error serializing entity representation!", "error", err)
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}
			var mystruct, structErr = structpb.NewStruct(json)
			if structErr != nil {
				logger.Error("Error making struct!", "error", err)
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}
			jsonEntities = append(jsonEntities, mystruct)
		}
		// make sure the id field is populated
		originialId := ident.GetId()
		if originialId == "" {
			originialId = auth.EntityIDPrefix + fmt.Sprint(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      originialId,
				AdditionalProps: jsonEntities},
		)
		logger.Debug("Entities", "resolved", fmt.Sprintf("%+v", resolvedEntities))
	}

	return entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

func typeToGenericJSONMap[Marshalable any](inputStruct Marshalable, logger *logger.Logger) (map[string]interface{}, error) {
	// For now, since we dont' know the "shape" of the entity/user record or representation we will get from a specific entity store,
	tmpDoc, err := json.Marshal(inputStruct)
	if err != nil {
		logger.Error("Error marshalling input type!", "error", err)
		return nil, err
	}

	var genericMap map[string]interface{}
	err = json.Unmarshal(tmpDoc, &genericMap)
	if err != nil {
		logger.Error("Could not deserialize generic entitlement context JSON input document!", "error", err)
		return nil, err
	}

	return genericMap, nil
}

func getKCClient(ctx context.Context, kcConfig KeycloakConfig, logger *logger.Logger) (*KeyCloakConnector, error) {
	var client *gocloak.GoCloak
	if kcConfig.LegacyKeycloak {
		logger.Warn("Using legacy connection mode for Keycloak < 17.x.x")
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
	// logger.Debug(kcConfig.ClientID)
	// logger.Debug(kcConfig.ClientSecret)
	// logger.Debug(kcConfig.URL)
	// logger.Debug(kcConfig.Realm)
	token, err := client.LoginClient(ctx, kcConfig.ClientID, kcConfig.ClientSecret, kcConfig.Realm)
	if err != nil {
		logger.Error("Error connecting to keycloak!", "error", err)
		return nil, err
	}
	keycloakConnector := KeyCloakConnector{token: token, client: client}

	return &keycloakConnector, nil
}

func expandGroup(ctx context.Context, groupID string, kcConnector *KeyCloakConnector, kcConfig *KeycloakConfig, logger *logger.Logger) ([]*gocloak.User, error) {
	logger.Info("expandGroup invoked: ", groupID, kcConnector, kcConfig.URL, ctx)
	var entityRepresentations []*gocloak.User

	grp, err := kcConnector.client.GetGroup(ctx, kcConnector.token.AccessToken, kcConfig.Realm, groupID)
	if err == nil {
		grpMembers, memberErr := kcConnector.client.GetGroupMembers(ctx, kcConnector.token.AccessToken, kcConfig.Realm,
			*grp.ID, gocloak.GetGroupsParams{})
		if memberErr == nil {
			logger.Debug("Adding members", "amount", len(grpMembers), "from group", *grp.Name)
			for i := 0; i < len(grpMembers); i++ {
				user := grpMembers[i]
				entityRepresentations = append(entityRepresentations, user)
			}
		} else {
			logger.Error("Error getting group members", "error", memberErr)
		}
	} else {
		logger.Error("Error getting group", "error", err)
		return nil, err
	}
	return entityRepresentations, nil
}

func getEntitiesFromToken(ctx context.Context, kcConfig KeycloakConfig, jwtString string, logger *logger.Logger) ([]*authorization.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, errors.New("error parsing jwt " + err.Error())
	}
	claims, err := token.AsMap(context.Background()) ///nolint:contextcheck // Do not want to include keys from context in map
	if err != nil {
		return nil, errors.New("error getting claims from jwt")
	}
	var entities = []*authorization.Entity{}
	var entityID = 0

	// extract azp
	extractedValue, okExtract := claims[ClientJwtSelector]
	if !okExtract {
		return nil, errors.New("error extracting selector " + ClientJwtSelector + " from jwt")
	}
	extractedValueCasted, okCast := extractedValue.(string)
	if !okCast {
		return nil, errors.New("error casting extracted value to string")
	}
	entities = append(entities, &authorization.Entity{EntityType: &authorization.Entity_ClientId{ClientId: extractedValueCasted}, Id: fmt.Sprintf("jwtentity-%d", entityID)})
	entityID++

	// extract preferred_username if client isnt present
	_, okExtractConditional := claims[UsernameConditionalSelector]
	if !okExtractConditional { //nolint:nestif // this case has many possible outcomes to handle
		extractedValueUsername, okExp := claims[UsernameJwtSelector]
		if !okExp {
			return nil, errors.New("error extracting selector " + UsernameJwtSelector + " from jwt")
		}
		extractedValueUsernameCasted, okUsernameCast := extractedValueUsername.(string)
		if !okUsernameCast {
			return nil, errors.New("error casting extracted value to string")
		}

		// double check for service account
		if strings.HasPrefix(extractedValueUsernameCasted, serviceAccountUsernamePrefix) {
			clientid, err := getServiceAccountClient(ctx, extractedValueUsernameCasted, kcConfig, logger)
			if err != nil {
				return nil, err
			}
			if clientid != "" {
				entities = append(entities, &authorization.Entity{EntityType: &authorization.Entity_ClientId{ClientId: clientid}, Id: fmt.Sprintf("jwtentity-%d", entityID)})
			} else {
				// if the returned clientId is empty, no client found, its not a serive account proceed with username
				entities = append(entities, &authorization.Entity{EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted}, Id: fmt.Sprintf("jwtentity-%d", entityID)})
			}
		} else {
			entities = append(entities, &authorization.Entity{EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted}, Id: fmt.Sprintf("jwtentity-%d", entityID)})
		}
	} else {
		logger.Debug("Did not find conditional value " + UsernameConditionalSelector + " in jwt, proceed")
	}

	return entities, nil
}

func getServiceAccountClient(ctx context.Context, username string, kcConfig KeycloakConfig, logger *logger.Logger) (string, error) {
	connector, err := getKCClient(ctx, kcConfig, logger)
	if err != nil {
		return "", err
	}
	expectedClientName := strings.TrimPrefix(username, serviceAccountUsernamePrefix)

	clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
		ClientID: &expectedClientName,
	})
	switch {
	case err != nil:
		logger.Error(err.Error())
		return "", err
	case len(clients) == 1:
		client := clients[0]
		logger.Debug("Client found", "client", *client.ClientID)
		return *client.ClientID, nil
	case len(clients) > 1:
		logger.Error("More than one client found for ", "clientid", expectedClientName)
	default:
		logger.Debug("No client found, likely not a service account", "clientid", expectedClientName)
	}

	return "", nil
}

func entityToStructPb(ident *authorization.Entity) (*structpb.Struct, error) {
	entityBytes, err := protojson.Marshal(ident)
	if err != nil {
		return nil, err
	}
	var entityStruct structpb.Struct
	err = entityStruct.UnmarshalJSON(entityBytes)
	if err != nil {
		return nil, err
	}
	return &entityStruct, nil
}
