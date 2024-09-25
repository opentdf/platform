package entityresolution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	auth "github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	ErrTextCreationFailed     = "resource creation failed"
	ErrTextGetRetrievalFailed = "resource retrieval failed"
	ErrTextNotFound           = "resource not found"
)

const (
	ClientJwtSelector   = "azp"
	UsernameJwtSelector = "preferred_username"
)

const serviceAccountUsernamePrefix = "service-account-"

type KeycloakConfig struct {
	URL            string                 `mapstructure:"url" json:"url"`
	Realm          string                 `mapstructure:"realm" json:"realm"`
	ClientID       string                 `mapstructure:"clientid" json:"clientid"`
	ClientSecret   string                 `mapstructure:"clientsecret" json:"clientsecret"`
	LegacyKeycloak bool                   `mapstructure:"legacykeycloak" json:"legacykeycloak" default:"false"`
	SubGroups      bool                   `mapstructure:"subgroups" json:"subgroups" default:"false"`
	InferID        InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
}

func (c KeycloakConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", c.URL),
		slog.String("realm", c.Realm),
		slog.String("clientid", c.ClientID),
		slog.String("clientsecret", "[REDACTED]"),
		slog.Bool("legacykeycloak", c.LegacyKeycloak),
		slog.Bool("subgroups", c.SubGroups),
		slog.Any("inferid", c.InferID),
	)
}

type InferredIdentityConfig struct {
	From EntityImpliedFrom `mapstructure:"from,omitempty" json:"from,omitempty"`
}

type EntityImpliedFrom struct {
	ClientID bool `mapstructure:"clientid,omitempty" json:"clientid,omitempty"`
	Email    bool `mapstructure:"email,omitempty" json:"email,omitempty"`
	Username bool `mapstructure:"username,omitempty" json:"username,omitempty"`
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
	entityChains := []*authorization.EntityChain{}
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
	req *entityresolution.ResolveEntitiesRequest, kcConfig KeycloakConfig, logger *logger.Logger,
) (entityresolution.ResolveEntitiesResponse, error) {

	logger.InfoContext(ctx, "Starting EntityResolution", slog.Any("Request", req), slog.Any("KeycloakConfig", kcConfig))

	connector, err := getKCClient(ctx, kcConfig, logger)
	if err != nil {
		logger.Error("Failed to get KC client", slog.String("error", err.Error()))
		return entityresolution.ResolveEntitiesResponse{},
			status.Error(codes.Internal, ErrTextCreationFailed)
	}

	payload := req.GetEntities()
	logger.InfoContext(ctx, "Entity Payload", slog.Any("entities", payload))

	var resolvedEntities []*entityresolution.EntityRepresentation

	for idx, ident := range payload {
		logger.InfoContext(ctx, "Processing entity", slog.Int("index", idx), slog.Any("entity", ident.GetEntityType()))

		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		var jsonEntities []*structpb.Struct // This is now initialized here

		switch ident.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			clientID := ident.GetClientId()
			logger.InfoContext(ctx, "Looking up client", slog.String("client_id", clientID))

			clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				logger.Error("Error getting client info", slog.String("error", err.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextGetRetrievalFailed)
			}

			logger.InfoContext(ctx, "Clients found", slog.Any("clients", clients))

		case *authorization.Entity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
			logger.InfoContext(ctx, "Looking up by email", slog.String("email", ident.GetEmailAddress()))

		case *authorization.Entity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
			logger.InfoContext(ctx, "Looking up by username", slog.String("username", ident.GetUserName()))
		}

		users, err := connector.client.GetUsers(ctx, connector.token.AccessToken, kcConfig.Realm, getUserParams)
		logger.InfoContext(ctx, "Users found", slog.Any("users", users), slog.Any("error", err))

		switch {
		case err != nil:
			logger.Error("Error retrieving users", slog.String("error", err.Error()))
			return entityresolution.ResolveEntitiesResponse{},
				status.Error(codes.Internal, ErrTextGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			logger.InfoContext(ctx, "User found", slog.String("user_id", *user.ID), slog.String("user", ident.String()))
			keycloakEntities = append(keycloakEntities, user)

		default:
			logger.WarnContext(ctx, "No user found for entity", slog.Any("entity", ident))
			// Additional group lookup logic goes here
		}

		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er, logger)
			if err != nil {
				logger.Error("Error serializing entity representation", slog.String("error", err.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}

			mystruct, structErr := structpb.NewStruct(json)
			if structErr != nil {
				logger.Error("Error creating struct", slog.String("error", structErr.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					status.Error(codes.Internal, ErrTextCreationFailed)
			}

			jsonEntities = append(jsonEntities, mystruct)
		}

		// Ensure ID is populated
		originalID := ident.GetId()
		if originalID == "" {
			originalID = auth.EntityIDPrefix + fmt.Sprint(idx)
		}

		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      originalID,
				AdditionalProps: jsonEntities,
			},
		)
		logger.InfoContext(ctx, "Resolved entity", slog.Any("resolvedEntity", resolvedEntities))
	}

	return entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

func typeToGenericJSONMap[Marshalable any](inputStruct Marshalable, logger *logger.Logger) (map[string]interface{}, error) {
	// For now, since we dont' know the "shape" of the entity/user record or representation we will get from a specific entity store,
	tmpDoc, err := json.Marshal(inputStruct)
	if err != nil {
		logger.Error("error marshalling input type!", slog.String("error", err.Error()))
		return nil, err
	}

	var genericMap map[string]interface{}
	err = json.Unmarshal(tmpDoc, &genericMap)
	if err != nil {
		logger.Error("could not deserialize generic entitlement context JSON input document!", slog.String("error", err.Error()))
		return nil, err
	}

	return genericMap, nil
}

func getKCClient(ctx context.Context, kcConfig KeycloakConfig, logger *logger.Logger) (*KeyCloakConnector, error) {
	var client *gocloak.GoCloak
	if kcConfig.LegacyKeycloak {
		logger.Warn("using legacy connection mode for Keycloak < 17.x.x")
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
		logger.Error("error connecting to keycloak!", slog.String("error", err.Error()))
		return nil, err
	}
	keycloakConnector := KeyCloakConnector{token: token, client: client}

	return &keycloakConnector, nil
}

func expandGroup(ctx context.Context, groupID string, kcConnector *KeyCloakConnector, kcConfig *KeycloakConfig, logger *logger.Logger) ([]*gocloak.User, error) {
	logger.Info("expanding group", slog.String("groupID", groupID))
	var entityRepresentations []*gocloak.User

	grp, err := kcConnector.client.GetGroup(ctx, kcConnector.token.AccessToken, kcConfig.Realm, groupID)
	if err == nil {
		grpMembers, memberErr := kcConnector.client.GetGroupMembers(ctx, kcConnector.token.AccessToken, kcConfig.Realm,
			*grp.ID, gocloak.GetGroupsParams{})
		if memberErr == nil {
			logger.Debug("adding members", slog.Int("amount", len(grpMembers)), slog.String("from group", *grp.Name))
			for i := 0; i < len(grpMembers); i++ {
				user := grpMembers[i]
				entityRepresentations = append(entityRepresentations, user)
			}
		} else {
			logger.Error("error getting group members", slog.String("error", memberErr.Error()))
		}
	} else {
		logger.Error("error getting group", slog.String("error", err.Error()))
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
	entities := []*authorization.Entity{}
	entityID := 0

	// extract azp
	extractedValue, okExtract := claims[ClientJwtSelector]
	if !okExtract {
		return nil, errors.New("error extracting selector " + ClientJwtSelector + " from jwt")
	}
	extractedValueCasted, okCast := extractedValue.(string)
	if !okCast {
		return nil, errors.New("error casting extracted value to string")
	}
	entities = append(entities, &authorization.Entity{
		EntityType: &authorization.Entity_ClientId{ClientId: extractedValueCasted},
		Id:         fmt.Sprintf("jwtentity-%d", entityID),
		Category:   authorization.Entity_CATEGORY_ENVIRONMENT,
	})
	entityID++

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
			entities = append(entities, &authorization.Entity{
				EntityType: &authorization.Entity_ClientId{ClientId: clientid},
				Id:         fmt.Sprintf("jwtentity-%d", entityID),
				Category:   authorization.Entity_CATEGORY_SUBJECT,
			})
		} else {
			// if the returned clientId is empty, no client found, its not a serive account proceed with username
			entities = append(entities, &authorization.Entity{
				EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted},
				Id:         fmt.Sprintf("jwtentity-%d", entityID),
				Category:   authorization.Entity_CATEGORY_SUBJECT,
			})
		}
	} else {
		entities = append(entities, &authorization.Entity{
			EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted},
			Id:         fmt.Sprintf("jwtentity-%d", entityID),
			Category:   authorization.Entity_CATEGORY_SUBJECT,
		})
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
		logger.Debug("client found", slog.String("client", *client.ClientID))
		return *client.ClientID, nil
	case len(clients) > 1:
		logger.Error("more than one client found for ", slog.String("clientid", expectedClientName))
	default:
		logger.Debug("no client found, likely not a service account", slog.String("clientid", expectedClientName))
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
