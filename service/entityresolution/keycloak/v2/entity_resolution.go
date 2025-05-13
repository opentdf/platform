package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/Nerzal/gocloak/v13"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	auth "github.com/opentdf/platform/service/authorization"
	keycloakV1 "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	ErrCreationFailed     = errors.New("resource creation failed")
	ErrGetRetrievalFailed = errors.New("resource retrieval failed")
	ErrNotFound           = errors.New("resource not found")
)

const (
	ClientJwtSelector   = "azp"
	UsernameJwtSelector = "preferred_username"
)

const serviceAccountUsernamePrefix = "service-account-"

// EntityType constants for clearer type checking
const (
	EntityTypeEmail    = "email"
	EntityTypeUsername = "username"
	EntityTypeClientID = "clientid"
)

type KeycloakEntityResolutionService struct {
	ersV2.UnimplementedEntityResolutionServiceServer
	idpConfig keycloakV1.KeycloakConfig
	logger    *logger.Logger
	trace.Tracer
}

func RegisterKeycloakERS(config config.ServiceConfig, logger *logger.Logger) (*KeycloakEntityResolutionService, serviceregistry.HandlerServer) {
	var inputIdpConfig keycloakV1.KeycloakConfig
	if err := mapstructure.Decode(config, &inputIdpConfig); err != nil {
		panic(err)
	}
	logger.Debug("entity_resolution configuration", "config", inputIdpConfig)
	keycloakSVC := &KeycloakEntityResolutionService{idpConfig: inputIdpConfig, logger: logger}
	return keycloakSVC, nil
}

func (s KeycloakEntityResolutionService) ResolveEntities(ctx context.Context, req *connect.Request[ersV2.ResolveEntitiesRequest]) (*connect.Response[ersV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "ResolveEntities")
	defer span.End()

	resp, err := EntityResolution(ctx, req.Msg, s.idpConfig, s.logger)
	return connect.NewResponse(resp), err
}

func (s KeycloakEntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *connect.Request[ersV2.CreateEntityChainFromJwtRequest]) (*connect.Response[ersV2.CreateEntityChainFromJwtResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	resp, err := CreateEntityChainFromJwt(ctx, req.Msg, s.idpConfig, s.logger)
	return connect.NewResponse(resp), err
}

func (s KeycloakEntityResolutionService) CreateEntityChainFromJwtMulti(ctx context.Context, req *connect.Request[ersV2.CreateEntityChainFromJwtMultiRequest]) (*connect.Response[ersV2.CreateEntityChainFromJwtMultiResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	resp, err := CreateEntityChainFromJwtMulti(ctx, req.Msg, s.idpConfig, s.logger)
	return connect.NewResponse(resp), err
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

// errorHandler provides a centralized way to handle service errors with logging
func errorHandler(ctx context.Context, logger *logger.Logger, code connect.Code, err error, msg string) error {
	logger.ErrorContext(ctx, msg, slog.String("error", err.Error()))
	return connect.NewError(code, err)
}

func CreateEntityChainFromJwt(
	ctx context.Context,
	req *ersV2.CreateEntityChainFromJwtRequest,
	kcConfig keycloakV1.KeycloakConfig,
	logger *logger.Logger,
) (*ersV2.CreateEntityChainFromJwtResponse, error) {
	tok := req.GetToken()
	// for each token in the tokens form an entity chain
	entities, err := getEntitiesFromToken(ctx, kcConfig, tok.GetJwt(), logger)
	if err != nil {
		return nil, err
	}
	entityChain := &authz.EntityChain{EphemeralChainId: tok.GetId(), Entities: entities}

	return &ersV2.CreateEntityChainFromJwtResponse{EntityChains: entityChain}, nil
}
func CreateEntityChainFromJwtMulti(
	ctx context.Context,
	req *ersV2.CreateEntityChainFromJwtMultiRequest,
	kcConfig keycloakV1.KeycloakConfig,
	logger *logger.Logger,
) (*ersV2.CreateEntityChainFromJwtMultiResponse, error) {
	tokens := req.GetToken()
	entityChains := make([]*authz.EntityChain, 0, len(tokens))
	// for each token in the tokens form an entity chain
	for idx, tok := range tokens {
		entities, err := getEntitiesFromToken(ctx, kcConfig, tok.GetJwt(), logger)
		if err != nil {
			return nil, err
		}
		entityChains[idx] = &authz.EntityChain{EphemeralChainId: tok.GetId(), Entities: entities}
	}

	return &ersV2.CreateEntityChainFromJwtMultiResponse{EntityChains: entityChains}, nil
}

func EntityResolution(ctx context.Context,
	req *ersV2.ResolveEntitiesRequest, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger,
) (*ersV2.ResolveEntitiesResponse, error) {
	connector, err := getKCClient(ctx, kcConfig, logger)
	if err != nil {
		return nil,
			connect.NewError(connect.CodeInternal, ErrCreationFailed)
	}
	payload := req.GetEntitiesV2()

	var resolvedEntities []*entityresolution.EntityRepresentation

	for idx, ident := range payload {
		logger.Debug("lookup", "entity", ident.GetEntityType())
		switch ident.GetEntityType().(type) {
		case *authz.Entity_ClientId:
			entityRep, err := handleClientIDResolution(ctx, ident, idx, connector, kcConfig, logger)
			if err != nil {
				return nil, err
			}
			resolvedEntities = append(resolvedEntities, entityRep)
		case *authz.Entity_EmailAddress, *authz.Entity_UserName:
			entityRep, err := handleUserResolution(ctx, ident, idx, connector, kcConfig, logger)
			if err != nil {
				return nil, err
			}
			resolvedEntities = append(resolvedEntities, entityRep)
		}
		logger.Debug("entities", slog.Any("resolved", resolvedEntities))
	}

	return &ersV2.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

// handleClientIDResolution specifically handles ClientID resolution
func handleClientIDResolution(ctx context.Context, ident *authz.Entity, idx int, connector *KeyCloakConnector, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger) (*entityresolution.EntityRepresentation, error) {
	logger.Debug("looking up", slog.Any("type", ident.GetEntityType()), slog.String("client_id", ident.GetClientId()))
	clientID := ident.GetClientId()
	clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
		ClientID: &clientID,
	})
	if err != nil {
		logger.Error("error getting client info", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
	}

	var jsonEntities []*structpb.Struct
	for _, client := range clients {
		json, err := typeToGenericJSONMap(client, logger)
		if err != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "error serializing entity representation")
		}
		mystruct, structErr := structpb.NewStruct(json)
		if structErr != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, structErr, "error making struct")
		}
		jsonEntities = append(jsonEntities, mystruct)
	}

	if len(clients) == 0 && kcConfig.InferID.From.ClientID {
		// convert entity to json
		entityStruct, err := entityToStructPb(ident)
		if err != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "unable to make entity struct")
		}
		jsonEntities = append(jsonEntities, entityStruct)
	}

	// make sure the id field is populated
	originalID := ident.GetEphemeralId()
	if originalID == "" {
		originalID = auth.EntityIDPrefix + strconv.Itoa(idx)
	}

	return &entityresolution.EntityRepresentation{
		OriginalId:      originalID,
		AdditionalProps: jsonEntities,
	}, nil
}

// handleUserResolution handles resolution for username and email
func handleUserResolution(ctx context.Context, ident *authz.Entity, idx int, connector *KeyCloakConnector, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger) (*entityresolution.EntityRepresentation, error) {
	var getUserParams gocloak.GetUsersParams
	exactMatch := true

	switch ident.GetEntityType().(type) {
	case *authz.Entity_EmailAddress:
		getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
	case *authz.Entity_UserName:
		getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
	}

	var jsonEntities []*structpb.Struct
	users, err := connector.client.GetUsers(ctx, connector.token.AccessToken, kcConfig.Realm, getUserParams)

	if err != nil {
		return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "error getting users")
	}

	if len(users) == 1 {
		user := users[0]
		logger.Debug("user found", slog.String("user", *user.ID), slog.String("entity", ident.String()))
		logger.Debug("user", slog.Any("details", user))
		logger.Debug("user", slog.Any("attributes", user.Attributes))

		json, err := typeToGenericJSONMap(user, logger)
		if err != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "error serializing entity representation")
		}

		mystruct, structErr := structpb.NewStruct(json)
		if structErr != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, structErr, "error making struct")
		}

		jsonEntities = append(jsonEntities, mystruct)
	} else {
		// No user found, try alternatives
		entityRep, err := handleEntityNotFound(ctx, ident, connector, kcConfig, logger)
		if err != nil {
			return nil, err
		}
		if entityRep != nil {
			jsonEntities = entityRep
		}
	}

	// Make sure the id field is populated
	originalID := ident.GetEphemeralId()
	if originalID == "" {
		originalID = auth.EntityIDPrefix + strconv.Itoa(idx)
	}

	return &entityresolution.EntityRepresentation{
		OriginalId:      originalID,
		AdditionalProps: jsonEntities,
	}, nil
}

// handleEntityNotFound handles the case when no user is found directly
func handleEntityNotFound(ctx context.Context, ident *authz.Entity, connector *KeyCloakConnector, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger) ([]*structpb.Struct, error) {
	var jsonEntities []*structpb.Struct

	if ident.GetEmailAddress() != "" {
		// Try by group
		groups, groupErr := connector.client.GetGroups(
			ctx,
			connector.token.AccessToken,
			kcConfig.Realm,
			gocloak.GetGroupsParams{Search: func() *string { t := ident.GetEmailAddress(); return &t }()},
		)

		if groupErr != nil {
			return nil, errorHandler(ctx, logger, connect.CodeInternal, groupErr, "error getting group")
		}

		if len(groups) == 1 {
			logger.Info("group found for", slog.String("entity", ident.String()))
			group := groups[0]
			expandedUsers, exErr := expandGroup(ctx, *group.ID, connector, &kcConfig, logger)
			if exErr != nil {
				return nil, connect.NewError(connect.CodeNotFound, ErrNotFound)
			}

			for _, user := range expandedUsers {
				json, err := typeToGenericJSONMap(user, logger)
				if err != nil {
					return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "error serializing entity representation")
				}

				mystruct, structErr := structpb.NewStruct(json)
				if structErr != nil {
					return nil, errorHandler(ctx, logger, connect.CodeInternal, structErr, "error making struct")
				}

				jsonEntities = append(jsonEntities, mystruct)
			}
			return jsonEntities, nil
		}

		// No group found, check if we should infer identity
		if kcConfig.InferID.From.Email {
			entityStruct, err := entityToStructPb(ident)
			if err != nil {
				return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "unable to make entity struct from email")
			}
			return []*structpb.Struct{entityStruct}, nil
		}

		// Neither user nor group found and inference not enabled
		entityNotFoundErr := entityresolution.EntityNotFoundError{
			Code:    int32(connect.CodeNotFound),
			Message: ErrGetRetrievalFailed.Error(),
			Entity:  ident.GetEmailAddress(),
		}
		return nil, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
	} else if ident.GetUserName() != "" {
		if kcConfig.InferID.From.Username {
			// User not found but inference enabled
			entityStruct, err := entityToStructPb(ident)
			if err != nil {
				return nil, errorHandler(ctx, logger, connect.CodeInternal, err, "unable to make entity struct from username")
			}
			return []*structpb.Struct{entityStruct}, nil
		}

		// User not found and inference not enabled
		entityNotFoundErr := entityresolution.EntityNotFoundError{
			Code:    int32(codes.NotFound),
			Message: ErrGetRetrievalFailed.Error(),
			Entity:  ident.GetUserName(),
		}
		return nil, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
	}

	return nil, nil
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

func getKCClient(ctx context.Context, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger) (*KeyCloakConnector, error) {
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

func expandGroup(ctx context.Context, groupID string, kcConnector *KeyCloakConnector, kcConfig *keycloakV1.KeycloakConfig, logger *logger.Logger) ([]*gocloak.User, error) {
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

func getEntitiesFromToken(ctx context.Context, kcConfig keycloakV1.KeycloakConfig, jwtString string, logger *logger.Logger) ([]*authz.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, errors.New("error parsing jwt " + err.Error())
	}
	claims, err := token.AsMap(context.Background()) ///nolint:contextcheck // Do not want to include keys from context in map
	if err != nil {
		return nil, errors.New("error getting claims from jwt")
	}
	entities := []*authz.Entity{}
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
	entities = append(entities, &authz.Entity{
		EntityType:  &authz.Entity_ClientId{ClientId: extractedValueCasted},
		EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, extractedValueCasted),
		Category:    authz.Entity_CATEGORY_ENVIRONMENT,
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
			entities = append(entities, &authz.Entity{
				EntityType:  &authz.Entity_ClientId{ClientId: clientid},
				EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, clientid),
				Category:    authz.Entity_CATEGORY_SUBJECT,
			})
		} else {
			// if the returned clientId is empty, no client found, its not a serive account proceed with username
			entities = append(entities, &authz.Entity{
				EntityType:  &authz.Entity_UserName{UserName: extractedValueUsernameCasted},
				EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
				Category:    authz.Entity_CATEGORY_SUBJECT,
			})
		}
	} else {
		entities = append(entities, &authz.Entity{
			EntityType:  &authz.Entity_UserName{UserName: extractedValueUsernameCasted},
			EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
			Category:    authz.Entity_CATEGORY_SUBJECT,
		})
	}

	return entities, nil
}

func getServiceAccountClient(ctx context.Context, username string, kcConfig keycloakV1.KeycloakConfig, logger *logger.Logger) (string, error) {
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

func entityToStructPb(ident *authz.Entity) (*structpb.Struct, error) {
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
