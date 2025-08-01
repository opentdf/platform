//nolint:sloglint // v1 entityresolution will be deprecated soon
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/Nerzal/gocloak/v13"
	"github.com/creasty/defaults"
	"github.com/go-viper/mapstructure/v2"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
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

type KeycloakEntityResolutionService struct { //nolint:revive // Too late! Already exported
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig KeycloakConfig
	logger    *logger.Logger
	trace.Tracer
	connector   *KeyCloakConnector
	connectorMu sync.Mutex
	svcCache    *cache.Cache
}

type KeycloakConfig struct { //nolint:revive // yeah but what if we want to embed multiple configs?
	URL            string                 `mapstructure:"url" json:"url"`
	Realm          string                 `mapstructure:"realm" json:"realm"`
	ClientID       string                 `mapstructure:"clientid" json:"clientid"`
	ClientSecret   string                 `mapstructure:"clientsecret" json:"clientsecret"`
	LegacyKeycloak bool                   `mapstructure:"legacykeycloak" json:"legacykeycloak" default:"false"`
	SubGroups      bool                   `mapstructure:"subgroups" json:"subgroups" default:"false"`
	InferID        InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
	TokenBuffer    time.Duration          `mapstructure:"token_buffer_seconds" json:"token_buffer_seconds" default:"120s"`
}

func RegisterKeycloakERS(config config.ServiceConfig, logger *logger.Logger, svcCache *cache.Cache) (*KeycloakEntityResolutionService, serviceregistry.HandlerServer) {
	var inputIdpConfig KeycloakConfig

	if err := defaults.Set(&inputIdpConfig); err != nil {
		logger.Error("Failed to set Keycloak default configuration", "error", err)
		log.Fatalf("Failed to set Keycloak default configuration: %v", err)
	}

	if err := mapstructure.Decode(config, &inputIdpConfig); err != nil {
		logger.Error("Failed to decode Keycloak configuration", "error", err)
		log.Fatalf("Failed to decode Keycloak configuration: %v", err)
	}
	logger.Debug("entity_resolution configuration", "config", inputIdpConfig)
	keycloakSVC := &KeycloakEntityResolutionService{idpConfig: inputIdpConfig, logger: logger, svcCache: svcCache}
	return keycloakSVC, nil
}

func (s *KeycloakEntityResolutionService) ResolveEntities(ctx context.Context, req *connect.Request[entityresolution.ResolveEntitiesRequest]) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "ResolveEntities")
	defer span.End()

	connector, err := s.getConnector(ctx, s.idpConfig.TokenBuffer)
	if err != nil {
		s.logger.ErrorContext(ctx, "error getting keycloak connector", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("%w: %w", ErrCreationFailed, err))
	}
	resp, err := EntityResolution(ctx, req.Msg, s.idpConfig, connector, s.logger)

	return connect.NewResponse(&resp), err
}

func (s *KeycloakEntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *connect.Request[entityresolution.CreateEntityChainFromJwtRequest]) (*connect.Response[entityresolution.CreateEntityChainFromJwtResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	connector, err := s.getConnector(ctx, s.idpConfig.TokenBuffer)
	if err != nil {
		s.logger.ErrorContext(ctx, "error getting keycloak connector", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("%w: %w", ErrCreationFailed, err))
	}
	resp, err := CreateEntityChainFromJwt(ctx, req.Msg, s.idpConfig, connector, s.logger)

	return connect.NewResponse(&resp), err
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

type KeyCloakConnector struct { //nolint:revive // Too late! Already exported
	token     *gocloak.JWT
	client    *gocloak.GoCloak
	expiresAt time.Time
}

func CreateEntityChainFromJwt(
	ctx context.Context,
	req *entityresolution.CreateEntityChainFromJwtRequest,
	kcConfig KeycloakConfig,
	connector *KeyCloakConnector,
	logger *logger.Logger,
) (entityresolution.CreateEntityChainFromJwtResponse, error) {
	entityChains := []*authorization.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(ctx, kcConfig, tok.GetJwt(), connector, logger)
		if err != nil {
			return entityresolution.CreateEntityChainFromJwtResponse{}, err
		}
		entityChains = append(entityChains, &authorization.EntityChain{Id: tok.GetId(), Entities: entities})
	}

	return entityresolution.CreateEntityChainFromJwtResponse{EntityChains: entityChains}, nil
}

func EntityResolution(ctx context.Context,
	req *entityresolution.ResolveEntitiesRequest, kcConfig KeycloakConfig, connector *KeyCloakConnector, logger *logger.Logger,
) (entityresolution.ResolveEntitiesResponse, error) {
	payload := req.GetEntities()

	var resolvedEntities []*entityresolution.EntityRepresentation

	for idx, ident := range payload {
		logger.Debug("lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			logger.Debug("looking up", slog.Any("type", ident.GetEntityType()), slog.String("client_id", ident.GetClientId()))
			clientID := ident.GetClientId()
			clients, err := connector.client.GetClients(ctx, connector.token.AccessToken, kcConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				logger.Error("error getting client info", slog.String("error", err.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client, logger)
				if err != nil {
					logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
					return entityresolution.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				mystruct, structErr := structpb.NewStruct(json)
				if structErr != nil {
					logger.Error("error making struct!", slog.String("error", structErr.Error()))
					return entityresolution.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			if len(clients) == 0 && kcConfig.InferID.From.ClientID {
				// convert entity to json
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					logger.Error("unable to make entity struct", slog.String("error", err.Error()))
					return entityresolution.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, entityStruct)
			}
			// make sure the id field is populated
			originialID := ident.GetId()
			if originialID == "" {
				originialID = entity.EntityIDPrefix + strconv.Itoa(idx)
			}
			resolvedEntities = append(
				resolvedEntities,
				&entityresolution.EntityRepresentation{
					OriginalId:      originialID,
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
				connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			logger.Debug("user found", slog.String("user", *user.ID), slog.String("entity", ident.String()))
			logger.Debug("user", slog.Any("details", user))
			logger.Debug("user", slog.Any("attributes", user.Attributes))
			keycloakEntities = append(keycloakEntities, user)
		default:
			logger.Error("no user found for", slog.Any("entity", ident))
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
					logger.Error("error getting group", slog.String("group", groupErr.Error()))
					return entityresolution.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
				case len(groups) == 1:
					logger.Info("group found for", slog.String("entity", ident.String()))
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(ctx, *group.ID, connector, &kcConfig, logger)
					if exErr != nil {
						return entityresolution.ResolveEntitiesResponse{},
							connect.NewError(connect.CodeNotFound, ErrNotFound)
					}
					keycloakEntities = expandedRepresentations
				default:
					logger.Error("no group found for", slog.String("entity", ident.String()))
					var entityNotFoundErr entityresolution.EntityNotFoundError
					switch ident.GetEntityType().(type) {
					case *authorization.Entity_EmailAddress:
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(connect.CodeNotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetEmailAddress()}
					case *authorization.Entity_UserName:
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(connect.CodeNotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetUserName()}
					// case "":
					// 	return &entityresolution.IdpPluginResponse{},
					// 		status.Error(codes.InvalidArgument, db.ErrTextNotFound)
					default:
						logger.Error("unsupported/unknown type for", slog.String("entity", ident.String()))
						entityNotFoundErr = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.String()}
					}
					logger.Error(entityNotFoundErr.String())
					if kcConfig.InferID.From.Email || kcConfig.InferID.From.Username {
						// user not found -- add json entity to resp instead
						entityStruct, err := entityToStructPb(ident)
						if err != nil {
							logger.Error("unable to make entity struct from email or username", slog.String("error", err.Error()))
							return entityresolution.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
						}
						jsonEntities = append(jsonEntities, entityStruct)
					} else {
						return entityresolution.ResolveEntitiesResponse{}, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
					}
				}
			} else if ident.GetUserName() != "" {
				if kcConfig.InferID.From.Username {
					// user not found -- add json entity to resp instead
					entityStruct, err := entityToStructPb(ident)
					if err != nil {
						logger.Error("unable to make entity struct from username", slog.String("error", err.Error()))
						return entityresolution.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
					}
					jsonEntities = append(jsonEntities, entityStruct)
				} else {
					entityNotFoundErr := entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetUserName()}
					return entityresolution.ResolveEntitiesResponse{}, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
				}
			}
		}

		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er, logger)
			if err != nil {
				logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrCreationFailed)
			}
			mystruct, structErr := structpb.NewStruct(json)
			if structErr != nil {
				logger.Error("error making struct!", slog.String("error", structErr.Error()))
				return entityresolution.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrCreationFailed)
			}
			jsonEntities = append(jsonEntities, mystruct)
		}
		// make sure the id field is populated
		originialID := ident.GetId()
		if originialID == "" {
			originialID = entity.EntityIDPrefix + strconv.Itoa(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      originialID,
				AdditionalProps: jsonEntities,
			},
		)
		logger.Debug("entities", slog.Any("resolved", resolvedEntities))
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

func getEntitiesFromToken(ctx context.Context, kcConfig KeycloakConfig, jwtString string, connector *KeyCloakConnector, logger *logger.Logger) ([]*authorization.Entity, error) {
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
		Id:         fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, extractedValueCasted),
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
		clientid, err := getServiceAccountClient(ctx, extractedValueUsernameCasted, kcConfig, connector, logger)
		if err != nil {
			return nil, err
		}
		if clientid != "" {
			entities = append(entities, &authorization.Entity{
				EntityType: &authorization.Entity_ClientId{ClientId: clientid},
				Id:         fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, clientid),
				Category:   authorization.Entity_CATEGORY_SUBJECT,
			})
		} else {
			// if the returned clientId is empty, no client found, its not a serive account proceed with username
			entities = append(entities, &authorization.Entity{
				EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted},
				Id:         fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
				Category:   authorization.Entity_CATEGORY_SUBJECT,
			})
		}
	} else {
		entities = append(entities, &authorization.Entity{
			EntityType: &authorization.Entity_UserName{UserName: extractedValueUsernameCasted},
			Id:         fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
			Category:   authorization.Entity_CATEGORY_SUBJECT,
		})
	}

	return entities, nil
}

func getServiceAccountClient(ctx context.Context, username string, kcConfig KeycloakConfig, connector *KeyCloakConnector, logger *logger.Logger) (string, error) {
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

// getConnector ensures a valid Keycloak connector is available, refreshing the token if necessary.
func (s *KeycloakEntityResolutionService) getConnector(ctx context.Context, tokenBuffer time.Duration) (*KeyCloakConnector, error) {
	s.connectorMu.Lock()
	defer s.connectorMu.Unlock()

	// Refresh token if it's nil, expired, or about to expire.

	if s.connector == nil || s.connector.token == nil || time.Now().After(s.connector.expiresAt.Add(-tokenBuffer)) {
		s.logger.InfoContext(ctx, "Keycloak connector is nil or token expired/expiring soon. Fetching new token.")

		var gocloakClient *gocloak.GoCloak
		if s.idpConfig.LegacyKeycloak {
			s.logger.WarnContext(ctx, "Using legacy connection mode for Keycloak < 17.x.x")
			gocloakClient = gocloak.NewClient(s.idpConfig.URL)
		} else {
			gocloakClient = gocloak.NewClient(s.idpConfig.URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
		}

		token, err := gocloakClient.LoginClient(ctx, s.idpConfig.ClientID, s.idpConfig.ClientSecret, s.idpConfig.Realm)
		if err != nil {
			s.logger.ErrorContext(ctx, "Error connecting to Keycloak or logging in", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to login to Keycloak: %w", err)
		}

		s.connector = &KeyCloakConnector{
			token:     token,
			client:    gocloakClient,
			expiresAt: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		}
		s.logger.InfoContext(ctx, "Successfully fetched new Keycloak token.", "expires_in_seconds", token.ExpiresIn)
	} else {
		s.logger.DebugContext(ctx, "Using existing Keycloak token.")
	}
	return s.connector, nil
}
