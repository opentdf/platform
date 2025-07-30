package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
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

type EntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	idpConfig Config
	logger    *logger.Logger
	trace.Tracer
	connector   *Connector
	connectorMu sync.Mutex
	svcCache    *cache.Cache
}

type Config struct {
	URL            string                 `mapstructure:"url" json:"url"`
	Realm          string                 `mapstructure:"realm" json:"realm"`
	ClientID       string                 `mapstructure:"clientid" json:"clientid"`
	ClientSecret   string                 `mapstructure:"clientsecret" json:"clientsecret"`
	LegacyKeycloak bool                   `mapstructure:"legacykeycloak" json:"legacykeycloak" default:"false"`
	SubGroups      bool                   `mapstructure:"subgroups" json:"subgroups" default:"false"`
	InferID        InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
	TokenBuffer    time.Duration          `mapstructure:"token_buffer_seconds" json:"token_buffer_seconds" default:"120s"`
}

func RegisterKeycloakERS(config config.ServiceConfig, logger *logger.Logger, svcCache *cache.Cache) (*EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	var inputIdpConfig Config

	if err := defaults.Set(&inputIdpConfig); err != nil {
		panic(err)
	}

	if err := mapstructure.Decode(config, &inputIdpConfig); err != nil {
		panic(err)
	}
	logger.Debug("entity_resolution configuration", slog.Any("config", inputIdpConfig))
	keycloakSVC := &EntityResolutionServiceV2{idpConfig: inputIdpConfig, logger: logger, svcCache: svcCache}
	return keycloakSVC, nil
}

func (s *EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "ResolveEntities")
	defer span.End()
	connector, err := s.getConnector(ctx, s.idpConfig.TokenBuffer)
	if err != nil {
		s.logger.ErrorContext(ctx, "error getting keycloak connector", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("%w: %w", ErrCreationFailed, err))
	}
	resp, err := EntityResolution(ctx, req.Msg, s.idpConfig, connector, s.logger, s.svcCache)
	return connect.NewResponse(&resp), err
}

func (s *EntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	connector, err := s.getConnector(ctx, s.idpConfig.TokenBuffer)
	if err != nil {
		s.logger.ErrorContext(ctx, "error getting keycloak connector", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("%w: %w", ErrCreationFailed, err))
	}
	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.idpConfig, connector, s.logger, s.svcCache)
	return connect.NewResponse(&resp), err
}

func (c Config) LogValue() slog.Value {
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

type Connector struct {
	token     *gocloak.JWT
	client    *gocloak.GoCloak
	expiresAt time.Time
}

func CreateEntityChainsFromTokens(
	ctx context.Context,
	req *entityresolutionV2.CreateEntityChainsFromTokensRequest,
	kcConfig Config,
	connector *Connector,
	logger *logger.Logger,
	svcCache *cache.Cache,
) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	entityChains := []*entity.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(ctx, kcConfig, connector, tok.GetJwt(), logger, svcCache)
		if err != nil {
			return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, err
		}
		entityChains = append(entityChains, &entity.EntityChain{EphemeralId: tok.GetEphemeralId(), Entities: entities})
	}

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: entityChains}, nil
}

func EntityResolution(ctx context.Context,
	req *entityresolutionV2.ResolveEntitiesRequest, kcConfig Config, connector *Connector, logger *logger.Logger, svcCache *cache.Cache,
) (entityresolutionV2.ResolveEntitiesResponse, error) {
	payload := req.GetEntities() // connector is now passed in

	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for idx, ident := range payload {
		logger.DebugContext(ctx,
			"lookup",
			slog.Any("entity", ident.GetEntityType()),
		)

		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *entity.Entity_ClientId:
			logger.DebugContext(ctx,
				"looking up",
				slog.Any("type", ident.GetEntityType()),
				slog.String("client_id", ident.GetClientId()),
			)

			clientID := ident.GetClientId()
			clients, err := retrieveClients(ctx, logger, clientID, kcConfig.Realm, svcCache, connector)
			if err != nil {
				logger.Error("error getting client info", slog.String("error", err.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client, logger)
				if err != nil {
					logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				mystruct, structErr := structpb.NewStruct(json)
				if structErr != nil {
					logger.Error("error making struct!", slog.String("error", structErr.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			if len(clients) == 0 && kcConfig.InferID.From.ClientID {
				// convert entity to json
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					logger.Error("unable to make entity struct", slog.String("error", err.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, entityStruct)
			}
			// make sure the id field is populated
			originialID := ident.GetEphemeralId()
			if originialID == "" {
				originialID = ent.EntityIDPrefix + strconv.Itoa(idx)
			}
			resolvedEntities = append(
				resolvedEntities,
				&entityresolutionV2.EntityRepresentation{
					OriginalId:      originialID,
					AdditionalProps: jsonEntities,
				},
			)
			continue
		case *entity.Entity_EmailAddress:
			getUserParams = gocloak.GetUsersParams{Email: func() *string { t := ident.GetEmailAddress(); return &t }(), Exact: &exactMatch}
		case *entity.Entity_UserName:
			getUserParams = gocloak.GetUsersParams{Username: func() *string { t := ident.GetUserName(); return &t }(), Exact: &exactMatch}
		}

		var jsonEntities []*structpb.Struct
		users, err := retrieveUsers(ctx, logger, getUserParams, kcConfig.Realm, svcCache, connector)
		switch {
		case err != nil:
			logger.ErrorContext(ctx, "error getting users", slog.Any("error", err))
			return entityresolutionV2.ResolveEntitiesResponse{},
				connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			logger.DebugContext(ctx,
				"user",
				slog.Any("details", user),
				slog.String("entity", ident.String()),
			)
			keycloakEntities = append(keycloakEntities, user)
		default:
			logger.ErrorContext(ctx, "no user found", slog.Any("entity", ident))
			if ident.GetEmailAddress() != "" { //nolint:nestif // this case has many possible outcomes to handle
				// try by group
				groups, groupErr := retrieveGroupsByEmail(ctx, logger, ident.GetEmailAddress(), kcConfig.Realm, svcCache, connector)
				switch {
				case groupErr != nil:
					logger.Error("error getting group", slog.String("group", groupErr.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
				case len(groups) == 1:
					logger.Info("group found for", slog.String("entity", ident.String()))
					group := groups[0]
					expandedRepresentations, exErr := expandGroup(ctx, *group.ID, connector, &kcConfig, logger, svcCache)
					if exErr != nil {
						return entityresolutionV2.ResolveEntitiesResponse{},
							connect.NewError(connect.CodeNotFound, ErrNotFound)
					}
					keycloakEntities = expandedRepresentations
				default:
					logger.ErrorContext(ctx, "no group found for", slog.String("entity", ident.String()))
					var entityNotFoundErr entityresolutionV2.EntityNotFoundError
					switch ident.GetEntityType().(type) {
					case *entity.Entity_EmailAddress:
						entityNotFoundErr = entityresolutionV2.EntityNotFoundError{Code: int32(connect.CodeNotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetEmailAddress()}
					case *entity.Entity_UserName:
						entityNotFoundErr = entityresolutionV2.EntityNotFoundError{Code: int32(connect.CodeNotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetUserName()}
					// case "":
					// 	return &entityresolutionV2.IdpPluginResponse{},
					// 		status.Error(codes.InvalidArgument, db.ErrTextNotFound)
					default:
						logger.ErrorContext(ctx, "unsupported/unknown type for", slog.String("entity", ident.String()))
						entityNotFoundErr = entityresolutionV2.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.String()}
					}
					logger.ErrorContext(ctx, "entity not found", slog.String("error", entityNotFoundErr.String()))

					if kcConfig.InferID.From.Email || kcConfig.InferID.From.Username {
						// user not found -- add json entity to resp instead
						entityStruct, err := entityToStructPb(ident)
						if err != nil {
							logger.Error("unable to make entity struct from email or username", slog.String("error", err.Error()))
							return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
						}
						jsonEntities = append(jsonEntities, entityStruct)
					} else {
						return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
					}
				}
			} else if ident.GetUserName() != "" {
				if kcConfig.InferID.From.Username {
					// user not found -- add json entity to resp instead
					entityStruct, err := entityToStructPb(ident)
					if err != nil {
						logger.Error("unable to make entity struct from username", slog.String("error", err.Error()))
						return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
					}
					jsonEntities = append(jsonEntities, entityStruct)
				} else {
					entityNotFoundErr := entityresolutionV2.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.GetUserName()}
					return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
				}
			}
		}

		for _, er := range keycloakEntities {
			json, err := typeToGenericJSONMap(er, logger)
			if err != nil {
				logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrCreationFailed)
			}
			mystruct, structErr := structpb.NewStruct(json)
			if structErr != nil {
				logger.Error("error making struct!", slog.String("error", structErr.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrCreationFailed)
			}
			jsonEntities = append(jsonEntities, mystruct)
		}
		// make sure the id field is populated
		originialID := ident.GetEphemeralId()
		if originialID == "" {
			originialID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolutionV2.EntityRepresentation{
				OriginalId:      originialID,
				AdditionalProps: jsonEntities,
			},
		)
		logger.Debug("entities", slog.Any("resolved", resolvedEntities))
	}

	return entityresolutionV2.ResolveEntitiesResponse{
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

func expandGroup(ctx context.Context, groupID string, kcConnector *Connector, kcConfig *Config, logger *logger.Logger, svcCache *cache.Cache) ([]*gocloak.User, error) {
	logger.Info("expanding group", slog.String("group_id", groupID))
	var entityRepresentations []*gocloak.User

	grp, err := retrieveGroupByID(ctx, logger, groupID, kcConfig.Realm, svcCache, kcConnector)
	if err == nil {
		grpMembers, memberErr := retrieveGroupMembers(ctx, logger, *grp.ID, kcConfig.Realm, svcCache, kcConnector)
		if memberErr == nil {
			logger.DebugContext(ctx,
				"adding members",
				slog.Int("amount", len(grpMembers)),
				slog.String("from group", *grp.Name),
			)
			for i := 0; i < len(grpMembers); i++ {
				user := grpMembers[i]
				entityRepresentations = append(entityRepresentations, user)
			}
		} else {
			logger.ErrorContext(ctx, "error getting group members", slog.String("error", memberErr.Error()))
		}
	} else {
		logger.ErrorContext(ctx, "error getting group", slog.String("error", err.Error()))
		return nil, err
	}
	return entityRepresentations, nil
}

func getEntitiesFromToken(ctx context.Context, kcConfig Config, connector *Connector, jwtString string, logger *logger.Logger, svcCache *cache.Cache) ([]*entity.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, errors.New("error parsing jwt " + err.Error())
	}
	claims, err := token.AsMap(context.Background()) ///nolint:contextcheck // Do not want to include keys from context in map
	if err != nil {
		return nil, errors.New("error getting claims from jwt")
	}
	entities := []*entity.Entity{}
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
	entities = append(entities, &entity.Entity{
		EntityType:  &entity.Entity_ClientId{ClientId: extractedValueCasted},
		EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, extractedValueCasted),
		Category:    entity.Entity_CATEGORY_ENVIRONMENT,
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
		clientid, err := getServiceAccountClient(ctx, extractedValueUsernameCasted, kcConfig, connector, logger, svcCache)
		if err != nil {
			return nil, err
		}
		if clientid != "" {
			entities = append(entities, &entity.Entity{
				EntityType:  &entity.Entity_ClientId{ClientId: clientid},
				EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, clientid),
				Category:    entity.Entity_CATEGORY_SUBJECT,
			})
		} else {
			// if the returned clientId is empty, no client found, its not a serive account proceed with username
			entities = append(entities, &entity.Entity{
				EntityType:  &entity.Entity_UserName{UserName: extractedValueUsernameCasted},
				EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
				Category:    entity.Entity_CATEGORY_SUBJECT,
			})
		}
	} else {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_UserName{UserName: extractedValueUsernameCasted},
			EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, extractedValueUsernameCasted),
			Category:    entity.Entity_CATEGORY_SUBJECT,
		})
	}

	return entities, nil
}

func getServiceAccountClient(ctx context.Context, username string, kcConfig Config, connector *Connector, logger *logger.Logger, svcCache *cache.Cache) (string, error) {
	expectedClientName := strings.TrimPrefix(username, serviceAccountUsernamePrefix)

	clients, err := retrieveClients(ctx, logger, expectedClientName, kcConfig.Realm, svcCache, connector)
	switch {
	case err != nil:
		logger.ErrorContext(ctx, "connector client error", slog.Any("error", err))
		return "", err
	case len(clients) == 1:
		client := clients[0]
		logger.DebugContext(ctx, "client found", slog.String("client", *client.ClientID))
		return *client.ClientID, nil
	case len(clients) > 1:
		logger.ErrorContext(ctx, "more than one client found for ", slog.String("clientid", expectedClientName))
	default:
		logger.DebugContext(ctx, "no client found, likely not a service account", slog.String("clientid", expectedClientName))
	}

	return "", nil
}

func entityToStructPb(ident *entity.Entity) (*structpb.Struct, error) {
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
func (s *EntityResolutionServiceV2) getConnector(ctx context.Context, tokenBuffer time.Duration) (*Connector, error) {
	s.connectorMu.Lock()
	defer s.connectorMu.Unlock()

	// Refresh token if it's nil, expired, or about to expire.

	if s.connector == nil || s.connector.token == nil || time.Now().After(s.connector.expiresAt.Add(-tokenBuffer)) {
		s.logger.InfoContext(ctx, "keycloak connector is nil or token expired/expiring soon - fetching new token")

		var gocloakClient *gocloak.GoCloak
		if s.idpConfig.LegacyKeycloak {
			s.logger.WarnContext(ctx, "using legacy connection mode for Keycloak < 17.x.x")
			gocloakClient = gocloak.NewClient(s.idpConfig.URL)
		} else {
			gocloakClient = gocloak.NewClient(s.idpConfig.URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
		}

		token, err := gocloakClient.LoginClient(ctx, s.idpConfig.ClientID, s.idpConfig.ClientSecret, s.idpConfig.Realm)
		if err != nil {
			s.logger.ErrorContext(ctx, "error connecting to Keycloak or logging in", slog.Any("error", err))
			return nil, fmt.Errorf("failed to login to Keycloak: %w", err)
		}

		s.connector = &Connector{
			token:     token,
			client:    gocloakClient,
			expiresAt: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
		}
		s.logger.InfoContext(ctx, "successfully fetched new Keycloak token", slog.Int("expires_in_seconds", token.ExpiresIn))
	} else {
		s.logger.DebugContext(ctx, "using existing Keycloak token")
	}
	return s.connector, nil
}
