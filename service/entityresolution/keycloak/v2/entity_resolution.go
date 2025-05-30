package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/Nerzal/gocloak/v13"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
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

type EntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	idpConfig Config
	logger    *logger.Logger
	trace.Tracer
	// Token caching fields
	kcClient    *gocloak.GoCloak
	kcToken     *gocloak.JWT
	tokenMutex  sync.RWMutex
	tokenExpiry time.Time
}

type Config struct {
	URL                   string                 `mapstructure:"url" json:"url"`
	Realm                 string                 `mapstructure:"realm" json:"realm"`
	ClientID              string                 `mapstructure:"clientid" json:"clientid"`
	ClientSecret          string                 `mapstructure:"clientsecret" json:"clientsecret"`
	LegacyKeycloak        bool                   `mapstructure:"legacykeycloak" json:"legacykeycloak" default:"false"`
	SubGroups             bool                   `mapstructure:"subgroups" json:"subgroups" default:"false"`
	InferID               InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
	ConnectTimeoutSeconds int                    `mapstructure:"connect_timeout_seconds" json:"connect_timeout_seconds" default:"10"`
	Pool                  PoolConfig             `mapstructure:"pool,omitempty" json:"pool,omitempty"`
}

func RegisterKeycloakERS(config config.ServiceConfig, logger *logger.Logger) (*EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	var inputIdpConfig Config
	if err := mapstructure.Decode(config, &inputIdpConfig); err != nil {
		panic(err)
	}
	logger.Debug("entity_resolution configuration", "config", inputIdpConfig)

	// Initialize the Keycloak client once
	var client *gocloak.GoCloak
	if inputIdpConfig.LegacyKeycloak {
		logger.Warn("using legacy connection mode for Keycloak < 17.x.x")
		client = gocloak.NewClient(inputIdpConfig.URL)
	} else {
		client = gocloak.NewClient(inputIdpConfig.URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	}

	// Configure HTTP transport with connection pooling
	restyClient := client.RestyClient()
	restyClient.SetTransport(&http.Transport{
		MaxIdleConns:        inputIdpConfig.Pool.MaxConnectionCount,
		MaxIdleConnsPerHost: inputIdpConfig.Pool.MaxIdleConnectionsCount,
		IdleConnTimeout:     time.Duration(inputIdpConfig.Pool.MaxConnectionIdleSeconds) * time.Second,
		TLSHandshakeTimeout: time.Duration(inputIdpConfig.ConnectTimeoutSeconds) * time.Second,
		DisableKeepAlives:   false,
	})
	restyClient.SetTimeout(time.Duration(inputIdpConfig.ConnectTimeoutSeconds) * time.Second)
	client.SetRestyClient(restyClient)

	keycloakSVC := &EntityResolutionServiceV2{
		idpConfig: inputIdpConfig,
		logger:    logger,
		kcClient:  client,
	}
	return keycloakSVC, nil
}

// getOrRefreshToken returns a valid token, refreshing if necessary
func (s *EntityResolutionServiceV2) getOrRefreshToken(ctx context.Context) (*gocloak.JWT, error) {
	s.tokenMutex.RLock()
	if s.kcToken != nil && time.Now().Before(s.tokenExpiry) {
		defer s.tokenMutex.RUnlock()
		return s.kcToken, nil
	}
	s.tokenMutex.RUnlock()

	// Need to refresh token
	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()

	// Double-check in case another goroutine refreshed while we were waiting
	if s.kcToken != nil && time.Now().Before(s.tokenExpiry) {
		return s.kcToken, nil
	}

	// Login to get new token
	token, err := s.kcClient.LoginClient(ctx, s.idpConfig.ClientID, s.idpConfig.ClientSecret, s.idpConfig.Realm)
	if err != nil {
		s.logger.Error("error connecting to keycloak!", slog.String("error", err.Error()))
		return nil, err
	}

	s.kcToken = token
	// Refresh 30 seconds before expiry
	s.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn-30) * time.Second)
	s.logger.Debug("refreshed keycloak token", slog.Time("expires_at", s.tokenExpiry))

	return token, nil
}

func (s *EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "ResolveEntities")
	defer span.End()

	resp, err := s.entityResolution(ctx, req.Msg)
	return connect.NewResponse(&resp), err
}

func (s *EntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	resp, err := s.createEntityChainsFromTokens(ctx, req.Msg)
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
		slog.Any("pool", c.Pool),
	)
}

type PoolConfig struct {
	MaxConnectionCount       int `mapstructure:"max_connection_count" json:"max_connection_count" default:"500"`
	MaxIdleConnectionsCount  int `mapstructure:"max_idle_connections_count" json:"max_idle_connections_count" default:"100"`
	MaxConnectionIdleSeconds int `mapstructure:"max_connection_idle_seconds" json:"max_connection_idle_seconds" default:"90"`
}

type InferredIdentityConfig struct {
	From EntityImpliedFrom `mapstructure:"from,omitempty" json:"from,omitempty"`
}

type EntityImpliedFrom struct {
	ClientID bool `mapstructure:"clientid,omitempty" json:"clientid,omitempty"`
	Email    bool `mapstructure:"email,omitempty" json:"email,omitempty"`
	Username bool `mapstructure:"username,omitempty" json:"username,omitempty"`
}

func (s *EntityResolutionServiceV2) createEntityChainsFromTokens(
	ctx context.Context,
	req *entityresolutionV2.CreateEntityChainsFromTokensRequest,
) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	entityChains := []*entity.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := s.getEntitiesFromToken(ctx, tok.GetJwt())
		if err != nil {
			return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, err
		}
		entityChains = append(entityChains, &entity.EntityChain{EphemeralId: tok.GetEphemeralId(), Entities: entities})
	}

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: entityChains}, nil
}

func (s *EntityResolutionServiceV2) entityResolution(ctx context.Context,
	req *entityresolutionV2.ResolveEntitiesRequest,
) (entityresolutionV2.ResolveEntitiesResponse, error) {
	token, err := s.getOrRefreshToken(ctx)
	if err != nil {
		return entityresolutionV2.ResolveEntitiesResponse{},
			connect.NewError(connect.CodeInternal, ErrCreationFailed)
	}
	payload := req.GetEntities()

	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for idx, ident := range payload {
		s.logger.Debug("lookup", "entity", ident.GetEntityType())
		var keycloakEntities []*gocloak.User
		var getUserParams gocloak.GetUsersParams
		exactMatch := true
		switch ident.GetEntityType().(type) {
		case *entity.Entity_ClientId:
			s.logger.Debug("looking up", slog.Any("type", ident.GetEntityType()), slog.String("client_id", ident.GetClientId()))
			clientID := ident.GetClientId()
			clients, err := s.kcClient.GetClients(ctx, token.AccessToken, s.idpConfig.Realm, gocloak.GetClientsParams{
				ClientID: &clientID,
			})
			if err != nil {
				s.logger.Error("error getting client info", slog.String("error", err.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
			}
			var jsonEntities []*structpb.Struct
			for _, client := range clients {
				json, err := typeToGenericJSONMap(client, s.logger)
				if err != nil {
					s.logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				mystruct, structErr := structpb.NewStruct(json)
				if structErr != nil {
					s.logger.Error("error making struct!", slog.String("error", structErr.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, mystruct)
			}
			if len(clients) == 0 && s.idpConfig.InferID.From.ClientID {
				// convert entity to json
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					s.logger.Error("unable to make entity struct", slog.String("error", err.Error()))
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
		users, err := s.kcClient.GetUsers(ctx, token.AccessToken, s.idpConfig.Realm, getUserParams)
		switch {
		case err != nil:
			s.logger.Error(err.Error())
			return entityresolutionV2.ResolveEntitiesResponse{},
				connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
		case len(users) == 1:
			user := users[0]
			s.logger.Debug("user found", slog.String("user", *user.ID), slog.String("entity", ident.String()))
			s.logger.Debug("user", slog.Any("details", user))
			s.logger.Debug("user", slog.Any("attributes", user.Attributes))
			keycloakEntities = append(keycloakEntities, user)
		default:
			s.logger.Error("no user found for", slog.Any("entity", ident))
			if ident.GetEmailAddress() != "" { //nolint:nestif // this case has many possible outcomes to handle
				// try by group
				groups, groupErr := s.kcClient.GetGroups(
					ctx,
					token.AccessToken,
					s.idpConfig.Realm,
					gocloak.GetGroupsParams{Search: func() *string { t := ident.GetEmailAddress(); return &t }()},
				)
				switch {
				case groupErr != nil:
					s.logger.Error("error getting group", slog.String("group", groupErr.Error()))
					return entityresolutionV2.ResolveEntitiesResponse{},
						connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
				case len(groups) == 1:
					s.logger.Info("group found for", slog.String("entity", ident.String()))
					group := groups[0]
					expandedRepresentations, exErr := s.expandGroup(ctx, *group.ID)
					if exErr != nil {
						return entityresolutionV2.ResolveEntitiesResponse{},
							connect.NewError(connect.CodeNotFound, ErrNotFound)
					}
					keycloakEntities = expandedRepresentations
				default:
					s.logger.Error("no group found for", slog.String("entity", ident.String()))
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
						s.logger.Error("unsupported/unknown type for", slog.String("entity", ident.String()))
						entityNotFoundErr = entityresolutionV2.EntityNotFoundError{Code: int32(codes.NotFound), Message: ErrGetRetrievalFailed.Error(), Entity: ident.String()}
					}
					s.logger.Error(entityNotFoundErr.String())
					if s.idpConfig.InferID.From.Email || s.idpConfig.InferID.From.Username {
						// user not found -- add json entity to resp instead
						entityStruct, err := entityToStructPb(ident)
						if err != nil {
							s.logger.Error("unable to make entity struct from email or username", slog.String("error", err.Error()))
							return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, ErrCreationFailed)
						}
						jsonEntities = append(jsonEntities, entityStruct)
					} else {
						return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrGetRetrievalFailed)
					}
				}
			} else if ident.GetUserName() != "" {
				if s.idpConfig.InferID.From.Username {
					// user not found -- add json entity to resp instead
					entityStruct, err := entityToStructPb(ident)
					if err != nil {
						s.logger.Error("unable to make entity struct from username", slog.String("error", err.Error()))
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
			json, err := typeToGenericJSONMap(er, s.logger)
			if err != nil {
				s.logger.Error("error serializing entity representation!", slog.String("error", err.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{},
					connect.NewError(connect.CodeInternal, ErrCreationFailed)
			}
			mystruct, structErr := structpb.NewStruct(json)
			if structErr != nil {
				s.logger.Error("error making struct!", slog.String("error", structErr.Error()))
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
		s.logger.Debug("entities", slog.Any("resolved", resolvedEntities))
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

func (s *EntityResolutionServiceV2) expandGroup(ctx context.Context, groupID string) ([]*gocloak.User, error) {
	s.logger.Info("expanding group", slog.String("groupID", groupID))
	var entityRepresentations []*gocloak.User

	token, err := s.getOrRefreshToken(ctx)
	if err != nil {
		return nil, err
	}

	grp, err := s.kcClient.GetGroup(ctx, token.AccessToken, s.idpConfig.Realm, groupID)
	if err == nil {
		grpMembers, memberErr := s.kcClient.GetGroupMembers(ctx, token.AccessToken, s.idpConfig.Realm,
			*grp.ID, gocloak.GetGroupsParams{})
		if memberErr == nil {
			s.logger.Debug("adding members", slog.Int("amount", len(grpMembers)), slog.String("from group", *grp.Name))
			for i := 0; i < len(grpMembers); i++ {
				user := grpMembers[i]
				entityRepresentations = append(entityRepresentations, user)
			}
		} else {
			s.logger.Error("error getting group members", slog.String("error", memberErr.Error()))
		}
	} else {
		s.logger.Error("error getting group", slog.String("error", err.Error()))
		return nil, err
	}
	return entityRepresentations, nil
}

func (s *EntityResolutionServiceV2) getEntitiesFromToken(ctx context.Context, jwtString string) ([]*entity.Entity, error) {
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
		clientid, err := s.getServiceAccountClient(ctx, extractedValueUsernameCasted)
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

func (s *EntityResolutionServiceV2) getServiceAccountClient(ctx context.Context, username string) (string, error) {
	token, err := s.getOrRefreshToken(ctx)
	if err != nil {
		return "", err
	}
	expectedClientName := strings.TrimPrefix(username, serviceAccountUsernamePrefix)

	clients, err := s.kcClient.GetClients(ctx, token.AccessToken, s.idpConfig.Realm, gocloak.GetClientsParams{
		ClientID: &expectedClientName,
	})
	switch {
	case err != nil:
		s.logger.Error(err.Error())
		return "", err
	case len(clients) == 1:
		client := clients[0]
		s.logger.Debug("client found", slog.String("client", *client.ClientID))
		return *client.ClientID, nil
	case len(clients) > 1:
		s.logger.Error("more than one client found for ", slog.String("clientid", expectedClientName))
	default:
		s.logger.Debug("no client found, likely not a service account", slog.String("clientid", expectedClientName))
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
