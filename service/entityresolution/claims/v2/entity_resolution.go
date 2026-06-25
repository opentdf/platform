package claims

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type EntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	logger                  *logger.Logger
	allowDirectEntitlements bool
	trace.Tracer
}

type ClaimsConfig struct {
	AllowDirectEntitlements bool `mapstructure:"allow_direct_entitlements" json:"allow_direct_entitlements" default:"false"`
}

func RegisterClaimsERS(cfg config.ServiceConfig, logger *logger.Logger) (EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	var inputConfig ClaimsConfig
	if err := mapstructure.Decode(cfg, &inputConfig); err != nil {
		logger.Error("failed to decode claims entity resolution configuration", slog.Any("error", err))
		log.Fatalf("Failed to decode claims entity resolution configuration: %v", err)
	}
	claimsSVC := EntityResolutionServiceV2{
		logger:                  logger,
		allowDirectEntitlements: inputConfig.AllowDirectEntitlements,
	}
	return claimsSVC, nil
}

func (s EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	resp, err := EntityResolution(ctx, req.Msg, s.logger, s.allowDirectEntitlements)
	return connect.NewResponse(&resp), err
}

func (s EntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func CreateEntityChainsFromTokens(
	_ context.Context,
	req *entityresolutionV2.CreateEntityChainsFromTokensRequest,
	_ *logger.Logger,
) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	entityChains := []*entity.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(tok.GetJwt())
		if err != nil {
			return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, err
		}
		entityChains = append(entityChains, &entity.EntityChain{EphemeralId: tok.GetEphemeralId(), Entities: entities})
	}

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: entityChains}, nil
}

func EntityResolution(_ context.Context,
	req *entityresolutionV2.ResolveEntitiesRequest, logger *logger.Logger, allowDirectEntitlements bool,
) (entityresolutionV2.ResolveEntitiesResponse, error) {
	payload := req.GetEntities()
	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for idx, ident := range payload {
		entityStruct := &structpb.Struct{}
		var directEntitlements []*entityresolutionV2.DirectEntitlement
		switch ident.GetEntityType().(type) {
		case *entity.Entity_Claims:
			claims := ident.GetClaims()
			if claims != nil {
				err := claims.UnmarshalTo(entityStruct)
				if err != nil {
					return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
				}
			}
			if allowDirectEntitlements {
				var err error
				directEntitlements, err = parseDirectEntitlementsFromClaims(entityStruct)
				if err != nil {
					return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, err)
				}
			}
		default:
			retrievedStruct, err := entityToStructPb(ident)
			if err != nil {
				logger.Error("unable to make entity struct", slog.String("error", err.Error()))
				return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to make entity struct: %w", err))
			}
			entityStruct = retrievedStruct
		}
		// make sure the id field is populated
		originialID := ident.GetEphemeralId()
		if originialID == "" {
			originialID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolutionV2.EntityRepresentation{
				OriginalId:         originialID,
				AdditionalProps:    []*structpb.Struct{entityStruct},
				DirectEntitlements: directEntitlements,
			},
		)
	}
	return entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: resolvedEntities}, nil
}

func getEntitiesFromToken(jwtString string) ([]*entity.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt: %w", err)
	}

	claims := token.PrivateClaims()
	// PrivateClaims() excludes standard registered JWT claims (sub, iss, aud, etc.)
	// because the jwx library stores them as typed fields. Add them back so selectors
	// like .sub work in subject mapping conditions.
	if sub := token.Subject(); sub != "" {
		claims["sub"] = sub
	}
	if iss := token.Issuer(); iss != "" {
		claims["iss"] = iss
	}
	if jti := token.JwtID(); jti != "" {
		claims["jti"] = jti
	}
	if aud := token.Audience(); len(aud) > 0 {
		// Convert []string to []interface{} for structpb compatibility
		audSlice := make([]interface{}, len(aud))
		for i, a := range aud {
			audSlice[i] = a
		}
		claims["aud"] = audSlice
	}
	entities := []*entity.Entity{}

	// Convert map[string]interface{} to *structpb.Struct
	structClaims, err := structpb.NewStruct(claims)
	if err != nil {
		return nil, fmt.Errorf("error converting to structpb.Struct: %w", err)
	}

	// Wrap the struct in an *anypb.Any message
	anyClaims, err := anypb.New(structClaims)
	if err != nil {
		return nil, fmt.Errorf("error wrapping in anypb.Any: %w", err)
	}

	entities = append(entities, &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
		EphemeralId: "jwtentity-claims",
		Category:    entity.Entity_CATEGORY_SUBJECT,
	})
	return entities, nil
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

func parseDirectEntitlementsFromClaims(entityStruct *structpb.Struct) ([]*entityresolutionV2.DirectEntitlement, error) {
	if entityStruct == nil {
		return nil, nil
	}
	claims := entityStruct.AsMap()
	rawEntitlements, ok := claims["direct_entitlements"]
	if !ok {
		rawEntitlements, ok = claims["directEntitlements"]
	}
	if !ok {
		return nil, nil
	}

	entitlementList, entitlementsOK := rawEntitlements.([]interface{})
	if !entitlementsOK {
		return nil, errors.New("direct_entitlements must be an array")
	}

	out := make([]*entityresolutionV2.DirectEntitlement, 0, len(entitlementList))
	for idx, entry := range entitlementList {
		entryMap, entryOK := entry.(map[string]interface{})
		if !entryOK {
			return nil, fmt.Errorf("direct_entitlements[%d] must be an object", idx)
		}

		fqn, err := parseDirectEntitlementFQN(entryMap)
		if err != nil {
			return nil, fmt.Errorf("direct_entitlements[%d] %w", idx, err)
		}

		rawActions, actionsOK := entryMap["actions"]
		if !actionsOK {
			return nil, fmt.Errorf("direct_entitlements[%d] missing actions", idx)
		}
		actions, err := parseDirectEntitlementActions(rawActions)
		if err != nil {
			return nil, fmt.Errorf("direct_entitlements[%d] invalid actions: %w", idx, err)
		}

		out = append(out, &entityresolutionV2.DirectEntitlement{
			AttributeValueFqn: fqn,
			Actions:           actions,
		})
	}

	return out, nil
}

func parseDirectEntitlementFQN(entry map[string]interface{}) (string, error) {
	if raw, ok := entry["attribute_value_fqn"]; ok {
		if fqn, fqnOK := raw.(string); fqnOK {
			fqn = strings.TrimSpace(fqn)
			if fqn != "" {
				return fqn, nil
			}
		}
	}
	if raw, ok := entry["attributeValueFqn"]; ok {
		if fqn, fqnOK := raw.(string); fqnOK {
			fqn = strings.TrimSpace(fqn)
			if fqn != "" {
				return fqn, nil
			}
		}
	}
	return "", errors.New("missing attribute_value_fqn")
}

func parseDirectEntitlementActions(raw interface{}) ([]string, error) {
	actions := make([]string, 0)
	switch typed := raw.(type) {
	case []interface{}:
		for _, action := range typed {
			actionStr, ok := action.(string)
			if !ok {
				return nil, errors.New("action must be a string")
			}
			actionStr = strings.TrimSpace(strings.ToLower(actionStr))
			if actionStr != "" {
				actions = append(actions, actionStr)
			}
		}
	case []string:
		for _, action := range typed {
			action = strings.TrimSpace(strings.ToLower(action))
			if action != "" {
				actions = append(actions, action)
			}
		}
	case string:
		for _, action := range strings.Split(typed, ",") {
			action = strings.TrimSpace(strings.ToLower(action))
			if action != "" {
				actions = append(actions, action)
			}
		}
	default:
		return nil, errors.New("actions must be an array or string")
	}

	if len(actions) == 0 {
		return nil, errors.New("no actions provided")
	}
	return actions, nil
}
