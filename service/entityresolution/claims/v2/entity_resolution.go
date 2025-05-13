package claims

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	auth "github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type ClaimsEntityResolutionServiceV2 struct {
	ersV2.UnimplementedEntityResolutionServiceServer
	logger *logger.Logger
	trace.Tracer
}

func RegisterClaimsERS(_ config.ServiceConfig, logger *logger.Logger) (ClaimsEntityResolutionServiceV2, serviceregistry.HandlerServer) {
	claimsSVC := ClaimsEntityResolutionServiceV2{logger: logger}
	return claimsSVC, nil
}

func (s ClaimsEntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[ersV2.ResolveEntitiesRequest]) (*connect.Response[ersV2.ResolveEntitiesResponse], error) {
	resp, err := resolveEntities(ctx, s.logger, req.Msg)
	return connect.NewResponse(&resp), err
}

func (s ClaimsEntityResolutionServiceV2) CreateEntityChainFromJwt(ctx context.Context, req *connect.Request[ersV2.CreateEntityChainFromJwtRequest]) (*connect.Response[ersV2.CreateEntityChainFromJwtResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	resp, err := createEntityChainFromSingleJwt(ctx, s.logger, req.Msg)
	return connect.NewResponse(&resp), err
}
func (s ClaimsEntityResolutionServiceV2) CreateEntityChainFromJwtMulti(ctx context.Context, req *connect.Request[ersV2.CreateEntityChainFromJwtMultiRequest]) (*connect.Response[ersV2.CreateEntityChainFromJwtMultiResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	resp, err := createEntityChainFromMultiJwt(ctx, s.logger, req.Msg)
	return connect.NewResponse(&resp), err
}

func createEntityChainFromSingleJwt(
	_ context.Context,
	_ *logger.Logger,
	req *ersV2.CreateEntityChainFromJwtRequest,
) (ersV2.CreateEntityChainFromJwtResponse, error) {
	tok := req.GetToken()
	// for each token in the tokens form an entity chain
	entities, err := getEntitiesFromToken(tok.GetJwt())
	if err != nil {
		return ersV2.CreateEntityChainFromJwtResponse{}, err
	}
	chain := &authz.EntityChain{EphemeralChainId: tok.GetId(), Entities: entities}

	return ersV2.CreateEntityChainFromJwtResponse{EntityChains: chain}, nil
}

func createEntityChainFromMultiJwt(
	_ context.Context,
	_ *logger.Logger,
	req *ersV2.CreateEntityChainFromJwtMultiRequest,
) (ersV2.CreateEntityChainFromJwtMultiResponse, error) {
	entityChains := []*authz.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetToken() {
		entities, err := getEntitiesFromToken(tok.GetJwt())
		if err != nil {
			return ersV2.CreateEntityChainFromJwtMultiResponse{}, err
		}
		entityChains = append(entityChains, &authz.EntityChain{EphemeralChainId: tok.GetId(), Entities: entities})
	}
	return ersV2.CreateEntityChainFromJwtMultiResponse{EntityChains: entityChains}, nil
}

func resolveEntities(
	_ context.Context,
	logger *logger.Logger,
	req *ersV2.ResolveEntitiesRequest,
) (ersV2.ResolveEntitiesResponse, error) {
	entities := req.GetEntitiesV2()
	var resolvedEntities []*entityresolution.EntityRepresentation

	for idx, entity := range entities {
		entityStruct := &structpb.Struct{}
		switch entity.GetEntityType().(type) {
		case *authz.Entity_Claims:
			claims := entity.GetClaims()
			if claims != nil {
				err := claims.UnmarshalTo(entityStruct)
				if err != nil {
					return ersV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
				}
			}
		default:
			retrievedStruct, err := entityToStructPb(entity)
			if err != nil {
				logger.Error("unable to make entity struct", slog.String("error", err.Error()))
				return ersV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInternal, fmt.Errorf("unable to make entity struct: %w", err))
			}
			entityStruct = retrievedStruct
		}
		// make sure the id field is populated
		originialID := entity.GetEphemeralId()
		if originialID == "" {
			originialID = auth.EntityIDPrefix + strconv.Itoa(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      originialID,
				AdditionalProps: []*structpb.Struct{entityStruct},
			},
		)
	}
	return ersV2.ResolveEntitiesResponse{EntityRepresentations: resolvedEntities}, nil
}

func getEntitiesFromToken(jwtString string) ([]*authz.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt: %w", err)
	}

	claims := token.PrivateClaims()
	entities := []*authz.Entity{}

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

	entities = append(entities, &authz.Entity{
		EntityType:  &authz.Entity_Claims{Claims: anyClaims},
		EphemeralId: "jwtentity-claims",
		Category:    authz.Entity_CATEGORY_SUBJECT,
	})
	return entities, nil
}

func entityToStructPb(entity *authz.Entity) (*structpb.Struct, error) {
	entityBytes, err := protojson.Marshal(entity)
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
