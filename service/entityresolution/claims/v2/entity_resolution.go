package claims

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"connectrpc.com/connect"
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
	logger *logger.Logger
	trace.Tracer
}

func RegisterClaimsERS(_ config.ServiceConfig, logger *logger.Logger) (EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	claimsSVC := EntityResolutionServiceV2{logger: logger}
	return claimsSVC, nil
}

func (s EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	resp, err := EntityResolution(ctx, req.Msg, s.logger)
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
	req *entityresolutionV2.ResolveEntitiesRequest, logger *logger.Logger,
) (entityresolutionV2.ResolveEntitiesResponse, error) {
	payload := req.GetEntities()
	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for idx, ident := range payload {
		entityStruct := &structpb.Struct{}
		switch ident.GetEntityType().(type) {
		case *entity.Entity_Claims:
			claims := ident.GetClaims()
			if claims != nil {
				err := claims.UnmarshalTo(entityStruct)
				if err != nil {
					return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
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
				OriginalId:      originialID,
				AdditionalProps: []*structpb.Struct{entityStruct},
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
