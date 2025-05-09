package entityresolution

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	auth "github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type ClaimsEntityResolutionService struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	logger *logger.Logger
	trace.Tracer
}

func RegisterClaimsERS(_ config.ServiceConfig, logger *logger.Logger) (ClaimsEntityResolutionService, serviceregistry.HandlerServer) {
	claimsSVC := ClaimsEntityResolutionService{logger: logger}
	return claimsSVC, nil
}

func (s ClaimsEntityResolutionService) ResolveEntities(ctx context.Context, req *connect.Request[entityresolution.ResolveEntitiesRequest]) (*connect.Response[entityresolution.ResolveEntitiesResponse], error) {
	resp, err := EntityResolution(ctx, req.Msg, s.logger)
	return connect.NewResponse(resp), err
}

func (s ClaimsEntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *connect.Request[entityresolution.CreateEntityChainFromJwtRequest]) (*connect.Response[entityresolution.CreateEntityChainFromJwtResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainFromJwt")
	defer span.End()

	resp, err := CreateEntityChainFromJwt(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func CreateEntityChainFromJwt(
	_ context.Context,
	req *entityresolution.CreateEntityChainFromJwtRequest,
	_ *logger.Logger,
) (entityresolution.CreateEntityChainFromJwtResponse, error) {
	entityChains := []*authorization.EntityChain{}
	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(tok.GetJwt())
		if err != nil {
			return entityresolution.CreateEntityChainFromJwtResponse{}, err
		}
		entityChains = append(entityChains, &authorization.EntityChain{Id: tok.GetId(), Entities: entities})
	}

	return entityresolution.CreateEntityChainFromJwtResponse{EntityChains: entityChains}, nil
}

func EntityResolution(_ context.Context,
	req *entityresolution.ResolveEntitiesRequest, logger *logger.Logger,
) (*entityresolution.ResolveEntitiesResponse, error) {
	var resolvedEntities []*entityresolution.EntityRepresentation

	// Process v1 entities
	for idx, entity := range req.GetEntities() {
		representation, err := processV1Entity(entity, idx, logger)
		if err != nil {
			return nil, err
		}
		resolvedEntities = append(resolvedEntities, representation)
	}

	// Process v2 entities
	for idx, entity := range req.GetEntitiesV2() {
		representation, err := processV2Entity(entity, idx, logger)
		if err != nil {
			return nil, err
		}
		resolvedEntities = append(resolvedEntities, representation)
	}

	return &entityresolution.ResolveEntitiesResponse{EntityRepresentations: resolvedEntities}, nil
}

// processV1Entity handles converting a v1 entity into an EntityRepresentation
func processV1Entity(entity *authorization.Entity, idx int, logger *logger.Logger) (*entityresolution.EntityRepresentation, error) {
	entityStruct := &structpb.Struct{}

	switch entity.GetEntityType().(type) {
	case *authorization.Entity_Claims:
		claims := entity.GetClaims()
		if claims != nil {
			if err := claims.UnmarshalTo(entityStruct); err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument,
					fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
			}
		}
	default:
		retrievedStruct, err := entityToStructPb(entity, nil)
		if err != nil {
			logger.Error("unable to make entity struct", slog.String("error", err.Error()))
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("unable to make entity struct: %w", err))
		}
		entityStruct = retrievedStruct
	}

	// Ensure ID is populated
	originalID := entity.GetId()
	if originalID == "" {
		originalID = auth.EntityIDPrefix + fmt.Sprint(idx)
	}

	return &entityresolution.EntityRepresentation{
		OriginalId:      originalID,
		AdditionalProps: []*structpb.Struct{entityStruct},
	}, nil
}

// processV2Entity handles converting a v2 entity into an EntityRepresentation
func processV2Entity(entity *authorizationv2.Entity, idx int, logger *logger.Logger) (*entityresolution.EntityRepresentation, error) {
	entityStruct := &structpb.Struct{}

	switch entity.GetEntityType().(type) {
	case *authorizationv2.Entity_Claims:
		claims := entity.GetClaims()
		if claims != nil {
			if err := claims.UnmarshalTo(entityStruct); err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument,
					fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err))
			}
		}
	default:
		retrievedStruct, err := entityToStructPb(nil, entity)
		if err != nil {
			logger.Error("unable to make entity struct", slog.String("error", err.Error()))
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("unable to make entity struct: %w", err))
		}
		entityStruct = retrievedStruct
	}

	// Ensure ID is populated
	originalID := entity.GetEphemeralId()
	if originalID == "" {
		originalID = auth.EntityIDPrefix + fmt.Sprint(idx)
	}

	return &entityresolution.EntityRepresentation{
		OriginalId:      originalID,
		AdditionalProps: []*structpb.Struct{entityStruct},
	}, nil
}

func getEntitiesFromToken(jwtString string) ([]*authorization.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt: %w", err)
	}

	claims := token.PrivateClaims()
	entities := []*authorization.Entity{}

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

	entities = append(entities, &authorization.Entity{
		EntityType: &authorization.Entity_Claims{Claims: anyClaims},
		Id:         "jwtentity-claims",
		Category:   authorization.Entity_CATEGORY_SUBJECT,
	})
	return entities, nil
}

func entityToStructPb(ident *authorization.Entity, ident2 *authorizationv2.Entity) (*structpb.Struct, error) {
	var (
		entityStruct structpb.Struct
		err          error
		entityBytes  []byte
	)
	if ident != nil {
		entityBytes, err = protojson.Marshal(ident)
		if err != nil {
			return nil, err
		}
		err = entityStruct.UnmarshalJSON(entityBytes)
		if err != nil {
			return nil, err
		}
	} else if ident2 != nil {
		entityBytes, err = protojson.Marshal(ident2)
		if err != nil {
			return nil, err
		}
		err = entityStruct.UnmarshalJSON(entityBytes)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("error: entity is nil")
	}
	return &entityStruct, nil
}
