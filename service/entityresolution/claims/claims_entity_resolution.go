package entityresolution

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	auth "github.com/opentdf/platform/service/authorization"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type ClaimsEntityResolutionService struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	logger *logger.Logger
}

func RegisterClaimsERS(_ serviceregistry.ServiceConfig, logger *logger.Logger) (ClaimsEntityResolutionService, serviceregistry.HandlerServer) {
	claimsSVC := ClaimsEntityResolutionService{logger: logger}
	return claimsSVC,
		func(ctx context.Context, mux *runtime.ServeMux) error {
			return entityresolution.RegisterEntityResolutionServiceHandlerServer(ctx, mux, claimsSVC)
		}
}

func (s ClaimsEntityResolutionService) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error) {
	resp, err := EntityResolution(ctx, req, s.logger)
	return &resp, err
}

func (s ClaimsEntityResolutionService) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	resp, err := CreateEntityChainFromJwt(ctx, req, s.logger)
	return &resp, err
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
) (entityresolution.ResolveEntitiesResponse, error) {
	payload := req.GetEntities()
	var resolvedEntities []*entityresolution.EntityRepresentation

	for idx, ident := range payload {
		entityStruct := &structpb.Struct{}
		switch ident.GetEntityType().(type) {
		case *authorization.Entity_Claims:
			claims := ident.GetClaims()
			if claims != nil {
				err := claims.UnmarshalTo(entityStruct)
				if err != nil {
					return entityresolution.ResolveEntitiesResponse{}, fmt.Errorf("error unpacking anypb.Any to structpb.Struct: %w", err)
				}
			}
		default:
			retrievedStruct, err := entityToStructPb(ident)
			if err != nil {
				logger.Error("unable to make entity struct", slog.String("error", err.Error()))
				return entityresolution.ResolveEntitiesResponse{}, fmt.Errorf("unable to make entity struct: %w", err)
			}
			entityStruct = retrievedStruct
		}
		// make sure the id field is populated
		originialID := ident.GetId()
		if originialID == "" {
			originialID = auth.EntityIDPrefix + fmt.Sprint(idx)
		}
		resolvedEntities = append(
			resolvedEntities,
			&entityresolution.EntityRepresentation{
				OriginalId:      originialID,
				AdditionalProps: []*structpb.Struct{entityStruct},
			},
		)
	}
	return entityresolution.ResolveEntitiesResponse{EntityRepresentations: resolvedEntities}, nil
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
