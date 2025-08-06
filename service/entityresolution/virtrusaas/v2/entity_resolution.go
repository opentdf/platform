package virtrusaas

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
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

var acmClient *AcmClient = NewAcmClient()

type EntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	logger *logger.Logger
	trace.Tracer
}

func RegisterVirtruSaasERS(_ config.ServiceConfig, logger *logger.Logger) (EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	svc := EntityResolutionServiceV2{
		logger: logger,
	}
	return svc, nil
}

func (s EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	resp, err := EntityResolution(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func (s EntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func CreateEntityChainsFromTokens(
	_ context.Context,
	req *entityresolutionV2.CreateEntityChainsFromTokensRequest,
	logger *logger.Logger,
) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	entityChains := []*entity.EntityChain{}
	resources := req.GetResources()

	// for each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(tok.GetJwt(), resources)
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
	var resolvedEntities []*entityresolutionV2.EntityRepresentation

	for idx, ident := range req.GetEntities() {
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
		default:
			return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unsupported entity type: %T", ident.GetEntityType()))
		}
	}

	return entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: resolvedEntities}, nil
}

func getEntitiesFromToken(jwtString string, resources []*authorizationv2.Resource) ([]*entity.Entity, error) {
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

	for _, res := range resources {
		for _, resFQN := range res.GetAttributeValues().GetFqns() {
			// strip policy ID off resource attr value FQN
			policyID := resFQN[strings.LastIndex(resFQN, "/")+1:]

			// validate access with call to ACM GET /policies/{policyID}/contract with token as auth
			resp, err := acmClient.GetContract(policyID, jwtString)
			if err != nil {
				return nil, fmt.Errorf("error getting contract for policy ID %s: %w", policyID, err)
			}

			var actions []string
			if resp.IsOwner {
				actions = []string{"read", "write", "update", "delete"}
			} else {
				actions = []string{"read"}
			}

			directEntitlements := map[string][]string{
				resFQN: actions,
			}

			bytes, err := json.Marshal(directEntitlements)
			if err != nil {
				return nil, fmt.Errorf("error marshaling direct entitlements: %w", err)
			}

			var directEntitlementsStruct structpb.Struct
			if err := protojson.Unmarshal(bytes, &directEntitlementsStruct); err != nil {
				return nil, fmt.Errorf("error unmarshaling direct entitlements: %w", err)
			}

			structClaims.Fields["direct_entitlements"] = &structpb.Value{
				Kind: &structpb.Value_StructValue{StructValue: &directEntitlementsStruct},
			}
		}
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
