package virtrusaas

import (
	"context"
	"fmt"
	"log/slog"
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

var acmClient = NewAcmClient()

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
	_ *logger.Logger,
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
	req *entityresolutionV2.ResolveEntitiesRequest,
	_ *logger.Logger,
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

			directEntitlements := make([]*entityresolutionV2.DirectEntitlement, 0)
			if pbstructDirectEntitlement, ok := entityStruct.GetFields()["direct_entitlements"]; ok {
				for _, entitlement := range pbstructDirectEntitlement.GetListValue().GetValues() {
					bytes, err := protojson.Marshal(entitlement)
					if err != nil {
						return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error marshaling direct entitlement: %w", err))
					}

					var directEntitlement entityresolutionV2.DirectEntitlement
					if err := protojson.Unmarshal(bytes, &directEntitlement); err != nil {
						return entityresolutionV2.ResolveEntitiesResponse{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("error unmarshaling direct entitlement: %w", err))
					}
					directEntitlements = append(directEntitlements, &directEntitlement)
				}

				delete(entityStruct.GetFields(), "direct_entitlements")
			}

			resolvedEntities = append(
				resolvedEntities,
				&entityresolutionV2.EntityRepresentation{
					OriginalId:         originialID,
					AdditionalProps:    []*structpb.Struct{entityStruct},
					DirectEntitlements: directEntitlements,
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

	spbEntitlements := make([]*structpb.Value, 0)

	for _, res := range resources {
		for _, resFQN := range res.GetAttributeValues().GetFqns() {
			// strip policy ID off resource attr value FQN
			policyID := resFQN[strings.LastIndex(resFQN, "/")+1:]

			// validate access with call to ACM GET /policies/{policyID}/contract with token as auth
			resp, err := acmClient.GetContract(policyID, jwtString)
			if err != nil {
				slog.Debug("error getting contract for policy ID",
					slog.String("policy_id", policyID),
					slog.Any("error", err),
				)
				continue // skip this resource if we can't get the contract b/c entity doesn't have access
			}

			var actions []string
			if resp.IsOwner {
				actions = []string{"read", "write", "update", "delete"}
			} else {
				actions = []string{"read"}
			}

			entitlement := &entityresolutionV2.DirectEntitlement{
				Fqn:     resFQN,
				Actions: actions,
			}

			bytes, err := protojson.Marshal(entitlement)
			if err != nil {
				return nil, fmt.Errorf("error converting entitlement to JSON: %w", err)
			}

			var entitlementStructPbValue structpb.Value
			if err := protojson.Unmarshal(bytes, &entitlementStructPbValue); err != nil {
				return nil, fmt.Errorf("error unmarshaling direct entitlements: %w", err)
			}

			spbEntitlements = append(spbEntitlements, &entitlementStructPbValue)
		}
	}

	structClaims.Fields["direct_entitlements"] = &structpb.Value{
		Kind: &structpb.Value_ListValue{
			ListValue: &structpb.ListValue{
				Values: spbEntitlements,
			},
		},
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
