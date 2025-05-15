package claims_test

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	claims "github.com/opentdf/platform/service/entityresolution/claims/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const samplejwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhlbGxvd29ybGQiLCJpYXQiOjE1MTYyMzkwMjJ9.EAOittOMzKENEAs44eaMuZe-xas7VNVsgBxhwmxYiIw"

func Test_ClientResolveEntity(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{EphemeralId: "1234", EntityType: &entity.Entity_ClientId{ClientId: "random"}})

	req := entityresolutionV2.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "random", propMap["clientId"])
	assert.Equal(t, "1234", propMap["id"])
}

func Test_EmailResolveEntity(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{EphemeralId: "1234", EntityType: &entity.Entity_EmailAddress{EmailAddress: "random"}})

	req := entityresolutionV2.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "random", propMap["emailAddress"])
	assert.Equal(t, "1234", propMap["id"])
}

func Test_ClaimsResolveEntity(t *testing.T) {
	customclaims := map[string]interface{}{
		"foo": "bar",
		"baz": 42,
	}
	// Convert map[string]interface{} to *structpb.Struct
	structClaims, err := structpb.NewStruct(customclaims)
	require.NoError(t, err)

	// Wrap the struct in an *anypb.Any
	anyClaims, err := anypb.New(structClaims)
	require.NoError(t, err)

	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{EphemeralId: "1234", EntityType: &entity.Entity_Claims{Claims: anyClaims}})

	req := entityresolutionV2.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bar", propMap["foo"])
	assert.EqualValues(t, 42, propMap["baz"])
}

func Test_JWTToEntityChainClaims(t *testing.T) {
	validBody := []*entity.Token{{Jwt: samplejwt}}

	resp, reserr := claims.CreateEntityChainsFromTokens(t.Context(), &entityresolutionV2.CreateEntityChainsFromTokensRequest{Tokens: validBody}, logger.CreateTestLogger())

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 1)
	assert.IsType(t, &entity.Entity_Claims{}, resp.GetEntityChains()[0].GetEntities()[0].GetEntityType())
	assert.Equal(t, entity.Entity_CATEGORY_SUBJECT, resp.GetEntityChains()[0].GetEntities()[0].GetCategory())

	var unpackedStruct structpb.Struct
	err := resp.GetEntityChains()[0].GetEntities()[0].GetClaims().UnmarshalTo(&unpackedStruct)
	require.NoError(t, err)

	// Convert structpb.Struct to map[string]interface{}
	claimsMap := unpackedStruct.AsMap()

	assert.Equal(t, "helloworld", claimsMap["name"])
}
