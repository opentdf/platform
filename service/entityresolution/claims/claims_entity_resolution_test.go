package entityresolution_test

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	claims "github.com/opentdf/platform/service/entityresolution/claims"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const samplejwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhlbGxvd29ybGQiLCJpYXQiOjE1MTYyMzkwMjJ9.EAOittOMzKENEAs44eaMuZe-xas7VNVsgBxhwmxYiIw"

func Test_ClientResolveEntity(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_ClientId{ClientId: "random"}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = claims.EntityResolution(ctxb, &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "random", propMap["clientId"])
	assert.Equal(t, "1234", propMap["id"])
}

func Test_EmailResolveEntity(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "random"}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = claims.EntityResolution(ctxb, &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
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

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_Claims{Claims: anyClaims}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = claims.EntityResolution(ctxb, &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bar", propMap["foo"])
	assert.EqualValues(t, 42, propMap["baz"])
}

func Test_JWTToEntityChainClaims(t *testing.T) {
	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: samplejwt}}

	var resp, reserr = claims.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, logger.CreateTestLogger())

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 1)
	assert.IsType(t, &authorization.Entity_Claims{}, resp.GetEntityChains()[0].GetEntities()[0].GetEntityType())
	assert.Equal(t, authorization.Entity_CATEGORY_SUBJECT, resp.GetEntityChains()[0].GetEntities()[0].GetCategory())

	var unpackedStruct structpb.Struct
	err := resp.GetEntityChains()[0].GetEntities()[0].GetClaims().UnmarshalTo(&unpackedStruct)
	require.NoError(t, err)

	// Convert structpb.Struct to map[string]interface{}
	claimsMap := unpackedStruct.AsMap()

	assert.Equal(t, "helloworld", claimsMap["name"])
}
