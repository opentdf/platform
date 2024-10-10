package entityresolution_test

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	dummy "github.com/opentdf/platform/service/entityresolution/dummy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const samplejwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhlbGxvd29ybGQiLCJpYXQiOjE1MTYyMzkwMjJ9.EAOittOMzKENEAs44eaMuZe-xas7VNVsgBxhwmxYiIw" //"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE2MDQsImlhdCI6MTcxNTA5MTMwNCwianRpIjoiMTE3MTYzMjYtNWQyNS00MjlmLWFjMDItNmU0MjE2OWFjMGJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiOTljOWVlZDItOTM1Ni00ZjE2LWIwODQtZTgyZDczZjViN2QyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudEhvc3QiOiIxOTIuMTY4LjI0MC4xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXRkZi1lbnRpdHktcmVzb2x1dGlvbiIsImNsaWVudEFkZHJlc3MiOiIxOTIuMTY4LjI0MC4xIiwiY2xpZW50X2lkIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIn0.h29QLo-QvIc67KKqU_e1-x6G_o5YQccOyW9AthMdB7xhn9C1dBrcScytaWq1RfETPmnM8MXGezqN4OpXrYr-zbkHhq9ha0Ib-M1VJXNgA5sbgKW9JxGQyudmYPgn4fimDCJtAsXo7C-e3mYNm6DJS0zhGQ3msmjLTcHmIPzWlj7VjtPgKhYV75b7yr_yZNBdHjf3EZqfynU2sL8bKa1w7DYDNQve7ThtD4MeKLiuOQHa3_23dECs_ptvPVks7pLGgRKfgGHBC-KQuopjtxIhwkz2vOWRzugDl0aBJMHfwBajYhgZ2YRlV9dqSxmy8BOj4OEXuHbiyfIpY0rCRpSrGg"

func Test_ClientResolveEntity(t *testing.T) {

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_ClientId{ClientId: "random"}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = dummy.EntityResolution(ctxb, &req, logger.CreateTestLogger())

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

	var resp, reserr = dummy.EntityResolution(ctxb, &req, logger.CreateTestLogger())

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

	claims := map[string]interface{}{
		"foo": "bar",
		"baz": 42,
	}
	// Convert map[string]interface{} to *structpb.Struct
	structClaims, err := structpb.NewStruct(claims)
	require.NoError(t, err)

	// Wrap the struct in an *anypb.Any
	anyClaims, err := anypb.New(structClaims)
	require.NoError(t, err)

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_Claims{Claims: anyClaims}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = dummy.EntityResolution(ctxb, &req, logger.CreateTestLogger())

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

	var resp, reserr = dummy.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, logger.CreateTestLogger())

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
