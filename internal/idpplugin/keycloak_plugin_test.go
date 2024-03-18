package idpplugin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opentdf/platform/internal/idpplugin"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

//nolint:gosec
const token_resp string = `
{ 
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "token_type": "Bearer",
  "expires_in": 3600,
}`

const by_email_bob_resp = `[
{"id": "bobid", "username":"bob.smith"}
]
`
const by_email_alice_resp = `[
{"id": "aliceid", "username":"alice.smith"}
]
`

const by_username_bob_resp = `[
{"id": "bobid", "username":"bob.smith"}
]`

const by_username_alice_resp = `[
{"id": "aliceid", "username":"alice.smith"}
]`

const group_submember_resp = `[
	{"id": "bobid", "username":"bob.smith"},
	{"id": "aliceid", "username":"alice.smith"}
]`
const group_resp = `{
	"id": "group1-uuid",
	"name": "group1"
}`

func test_keycloakConfig(server *httptest.Server) idpplugin.KeyCloakConfig {
	return idpplugin.KeyCloakConfig{
		Url:            server.URL,
		ClientId:       "c1",
		ClientSecret:   "cs",
		Realm:          "tdf",
		LegacyKeycloak: false,
	}
}

func test_server_resp(t *testing.T, w http.ResponseWriter, r *http.Request, k string, reqRespMap map[string]string) {
	i, ok := reqRespMap[k]
	if ok == true {
		w.Header().Set("Content-Type", "application/json")
		_, err := io.WriteString(w, i)
		if err != nil {
			t.Error(err)
		}
	} else {
		t.Errorf("UnExpected Request, got: %s", r.URL.Path)
	}
}
func test_server(t *testing.T, userSearchQueryAndResp map[string]string, groupSearchQueryAndResp map[string]string,
	groupByIdAndResponse map[string]string, groupMemberQueryAndResponse map[string]string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/tdf/protocol/openid-connect/token" {
			_, err := io.WriteString(w, token_resp)
			if err != nil {
				t.Error(err)
			}
		} else if r.URL.Path == "/admin/realms/tdf/users" {
			test_server_resp(t, w, r, r.URL.RawQuery, userSearchQueryAndResp)
		} else if r.URL.Path == "/admin/realms/tdf/groups" && groupSearchQueryAndResp != nil {
			test_server_resp(t, w, r, r.URL.RawQuery, groupSearchQueryAndResp)
		} else if strings.HasPrefix(r.URL.Path, "/admin/realms/tdf/groups") &&
			strings.HasSuffix(r.URL.Path, "members") && groupMemberQueryAndResponse != nil {
			groupId := r.URL.Path[len("/admin/realms/tdf/groups/"):strings.LastIndex(r.URL.Path, "/")]
			test_server_resp(t, w, r, groupId, groupMemberQueryAndResponse)
		} else if strings.HasPrefix(r.URL.Path, "/admin/realms/tdf/groups") && groupByIdAndResponse != nil {
			groupId := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			test_server_resp(t, w, r, groupId, groupByIdAndResponse)
		} else {
			t.Errorf("UnExpected Request, got: %s", r.URL.Path)
		}
	}))
	return server
}

func Test_KCEntityResolutionByEmail(t *testing.T) {

	server := test_server(t, map[string]string{
		"email=bob%40sample.org&exact=true":   by_email_bob_resp,
		"email=alice%40sample.org&exact=true": by_email_alice_resp,
	}, nil, nil, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@sample.org"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "alice@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	assert.Nil(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	assert.Nil(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	assert.Nil(t, reserr)

	var entity_representations = resp.GetEntityRepresentations()
	assert.NotNil(t, entity_representations)
	assert.Equal(t, 2, len(entity_representations))

	assert.Equal(t, "1234", entity_representations[0].OriginalId)
	assert.Equal(t, 1, len(entity_representations[0].AdditionalProps))
	var propMap = entity_representations[0].AdditionalProps[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])

	assert.Equal(t, "1235", entity_representations[1].OriginalId)
	assert.Equal(t, 1, len(entity_representations[1].AdditionalProps))
	propMap = entity_representations[1].AdditionalProps[0].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionByUsername(t *testing.T) {
	server := test_server(t, map[string]string{
		"exact=true&username=bob.smith":   by_username_bob_resp,
		"exact=true&username=alice.smith": by_username_alice_resp,
	}, nil, nil, nil)
	defer server.Close()

	// validBody := `{"entity_identifiers": [{"type": "username","identifier": "bob.smith"}]}`
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_UserName{UserName: "alice.smith"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	assert.Nil(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	assert.Nil(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	assert.Nil(t, reserr)

	var entity_representations = resp.GetEntityRepresentations()
	assert.NotNil(t, entity_representations)
	assert.Equal(t, 2, len(entity_representations))

	assert.Equal(t, "1234", entity_representations[0].OriginalId)
	assert.Equal(t, 1, len(entity_representations[0].AdditionalProps))
	var propMap = entity_representations[0].AdditionalProps[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])

	assert.Equal(t, "1235", entity_representations[1].OriginalId)
	assert.Equal(t, 1, len(entity_representations[1].AdditionalProps))
	propMap = entity_representations[1].AdditionalProps[0].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionByGroupEmail(t *testing.T) {
	server := test_server(t, map[string]string{
		"email=group1%40sample.org&exact=true": "[]",
	}, map[string]string{
		"search=group1%40sample.org": `[{"id":"group1-uuid"}]`,
	}, map[string]string{
		"group1-uuid": group_resp,
	}, map[string]string{
		"group1-uuid": group_submember_resp,
	})
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "123456", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "group1@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	assert.Nil(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	assert.Nil(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	assert.Nil(t, reserr)

	var entity_representations = resp.GetEntityRepresentations()
	assert.NotNil(t, entity_representations)
	assert.Equal(t, 1, len(entity_representations))

	assert.Equal(t, "123456", entity_representations[0].OriginalId)
	assert.Equal(t, 2, len(entity_representations[0].AdditionalProps))
	var propMap = entity_representations[0].AdditionalProps[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])
	propMap = entity_representations[0].AdditionalProps[1].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionNotFoundError(t *testing.T) {

	server := test_server(t, map[string]string{
		"email=random%40sample.org&exact=true": "[]",
	}, map[string]string{
		"search=random%40sample.org": "[]",
	}, map[string]string{
		"group1-uuid": group_resp,
	}, map[string]string{
		"group1-uuid": group_submember_resp,
	})
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "random@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	assert.Nil(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	assert.Nil(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	assert.NotNil(t, reserr)
	assert.Equal(t, &authorization.IdpPluginResponse{}, resp)
	var entityNotFound = authorization.EntityNotFoundError{Code: int32(codes.NotFound), Message: services.ErrGetRetrievalFailed, Entity: "random@sample.org"}
	var expectedError = errors.New(entityNotFound.String())
	assert.Equal(t, expectedError, reserr)
}
