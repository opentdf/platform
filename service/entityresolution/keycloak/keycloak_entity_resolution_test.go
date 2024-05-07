package entityresolution_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	keycloak "github.com/opentdf/platform/service/entityresolution/keycloak"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const tokenResp string = `
{ 
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "token_type": "Bearer",
  "expires_in": 3600,
}`

const byEmailBobResp = `[
{"id": "bobid", "username":"bob.smith"}
]
`
const byEmailAliceResp = `[
{"id": "aliceid", "username":"alice.smith"}
]
`

const byUsernameBobResp = `[
{"id": "bobid", "username":"bob.smith"}
]`

const byUsernameAliceResp = `[
{"id": "aliceid", "username":"alice.smith"}
]`

const groupSubmemberResp = `[
	{"id": "bobid", "username":"bob.smith"},
	{"id": "aliceid", "username":"alice.smith"}
]`
const groupResp = `{
	"id": "group1-uuid",
	"name": "group1"
}`

func testKeycloakConfig(server *httptest.Server) keycloak.KeycloakConfig {
	return keycloak.KeycloakConfig{
		URL:            server.URL,
		ClientID:       "c1",
		ClientSecret:   "cs",
		Realm:          "tdf",
		LegacyKeycloak: false,
	}
}

func testServerResp(t *testing.T, w http.ResponseWriter, r *http.Request, k string, reqRespMap map[string]string) {
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
func testServer(t *testing.T, userSearchQueryAndResp map[string]string, groupSearchQueryAndResp map[string]string,
	groupByIDAndResponse map[string]string, groupMemberQueryAndResponse map[string]string, clientsSearchQueryAndResp map[string]string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/realms/tdf/protocol/openid-connect/token":
			_, err := io.WriteString(w, tokenResp)
			if err != nil {
				t.Error(err)
			}
		case r.URL.Path == "/admin/realms/tdf/clients":
			testServerResp(t, w, r, r.URL.RawQuery, clientsSearchQueryAndResp)
		case r.URL.Path == "/admin/realms/tdf/users":
			testServerResp(t, w, r, r.URL.RawQuery, userSearchQueryAndResp)
		case r.URL.Path == "/admin/realms/tdf/groups" && groupSearchQueryAndResp != nil:
			testServerResp(t, w, r, r.URL.RawQuery, groupSearchQueryAndResp)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/tdf/groups") &&
			strings.HasSuffix(r.URL.Path, "members") && groupMemberQueryAndResponse != nil:
			groupID := r.URL.Path[len("/admin/realms/tdf/groups/"):strings.LastIndex(r.URL.Path, "/")]
			testServerResp(t, w, r, groupID, groupMemberQueryAndResponse)
		case strings.HasPrefix(r.URL.Path, "/admin/realms/tdf/groups") && groupByIDAndResponse != nil:
			groupID := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			testServerResp(t, w, r, groupID, groupByIDAndResponse)
		default:
			t.Errorf("UnExpected Request, got: %s", r.URL.Path)
		}
	}))
	return server
}

func Test_KCEntityResolutionByClientId(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf"}})

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody
	csqr := map[string]string{
		"clientId=opentdf": byEmailBobResp,
	}
	server := testServer(t, nil, nil, nil, nil, csqr)
	defer server.Close()
	var kcconfig = testKeycloakConfig(server)

	var resp, reserr = keycloak.EntityResolution(ctxb, &req, kcconfig)

	require.NoError(t, reserr)
	_ = json.NewEncoder(os.Stdout).Encode(&resp)
	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)
}

func Test_KCEntityResolutionByEmail(t *testing.T) {
	server := testServer(t, map[string]string{
		"email=bob%40sample.org&exact=true":   byEmailBobResp,
		"email=alice%40sample.org&exact=true": byEmailAliceResp,
	}, nil, nil, nil, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@sample.org"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "alice@sample.org"}})

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = keycloak.EntityResolution(ctxb, &req, kcconfig)

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 2)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])

	assert.Equal(t, "1235", entityRepresentations[1].GetOriginalId())
	assert.Len(t, entityRepresentations[1].GetAdditionalProps(), 1)
	propMap = entityRepresentations[1].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionByUsername(t *testing.T) {
	server := testServer(t, map[string]string{
		"exact=true&username=bob.smith":   byUsernameBobResp,
		"exact=true&username=alice.smith": byUsernameAliceResp,
	}, nil, nil, nil, nil)
	defer server.Close()

	// validBody := `{"entity_identifiers": [{"type": "username","identifier": "bob.smith"}]}`
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_UserName{UserName: "alice.smith"}})

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = keycloak.EntityResolution(ctxb, &req, kcconfig)

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 2)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])

	assert.Equal(t, "1235", entityRepresentations[1].GetOriginalId())
	assert.Len(t, entityRepresentations[1].GetAdditionalProps(), 1)
	propMap = entityRepresentations[1].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionByGroupEmail(t *testing.T) {
	server := testServer(t, map[string]string{
		"email=group1%40sample.org&exact=true": "[]",
	}, map[string]string{
		"search=group1%40sample.org": `[{"id":"group1-uuid"}]`,
	}, map[string]string{
		"group1-uuid": groupResp,
	}, map[string]string{
		"group1-uuid": groupSubmemberResp,
	},
		nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "123456", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "group1@sample.org"}})

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = keycloak.EntityResolution(ctxb, &req, kcconfig)

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "123456", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 2)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])
	propMap = entityRepresentations[0].GetAdditionalProps()[1].AsMap()
	assert.Equal(t, "aliceid", propMap["id"])
}

func Test_KCEntityResolutionNotFoundError(t *testing.T) {
	server := testServer(t, map[string]string{
		"email=random%40sample.org&exact=true": "[]",
	}, map[string]string{
		"search=random%40sample.org": "[]",
	}, map[string]string{
		"group1-uuid": groupResp,
	}, map[string]string{
		"group1-uuid": groupSubmemberResp,
	}, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "random@sample.org"}})

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	var req = entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	var resp, reserr = keycloak.EntityResolution(ctxb, &req, kcconfig)

	require.Error(t, reserr)
	assert.Equal(t, &entityresolution.ResolveEntitiesResponse{}, &resp)
	var entityNotFound = entityresolution.EntityNotFoundError{Code: int32(codes.NotFound), Message: keycloak.ErrTextGetRetrievalFailed, Entity: "random@sample.org"}
	var expectedError = errors.New(entityNotFound.String())
	assert.Equal(t, expectedError, reserr)
}
