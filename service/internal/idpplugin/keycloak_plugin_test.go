package idpplugin_test

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
	"github.com/opentdf/platform/service/internal/db"
	"github.com/opentdf/platform/service/internal/idpplugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const tokenResp string = `
{ 
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "token_type": "Bearer",
  "expires_in": 3600,
}`

const certResp string = `
{
	"keys": [
		{
		"kid": "jYuvQBmT72CPQOJLY_Tp2AzvUNek15MBjiwapDeve90",
		"kty": "RSA",
		"alg": "RSA-OAEP",
		"use": "enc",
		"n": "yQunQMU4biAU4JkgOGMMjFcGghuIGu0F2MDk88hsrPHn7vEz5ua2CqGJCzsOJUOheI7aQueB5PUlbyfC0e8lm67YgV0qx6_rhNUZpiU3Ykqf0B-3bSa5sZyNI73VqkOfx-_0Rz4NtSnuHQk93H7gap8Xin7WoTShwnffvXYgLD2w36fpV5rxbjYm71uD5Q_-lrsAbq96IygiZ8qqLn61V5pEFozDFbxzBi-GAw0yr7PgWTcH6-6__u3FTfQJqcYTiNAD0PXR20CYq5u5Xb5yXvKLxZlioQxIU7FzhguS78eyJSTBZh5GPIW9IhkZxVUyfa9LsS2NX57htmaNo3NcbQ",
		"e": "AQAB",
		"x5c": [
			"MIICnTCCAYUCBgGPBu3xhzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdvcGVudGRmMB4XDTI0MDQyMjE3NDgyOFoXDTM0MDQyMjE3NTAwOFowEjEQMA4GA1UEAwwHb3BlbnRkZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkLp0DFOG4gFOCZIDhjDIxXBoIbiBrtBdjA5PPIbKzx5+7xM+bmtgqhiQs7DiVDoXiO2kLngeT1JW8nwtHvJZuu2IFdKsev64TVGaYlN2JKn9Aft20mubGcjSO91apDn8fv9Ec+DbUp7h0JPdx+4GqfF4p+1qE0ocJ33712ICw9sN+n6Vea8W42Ju9bg+UP/pa7AG6veiMoImfKqi5+tVeaRBaMwxW8cwYvhgMNMq+z4Fk3B+vuv/7txU30CanGE4jQA9D10dtAmKubuV2+cl7yi8WZYqEMSFOxc4YLku/HsiUkwWYeRjyFvSIZGcVVMn2vS7EtjV+e4bZmjaNzXG0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAnimOVTobEfCa9DtAKccCrpqaahX2wwwgNdRdr3ZbKnY2IpAZcJ310x8Fe1FPNc0Rh5vpwzA2xRNyQ1DwQJsxDn9unRmJv9OTvxDGJQdoA26WCeU6CjAM93c1n1+lLWrufOaAjkU/MyyuYRbjYzsgFSkf/K7hKyt6lWYYGfHNVTPaGURWPKas+eeQyWBpuRzEN418Sj0WmwMLmpRo4+oX3S7KgwqIBEOPj6+U8MsKm21d7vlFsoEQy79/Y6nUvril936q+UuvnnrT0rMZkkTlrFeN+5j+GLwPiMewgoqhCZN7N95OZX8vUaqe68ZPp50bnCAK20kw7S65BUlXjyCxeA=="
		],
		"x5t": "8hYmNEWXjLqaE1S9CPekBrBwsTY",
		"x5t#S256": "x0sDp4U3yd2X8L4nR5hhFSmJl1ApkLIeYqk8XMNYj9I"
		},
		{
		"kid": "NKuxDjaBWC7U5jw349EvLkymNMlb7w_ZwcfRFAagXDA",
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"n": "lpZ0PehK_Qmlyg6kCxN75ePsaQ2C4XDMWmIBSIbShbLufQwNLxXbHOwRz2LUXF4lLyRdttPk31sJb9TRdnTPkmfoCMnaMhSY8Vd71mQZExMAb6XtpWvHqF0_ebr4tSYStXAQFVYvOO2ktJwAXcOxafC3QH7iuT6mr8IG55QIHdOifDKgk649F8XflkIChdUqoFtNv5nftCr-RpUdddhXkyxwkaguYhjuV21b0AYJFrYdzpictUS-ywEQt6DDnco8tB07FAxCbIt5Kc5WpN0_cQsTqZXrP6CEVbPUx07xOkSzYi73clOzX8ltAUs8A3Rukzxx8ySAZTTCwr14aHG1rQ",
		"e": "AQAB",
		"x5c": [
			"MIICnTCCAYUCBgGPBu3vvjANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdvcGVudGRmMB4XDTI0MDQyMjE3NDgyN1oXDTM0MDQyMjE3NTAwN1owEjEQMA4GA1UEAwwHb3BlbnRkZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJaWdD3oSv0JpcoOpAsTe+Xj7GkNguFwzFpiAUiG0oWy7n0MDS8V2xzsEc9i1FxeJS8kXbbT5N9bCW/U0XZ0z5Jn6AjJ2jIUmPFXe9ZkGRMTAG+l7aVrx6hdP3m6+LUmErVwEBVWLzjtpLScAF3DsWnwt0B+4rk+pq/CBueUCB3TonwyoJOuPRfF35ZCAoXVKqBbTb+Z37Qq/kaVHXXYV5MscJGoLmIY7ldtW9AGCRa2Hc6YnLVEvssBELegw53KPLQdOxQMQmyLeSnOVqTdP3ELE6mV6z+ghFWz1MdO8TpEs2Iu93JTs1/JbQFLPAN0bpM8cfMkgGU0wsK9eGhxta0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAFh0d/E0+hRc4b959Nv7m9vz1MLfyKxTpdplu9OhjuRSA4Zj/Q+J27tVt/UF/sakHT+ikcdkiIh2M8pnGC2oCp4w0XWhvK5heU+2xU9/6YqrLxTxsVtgiE+befcQ3VT4aJIGRO9FpYIwPmZfdhhqL5d9lh94gu4ahBIgTelIF68xbf9ry6GBynF9e16N75WB6iNC9B1Y5oeOGBJlY165/dXi331ScA8sT1CFj6UJr7NbkRfGcj9Sr/Fy2ie3ZG3plo+yAgbhj24VTS08RWM/AHnK4GweDWsY9TEj6jD7MblYwmx/aJ43RnGRmi3PaJCfkMlObMZDd2hHyAL1vP9q/Kg=="
		],
		"x5t": "iC1duZ-4fC4L5Y2jh9N7BqO1698",
		"x5t#S256": "y5jUwKh57sDCofXC-_LKMstDUFmYsz8VWj1nGJgv2y8"
		}
	]
}
`
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

const bobJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOS3V4RGphQldDN1U1anczNDlFdkxreW1OTWxiN3dfWndjZlJGQWFnWERBIn0.eyJleHAiOjIxNDU4MTA4NTUsImlhdCI6MTcxMzgxMDg1NSwianRpIjoiNGM2MGZkN2MtZTkyOS00NmI5LWJlMGQtNzgwNTgzN2NlODI0IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiZDRjOTNjOGQtYjY4MS00NGVhLWI4NTEtMGY3YjA3ODcwZDVjIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdGNsaWVudCIsInNlc3Npb25fc3RhdGUiOiI0N2UyM2Y3Ny0xMWJjLTQ4M2UtYmI4Ni02M2EyNjcyNDVhNmUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtb3BlbnRkZiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiI0N2UyM2Y3Ny0xMWJjLTQ4M2UtYmI4Ni02M2EyNjcyNDVhNmUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImJvYiBzbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImJvYi5zbWl0aCIsImdpdmVuX25hbWUiOiJib2IiLCJmYW1pbHlfbmFtZSI6InNtaXRoIiwiZW1haWwiOiJib2JAc2FtcGxlLm9yZyJ9.ZeMOV3gq9zduwVBdAahW6yHz5RC_nC7kgEq-qL51rp7-YRESri_meXISLA1AEOdmIcorXHM55H-mV84X0D1D7g9AlSjxqwU-_wiL5qnVQwbx2KVyaJ2YfRni5lOZ4HnZi9yIo7sBQISaswf7GYieCJ4d1y6VoC2v9401sTK2q6A_EGI3XMBZfyWOdGYRjp6OuTsjlpKgW8y9IDHEVZhHujjwz7gUVzHrW74ZYWM_PQhC4dLTofDJz0DwiqcwoKtovnJHlaqfKoBWTma6bBYJ8fEiGu8gH1Yv06JNnFAG3Fav1HerB0Qow6sBOpGlswayoBMsWF9uirqHcXe6zGc65Q"
const testclientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOS3V4RGphQldDN1U1anczNDlFdkxreW1OTWxiN3dfWndjZlJGQWFnWERBIn0.eyJleHAiOjIxNDU4MTEwMjYsImlhdCI6MTcxMzgxMTAyNiwianRpIjoiNTJkZjk0N2EtNmUzMS00MmQzLTkxMjUtNGI2NGFmM2I3NjE1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMjg4NjZjYmEtY2RkZS00MzAwLTgzNTctYWQxNzE0YTA1NWZlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdGNsaWVudCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1vcGVudGRmIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImNsaWVudEhvc3QiOiIxOTIuMTY4Ljk2LjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10ZXN0Y2xpZW50IiwiY2xpZW50QWRkcmVzcyI6IjE5Mi4xNjguOTYuMSIsImNsaWVudF9pZCI6InRlc3RjbGllbnQifQ.busdqj7LABioVqzWFD6cDTSkeo7F1dVdTB34EIHrjcP9BRQRNzbtLq5B-g6juIIHqRGF50rOpgmOuWPqymLCEm-9zloGeV6tj6Jv2MOrfH82vepo5yB-NutGc1o31Rw6vXvrrMj8hXKc5cNsPZDgRiToVcCs5OgjNjuS-nD1cwBzh3J-_jI64ILzugJMYVituLw85mYiBuZxA5t6_PSliw2mR-9AnBv1O1d4ZOVkbphKwHNQlaYkgm5U9TmcSX2ud_mOeIhcq9v3Ay18sKptwy9yEFOAXKSpSRxs1NDTGfJO4-k5g2l5FkRJRsGysWJdtqauow8pZxJVkVpkkA2wTw"

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
	groupByIdAndResponse map[string]string, groupMemberQueryAndResponse map[string]string, clientsSearchQueryAndResp map[string]string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/tdf/protocol/openid-connect/token" {
			_, err := io.WriteString(w, tokenResp)
			if err != nil {
				t.Error(err)
			}
		} else if r.URL.Path == "/realms/tdf/protocol/openid-connect/certs" {
			w.Header().Set("Content-Type", "application/json")
			_, err := io.WriteString(w, certResp)
			if err != nil {
				t.Error(err)
			}
		} else if r.URL.Path == "/admin/realms/tdf/clients" {
			test_server_resp(t, w, r, r.URL.RawQuery, clientsSearchQueryAndResp)
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

func Test_KCEntityResolutionByJwtUsername(t *testing.T) {
	server := test_server(t, map[string]string{
		"exact=true&username=bob.smith": by_username_bob_resp,
	}, nil, nil, nil, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_Jwt{Jwt: bobJwt}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])
}

func Test_KCEntityResolutionByJwtClientID(t *testing.T) {
	server := test_server(t, nil, nil, nil, nil, map[string]string{
		"clientId=testclient": by_email_bob_resp,
	})
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_Jwt{Jwt: testclientJwt}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])
}

func Test_KCEntityResolutionByClientId(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_ClientId{ClientId: "opentdf"}})

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody
	csqr := map[string]string{
		"clientId=opentdf": by_email_bob_resp,
	}
	server := test_server(t, nil, nil, nil, nil, csqr)
	defer server.Close()
	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{
		Config: kcConfigStruct,
	})

	require.NoError(t, reserr)
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)
}

func Test_KCEntityResolutionByEmail(t *testing.T) {
	server := test_server(t, map[string]string{
		"email=bob%40sample.org&exact=true":   by_email_bob_resp,
		"email=alice%40sample.org&exact=true": by_email_alice_resp,
	}, nil, nil, nil, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@sample.org"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "alice@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

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
	server := test_server(t, map[string]string{
		"exact=true&username=bob.smith":   by_username_bob_resp,
		"exact=true&username=alice.smith": by_username_alice_resp,
	}, nil, nil, nil, nil)
	defer server.Close()

	// validBody := `{"entity_identifiers": [{"type": "username","identifier": "bob.smith"}]}`
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_UserName{UserName: "bob.smith"}})
	validBody = append(validBody, &authorization.Entity{Id: "1235", EntityType: &authorization.Entity_UserName{UserName: "alice.smith"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

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
	server := test_server(t, map[string]string{
		"email=group1%40sample.org&exact=true": "[]",
	}, map[string]string{
		"search=group1%40sample.org": `[{"id":"group1-uuid"}]`,
	}, map[string]string{
		"group1-uuid": group_resp,
	}, map[string]string{
		"group1-uuid": group_submember_resp,
	},
		nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "123456", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "group1@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	require.NoError(t, reserr)

	var entityRepresentations = resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Equal(t, 1, len(entityRepresentations))

	assert.Equal(t, "123456", entityRepresentations[0].GetOriginalId())
	assert.Equal(t, 2, len(entityRepresentations[0].GetAdditionalProps()))
	var propMap = entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bobid", propMap["id"])
	propMap = entityRepresentations[0].GetAdditionalProps()[1].AsMap()
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
	}, nil)
	defer server.Close()

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "random@sample.org"}})

	var kcconfig = test_keycloakConfig(server)
	var kcConfigInterface map[string]interface{}
	inrec, err := json.Marshal(kcconfig)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(inrec, &kcConfigInterface))
	kcConfigStruct, err := structpb.NewStruct(kcConfigInterface)
	require.NoError(t, err)

	var ctxb = context.Background()

	var req = authorization.IdpPluginRequest{}
	req.Entities = validBody

	var resp, reserr = idpplugin.EntityResolution(ctxb, &req, &authorization.IdpConfig{Config: kcConfigStruct})

	assert.Error(t, reserr)
	assert.Equal(t, &authorization.IdpPluginResponse{}, resp)
	var entityNotFound = authorization.EntityNotFoundError{Code: int32(codes.NotFound), Message: db.ErrTextGetRetrievalFailed, Entity: "random@sample.org"}
	var expectedError = errors.New(entityNotFound.String())
	assert.Equal(t, expectedError, reserr)
}
