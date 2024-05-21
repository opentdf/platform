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
const byClientIDOpentdfSdkResp = `[
{"id": "opentdfsdkclient", "clientId":"opentdf-sdk"}
]
`

const clientCredentialsJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE2MDQsImlhdCI6MTcxNTA5MTMwNCwianRpIjoiMTE3MTYzMjYtNWQyNS00MjlmLWFjMDItNmU0MjE2OWFjMGJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiOTljOWVlZDItOTM1Ni00ZjE2LWIwODQtZTgyZDczZjViN2QyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudEhvc3QiOiIxOTIuMTY4LjI0MC4xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXRkZi1lbnRpdHktcmVzb2x1dGlvbiIsImNsaWVudEFkZHJlc3MiOiIxOTIuMTY4LjI0MC4xIiwiY2xpZW50X2lkIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIn0.h29QLo-QvIc67KKqU_e1-x6G_o5YQccOyW9AthMdB7xhn9C1dBrcScytaWq1RfETPmnM8MXGezqN4OpXrYr-zbkHhq9ha0Ib-M1VJXNgA5sbgKW9JxGQyudmYPgn4fimDCJtAsXo7C-e3mYNm6DJS0zhGQ3msmjLTcHmIPzWlj7VjtPgKhYV75b7yr_yZNBdHjf3EZqfynU2sL8bKa1w7DYDNQve7ThtD4MeKLiuOQHa3_23dECs_ptvPVks7pLGgRKfgGHBC-KQuopjtxIhwkz2vOWRzugDl0aBJMHfwBajYhgZ2YRlV9dqSxmy8BOj4OEXuHbiyfIpY0rCRpSrGg"
const passwordPubClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE0ODAsImlhdCI6MTcxNTA5MTE4MCwianRpIjoiZmI5MmM2MTAtYmI0OC00ZDgyLTljZGQtOWFhZjllNzEyNzc3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiMmU2YzE1ODAtY2ZkMy00M2FiLWIxNzMtZjZjM2JmOGZmNGUyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uLXB1YmxpYyIsInNlc3Npb25fc3RhdGUiOiIzN2E3YjdiOS0xZmNlLTQxMmYtOTI1OS1lYzUxMTY3MGVhMGYiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIi8qIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvcGVudGRmLW9yZy1hZG1pbiIsImRlZmF1bHQtcm9sZXMtb3BlbnRkZiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJ0ZGYtZW50aXR5LXJlc29sdXRpb24iOnsicm9sZXMiOlsiZW50aXR5LXJlc29sdXRpb24tdGVzdC1yb2xlIl19LCJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJxdWVyeS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIiwicXVlcnktdXNlcnMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjM3YTdiN2I5LTFmY2UtNDEyZi05MjU5LWVjNTExNjcwZWEwZiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6InNhbXBsZSB1c2VyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2FtcGxlLXVzZXIiLCJnaXZlbl9uYW1lIjoic2FtcGxlIiwiZmFtaWx5X25hbWUiOiJ1c2VyIiwiZW1haWwiOiJzYW1wbGV1c2VyQHNhbXBsZS5jb20ifQ.Gd_OvPNY7UfY7sBKh55TcvWQHmAkYZ2Jb2VyK1lYgse9EBEa_y3uoepZYrGMGkmYdwApg4eauQjxzT_BZYVBc7u9ch3HY_IUuSh3A6FkDDXZIziByP63FYiI4vKTp0w7e2-oYAdaUTDJ1Y50-l_VvRWjdc4fqi-OKH4t8D1rlq0GJ-P7uOl44Ta43YdBMuXI146-eLqx_zLIC49Pg5Y7MD_Lv23QfGTHTP47ckUQueXoGegNLQNE9nPTuD6lNzHD5_MOqse4IKzoWVs_hs4S8SqVxVlN_ZWXkcGhPllfQtf1qxLyFm51eYH3LGxqyNbGr4nQc8djPV0yWqOTrg8IYQ"
const passwordPrivClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE0MjMsImlhdCI6MTcxNTA5MTEyMywianRpIjoiMTNhNDljZmQtOGRiZC00NTA2LTk1NGMtZWFmZGRkNGE4ZTdjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiMmU2YzE1ODAtY2ZkMy00M2FiLWIxNzMtZjZjM2JmOGZmNGUyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwic2Vzc2lvbl9zdGF0ZSI6ImNmZjYwZDZmLWI2M2MtNDBhYy1hYjI3LWFjZmU4MjY5OWQyYSIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3BlbnRkZi1vcmctYWRtaW4iLCJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGRmLWVudGl0eS1yZXNvbHV0aW9uIjp7InJvbGVzIjpbImVudGl0eS1yZXNvbHV0aW9uLXRlc3Qtcm9sZSJdfSwicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiJjZmY2MGQ2Zi1iNjNjLTQwYWMtYWIyNy1hY2ZlODI2OTlkMmEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJzYW1wbGUgdXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6InNhbXBsZS11c2VyIiwiZ2l2ZW5fbmFtZSI6InNhbXBsZSIsImZhbWlseV9uYW1lIjoidXNlciIsImVtYWlsIjoic2FtcGxldXNlckBzYW1wbGUuY29tIn0.JFWKf7GZq1f8raP3Jm6rszpwPCh0JnaeZcHyC_AwcsNS6sJ9_qSY9wrbyHmvV9KIGMIPv23fymADZXb0ng7maeAv9NR34KiJqnKbmPeeWwL0cPoGOGOUICL6H5x1iTw7XaMDN2WQRrBRFuUkudybEF8n6fEGsAvcsXViaHjYwJyIEYCnHKPzuTvM1RjyGFsERpFXKls4UB_KhMBEonr4JOskupmX1pADBuicTNx_4whnd6ZDfiF5SSBohFV1ikwFOXK-qZ7znQfE-RJ-jV1CXBgEK8O66TMbMw9MbasS25xKoO0mH1_Ohf9niSXsY02o2qjGFZA9sWRk7K7pNgsxUw"
const authPubClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTI2NDcsImlhdCI6MTcxNTA5MjM0NywiYXV0aF90aW1lIjoxNzE1MDkyMzQ3LCJqdGkiOiI3NzkwZmVhNC1hNzcyLTRhZTMtOTcyMi0yMTU2MmQyZGM5YmYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg4ODgvYXV0aC9yZWFsbXMvb3BlbnRkZiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0Ojg4ODgiLCJ0ZGYtZW50aXR5LXJlc29sdXRpb24iLCJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiIyZTZjMTU4MC1jZmQzLTQzYWItYjE3My1mNmMzYmY4ZmY0ZTIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZGYtZW50aXR5LXJlc29sdXRpb24tcHVibGljIiwic2Vzc2lvbl9zdGF0ZSI6ImFmNmViOTRiLWU4ZDQtNDNlYi1hYzYwLTI3YmZiYjNiOTQxZSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3BlbnRkZi1vcmctYWRtaW4iLCJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGRmLWVudGl0eS1yZXNvbHV0aW9uIjp7InJvbGVzIjpbImVudGl0eS1yZXNvbHV0aW9uLXRlc3Qtcm9sZSJdfSwicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiYWY2ZWI5NGItZThkNC00M2ViLWFjNjAtMjdiZmJiM2I5NDFlIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoic2FtcGxlIHVzZXIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzYW1wbGUtdXNlciIsImdpdmVuX25hbWUiOiJzYW1wbGUiLCJmYW1pbHlfbmFtZSI6InVzZXIiLCJlbWFpbCI6InNhbXBsZXVzZXJAc2FtcGxlLmNvbSJ9.BfCX_fq2Q6cv5qb6TWzyCNiJf1vFw_iA4UTKr21ahUiNItNSW5ozET2jSLwKNAuMdBNrooU--OV1NniDcviIAMReaAEgjmAyBz6OSwAh3SmxzIU9Zy7f4V032FLDcVVoJ7CefItfBNu7WnWFGS7CYahNX_M2a6LXKhk7WRO4gQ2Ig11gtODlAP8jwLLAMU4_H9mVHD3LXd-IeOsnA8ZuBCq1DeFcn5T9tNZEGe0_21lp8spxoub0MRl-vYbgxEIoaeqxoSipb2hOjF7h0h1uaNhZT4m5ynHdd5yfspD8XjjjwlbXQn9Z8vrZUQQS6HLAi2pJIFNEoYxQk9lHal6VUA"
const authPrivClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTI3NDAsImlhdCI6MTcxNTA5MjQ0MCwiYXV0aF90aW1lIjoxNzE1MDkyNDQwLCJqdGkiOiIzZjk2ZDhjNC0yMjRkLTQyNjAtYmVkMy1lOGY2N2IwYTJjM2EiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg4ODgvYXV0aC9yZWFsbXMvb3BlbnRkZiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0Ojg4ODgiLCJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiIyZTZjMTU4MC1jZmQzLTQzYWItYjE3My1mNmMzYmY4ZmY0ZTIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZGYtZW50aXR5LXJlc29sdXRpb24iLCJzZXNzaW9uX3N0YXRlIjoiZDI1ZjhhZTMtYzE0Yy00ZWFmLTkzOWMtZjhlNGIyYmE1NDY3IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvcGVudGRmLW9yZy1hZG1pbiIsImRlZmF1bHQtcm9sZXMtb3BlbnRkZiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJ0ZGYtZW50aXR5LXJlc29sdXRpb24iOnsicm9sZXMiOlsiZW50aXR5LXJlc29sdXRpb24tdGVzdC1yb2xlIl19LCJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJxdWVyeS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIiwicXVlcnktdXNlcnMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJkMjVmOGFlMy1jMTRjLTRlYWYtOTM5Yy1mOGU0YjJiYTU0NjciLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJzYW1wbGUgdXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6InNhbXBsZS11c2VyIiwiZ2l2ZW5fbmFtZSI6InNhbXBsZSIsImZhbWlseV9uYW1lIjoidXNlciIsImVtYWlsIjoic2FtcGxldXNlckBzYW1wbGUuY29tIn0.JphgIUbUeEEd25-Ji0o6_pcWvLzcQasCfr1z8WRt3xb1QrkN_d0_rmIpOJ9drhp8LjJPQRhFVxEU2TnAlYJ225IjPYolCrnEtKWsBbPJH9dP0cIJlilYplN4RZbmI9VbF578zAgVAs40n8aalNyxqYbPq_JViHDl_ufl4VEQ4Entzlp980I8whx3kfTygu0Yfl4eHLghPGt4LNPUmfeOIy8NKHbhmjHwKufrTmd0NV07cAOMUWl1NAF_4QWqmSqAY0SIcamwE7YlpuImzhj5PQH9tlyJMLr5m-k8CgKRfhpQ0H9cfVGUzWGG2A-lcNvxNmsk1kobmfHczjw13ajLKg"
const implicitPrivClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTM4MzgsImlhdCI6MTcxNTA5MjkzOCwiYXV0aF90aW1lIjoxNzE1MDkyOTM4LCJqdGkiOiI0ZWIzY2I1OS05ZDRhLTQwNjctYmI0YS1iMjNjNDVhMDIyYTIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg4ODgvYXV0aC9yZWFsbXMvb3BlbnRkZiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0Ojg4ODgiLCJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiIyZTZjMTU4MC1jZmQzLTQzYWItYjE3My1mNmMzYmY4ZmY0ZTIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZGYtZW50aXR5LXJlc29sdXRpb24iLCJzZXNzaW9uX3N0YXRlIjoiYmE1OWFmOTgtNmE3YS00YjRhLTliOTItODU1M2ZkM2EwMTNjIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6W10sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvcGVudGRmLW9yZy1hZG1pbiIsImRlZmF1bHQtcm9sZXMtb3BlbnRkZiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJ0ZGYtZW50aXR5LXJlc29sdXRpb24iOnsicm9sZXMiOlsiZW50aXR5LXJlc29sdXRpb24tdGVzdC1yb2xlIl19LCJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJxdWVyeS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIiwicXVlcnktdXNlcnMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJiYTU5YWY5OC02YTdhLTRiNGEtOWI5Mi04NTUzZmQzYTAxM2MiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJzYW1wbGUgdXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6InNhbXBsZS11c2VyIiwiZ2l2ZW5fbmFtZSI6InNhbXBsZSIsImZhbWlseV9uYW1lIjoidXNlciIsImVtYWlsIjoic2FtcGxldXNlckBzYW1wbGUuY29tIn0.KQasyQ-f9KBRWRDXg4NikiHlragVil1nlYTQ8czPKku_uncpHZb7PMJhyPrwy72mwC10EJMpBIWGDVRfRjBRHxdzIbjozcGg3vusX748NMiDSlF4KoB5Fz-qExszcszEP5Qm_fvMRFcW7m9RPW9St1aaHcjAOW5Vee9ACJI56YffgqrTn1xp7ha2Z2X8d_NJfJOFdP3cqgxjR7DV5RezkDLRPfxHwJLk3anavSuDScXIO1w1C6AlTUQFVQUEX0DKZIt-RbzKcd6HWBfyDvHUSlfodEI_diWQIL1hEfrBXV6ThuhTqhrghHyIbb2e-zoC20arjMAK0Tr7hMAY4acxgQ"
const implicitPubClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUxNTE0MTMsImlhdCI6MTcxNTE1MDUxMywiYXV0aF90aW1lIjoxNzE1MTUwNTEzLCJqdGkiOiJlYTRmOGZiYS01ZjljLTRiMzQtYmU1ZC1jNTk2ZGI4YzNlYzkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg4ODgvYXV0aC9yZWFsbXMvb3BlbnRkZiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0Ojg4ODgiLCJ0ZGYtZW50aXR5LXJlc29sdXRpb24iLCJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiIyZTZjMTU4MC1jZmQzLTQzYWItYjE3My1mNmMzYmY4ZmY0ZTIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0ZGYtZW50aXR5LXJlc29sdXRpb24tcHVibGljIiwic2Vzc2lvbl9zdGF0ZSI6ImRlM2U2ZDc1LTI3ODItNDg4NS1iYzU4LTU0MmJmYzEzNWNkNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOltdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3BlbnRkZi1vcmctYWRtaW4iLCJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGRmLWVudGl0eS1yZXNvbHV0aW9uIjp7InJvbGVzIjpbImVudGl0eS1yZXNvbHV0aW9uLXRlc3Qtcm9sZSJdfSwicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZGUzZTZkNzUtMjc4Mi00ODg1LWJjNTgtNTQyYmZjMTM1Y2Q1IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoic2FtcGxlIHVzZXIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzYW1wbGUtdXNlciIsImdpdmVuX25hbWUiOiJzYW1wbGUiLCJmYW1pbHlfbmFtZSI6InVzZXIiLCJlbWFpbCI6InNhbXBsZXVzZXJAc2FtcGxlLmNvbSJ9.jH60V3ZkuiN6cuEmbRTspnxyOvQs_wNkgoBw9IEZ8E8yGzXDayouduxEd_O-DG6vjT4KPDxGC2lA0V4i-ke7KChkZhRYLkaSuqt2hTlKoLXotepJPq8GBlXhWjCmFMqaXEB8lMAlAEoCT7CWmg03eTBGzwynj0S4rjMuOj6TLf3HIIN0DP7bgtG9uIc0Ah_mTVJ4L6Y5yjv6LC9bMZ7YNpUIkFn-CZTudquxHkLYgxHgaRAfELBvmS5xn0pTrpIfZSdYQK7hGhjhm9fUg4J06Pg6QW-xZe1U7awyNl7pOeeGQ2lVTo1CWrAlOz9lAmzKzAwQakEOMXFxAjJeHsXTWg"
const tokenExchangeJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImE1NThkYzg0NzYzNDVjY2QyZWFhNjEzNjg4YmI2YTNkIn0.eyJleHAiOjE3MTU3OTA5MTAsImlhdCI6MTcxNTc5MDYxMCwianRpIjoiNjEyOTI2NzQtMDhmOS00ZmQ1LTk3Y2MtZDg3M2RhODRkZjllIiwiaXNzIjoiaHR0cHM6Ly9sb2NhbC1kc3AudmlydHJ1LmNvbTo4NDQzL2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiYWNjb3VudCIsIm9wZW50ZGYtc2RrIl0sInN1YiI6ImU2ZWI0YWU1LThjMDUtNDI3NC04ZmExLTFmMGY1ZmJjY2JkZiIsInR5cCI6IkJlYXJlciIsImF6cCI6Im9wZW50ZGYiLCJzZXNzaW9uX3N0YXRlIjoiZTQ0YzMxNWMtNjk5Yy00NGFkLTk2NDUtNmRkMmIyMjgzN2JlIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvcGVudGRmLXJlYWRvbmx5IiwiZGVmYXVsdC1yb2xlcy1vcGVudGRmIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJlNDRjMzE1Yy02OTljLTQ0YWQtOTY0NS02ZGQyYjIyODM3YmUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1vcGVudGRmLXNkayJ9.dmAulsUNfdPXVyWmVPsbGqaztshyHTD-m2hh1l2hmhwuNISJZjON0e1kXNxYXRLABr_PJzIpGYQCXz98yxOyiw"

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

func Test_JwtClientAndUsernameClientCredentials(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: clientCredentialsJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 1)
	assert.Equal(t, "tdf-entity-resolution", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
}

func Test_JwtClientAndUsernamePasswordPub(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: passwordPubClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution-public", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndUsernamePasswordPriv(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: passwordPrivClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndUsernameAuthPub(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: authPubClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution-public", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndUsernameAuthPriv(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: authPrivClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndUsernameImplicitPub(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: implicitPubClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution-public", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndUsernameImplicitPriv(t *testing.T) {
	server := testServer(t, nil, nil, nil, nil, nil)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: implicitPrivClientJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[0].GetEntities()[1].GetUserName())
}

func Test_JwtClientAndClientTokenExchange(t *testing.T) {
	csqr := map[string]string{
		"clientId=opentdf-sdk": byClientIDOpentdfSdkResp,
	}
	server := testServer(t, nil, nil, nil, nil, csqr)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: tokenExchangeJwt}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "opentdf", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "opentdf-sdk", resp.GetEntityChains()[0].GetEntities()[1].GetClientId())
}

func Test_JwtMultiple(t *testing.T) {
	csqr := map[string]string{
		"clientId=opentdf-sdk": byClientIDOpentdfSdkResp,
	}
	server := testServer(t, nil, nil, nil, nil, csqr)
	defer server.Close()

	var kcconfig = testKeycloakConfig(server)

	var ctxb = context.Background()

	validBody := []*authorization.Token{{Jwt: tokenExchangeJwt, Id: "tok1"}, {Jwt: authPrivClientJwt, Id: "tok2"}}

	var resp, reserr = keycloak.CreateEntityChainFromJwt(ctxb, &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, kcconfig)

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 2)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 2)
	assert.Equal(t, "opentdf", resp.GetEntityChains()[0].GetEntities()[0].GetClientId())
	assert.Equal(t, "opentdf-sdk", resp.GetEntityChains()[0].GetEntities()[1].GetClientId())

	assert.Len(t, resp.GetEntityChains()[1].GetEntities(), 2)
	assert.Equal(t, "tdf-entity-resolution", resp.GetEntityChains()[1].GetEntities()[0].GetClientId())
	assert.Equal(t, "sample-user", resp.GetEntityChains()[1].GetEntities()[1].GetUserName())
}
