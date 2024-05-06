package sdk

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewOIDCAuthConfig(t *testing.T) {
	expectedAccessToken := "fail"
	clientID := "idk"
	clientSecret := "secret password"
	subjectToken := "token"
	realm := "tdf"
	urlVals := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {clientID}, "client_secret": {clientSecret}, "subject_token": {subjectToken}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}
	expectedBody := urlVals.Encode()

	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body, err := io.ReadAll(req.Body)
			if req.Header.Get("X-VirtruPubKey") == "" || err != nil || string(body) != expectedBody {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			_, _ = w.Write([]byte("{\"access_token\": \"fail\", \"token_type\": \"ok\"}"))
		}),
	)
	defer s.Close()
	u, _ := url.Parse(s.URL)
	host, port, _ := net.SplitHostPort(u.Host)

	client := http.Client{}
	authConfig, err := NewOIDCAuthConfig(context.TODO(), &client, "http://"+host+":"+port, realm, clientID, clientSecret, subjectToken)
	if err != nil {
		t.Fatalf("authconfig failed: %v", err)
	}

	if authConfig.accessToken != expectedAccessToken {
		t.Fatalf("Auth token expected %s recived %s", expectedAccessToken, authConfig.accessToken)
	}
}
