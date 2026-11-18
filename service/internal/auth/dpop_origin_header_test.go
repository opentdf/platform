package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (s *AuthSuite) Test_MuxHandler_UsesRequestHostInsteadOfOriginHeader() {
	const path = "/attributes/example/value"
	for _, tc := range []struct {
		name   string
		url    string
		origin string
		want   string
	}{
		{"no Origin", "https://platform.example.com" + path, "", "https://platform.example.com" + path},
		{"browser Origin", "https://platform.example.com" + path, "https://app.example.com", "https://platform.example.com" + path},
		{"forged Origin", "https://platform.example.com" + path, "https://other.example.com", "https://platform.example.com" + path},
		{"null Origin", "https://platform.example.com" + path, "null", "https://platform.example.com" + path},
		{"proxy rewrites Host", "http://platform.internal:8080" + path, "https://platform.example.com", "http://platform.internal:8080" + path},
	} {
		s.Run(tc.name, func() {
			var received receiverInfo
			called := false
			s.auth._testCheckTokenFunc = func(_ context.Context, _ []string, got receiverInfo, _ []string) (jwt.Token, context.Context, error) {
				called = true
				received = got
				return nil, nil, errors.New("captured expected URI")
			}
			defer func() { s.auth._testCheckTokenFunc = nil }()

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Header.Set("Authorization", "DPoP token")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			s.auth.MuxHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

			s.Require().True(called, "the HTTP handler must check the DPoP receiver URI")
			s.Equal([]string{tc.want}, received.u)
		})
	}
}
