package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectMissingKASPrefixHandler tests the behavior of the redirectMissingKASPrefixHandler
func TestRedirectMissingKASPrefixHandler(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		queryString        string
		expectedStatusCode int
		expectedLocation   string
		shouldRedirect     bool
	}{
		{
			name:               "v2 kas_public_key without trailing slash",
			path:               "/v2/kas_public_key",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/v2/kas_public_key",
			shouldRedirect:     true,
		},
		{
			name:               "v2 kas_public_key with trailing slash",
			path:               "/v2/kas_public_key/",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/v2/kas_public_key/",
			shouldRedirect:     true,
		},
		{
			name:               "kas_public_key without trailing slash",
			path:               "/kas_public_key",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/kas_public_key",
			shouldRedirect:     true,
		},
		{
			name:               "kas_public_key with trailing slash",
			path:               "/kas_public_key/",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/kas_public_key/",
			shouldRedirect:     true,
		},
		{
			name:               "v2 rewrap without trailing slash",
			path:               "/v2/rewrap",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/v2/rewrap",
			shouldRedirect:     true,
		},
		{
			name:               "v2 rewrap with trailing slash",
			path:               "/v2/rewrap/",
			queryString:        "",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/v2/rewrap/",
			shouldRedirect:     true,
		},
		{
			name:               "with query parameters",
			path:               "/v2/rewrap",
			queryString:        "param1=value1&param2=value2",
			expectedStatusCode: http.StatusMovedPermanently,
			expectedLocation:   "/kas/v2/rewrap?param1=value1&param2=value2",
			shouldRedirect:     true,
		},
		{
			name:           "unrelated path should not redirect",
			path:           "/some/other/path",
			shouldRedirect: false,
		},
		{
			name:           "path already prefixed with /kas should not redirect",
			path:           "/kas/v2/kas_public_key",
			shouldRedirect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a handler that always returns 200 OK
			mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap it with our redirect handler
			handler := redirectMissingKASPrefixHandler(mockHandler)

			// Create a test request with the test path
			url := tc.path
			if tc.queryString != "" {
				url += "?" + tc.queryString
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()

			// Send the request through our handler
			handler.ServeHTTP(rec, req)

			if tc.shouldRedirect { //nolint:nestif // Nested to keep the test cases together
				// Check that we got a redirect response
				if rec.Code != tc.expectedStatusCode {
					t.Errorf("Expected status code %d, got %d", tc.expectedStatusCode, rec.Code)
				}

				// Check the redirect location
				location := rec.Header().Get("Location")
				if location != tc.expectedLocation {
					t.Errorf("Expected redirect to %q, got %q", tc.expectedLocation, location)
				}
			} else {
				// Check that we didn't get a redirect
				if rec.Code != http.StatusOK {
					t.Errorf("Expected status code %d, got %d", http.StatusOK, rec.Code)
				}
				if rec.Header().Get("Location") != "" {
					t.Errorf("Did not expect a Location header, but got %q", rec.Header().Get("Location"))
				}
			}
		})
	}
}
