package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/cors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeStringSlices(t *testing.T) {
	tests := []struct {
		name       string
		base       []string
		additional []string
		want       []string
	}{
		{
			name:       "empty additional returns base",
			base:       []string{"A", "B"},
			additional: nil,
			want:       []string{"A", "B"},
		},
		{
			name:       "empty base returns additional",
			base:       nil,
			additional: []string{"A", "B"},
			want:       []string{"A", "B"},
		},
		{
			name:       "merge without duplicates",
			base:       []string{"A", "B"},
			additional: []string{"C", "D"},
			want:       []string{"A", "B", "C", "D"},
		},
		{
			name:       "merge with duplicates removed",
			base:       []string{"A", "B", "C"},
			additional: []string{"B", "D"},
			want:       []string{"A", "B", "C", "D"},
		},
		{
			name:       "both empty returns nil",
			base:       nil,
			additional: nil,
			want:       nil,
		},
		{
			name:       "preserves order - base first then additional",
			base:       []string{"Z", "A"},
			additional: []string{"M", "B"},
			want:       []string{"Z", "A", "M", "B"},
		},
		{
			name:       "deduplicates within base",
			base:       []string{"A", "B", "A"},
			additional: []string{"C"},
			want:       []string{"A", "B", "C"},
		},
		{
			name:       "case sensitive comparison",
			base:       []string{"Accept"},
			additional: []string{"accept", "ACCEPT"},
			want:       []string{"Accept", "accept", "ACCEPT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeStringSlices(tt.base, tt.additional)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveMethods(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional methods",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST"},
				AdditionalMethods: nil,
			},
			want: []string{"GET", "POST"},
		},
		{
			name: "with additional methods",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST"},
				AdditionalMethods: []string{"PUT", "DELETE"},
			},
			want: []string{"GET", "POST", "PUT", "DELETE"},
		},
		{
			name: "additional methods with duplicate",
			cfg: CORSConfig{
				AllowedMethods:    []string{"GET", "POST", "PUT"},
				AdditionalMethods: []string{"PUT", "DELETE"},
			},
			want: []string{"GET", "POST", "PUT", "DELETE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveMethods()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeHeaderSlices(t *testing.T) {
	tests := []struct {
		name       string
		base       []string
		additional []string
		want       []string
	}{
		{
			name:       "empty additional returns base",
			base:       []string{"Authorization", "Content-Type"},
			additional: nil,
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "empty base returns additional",
			base:       nil,
			additional: []string{"Authorization", "Content-Type"},
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "merge without duplicates",
			base:       []string{"Authorization"},
			additional: []string{"Content-Type"},
			want:       []string{"Authorization", "Content-Type"},
		},
		{
			name:       "case-insensitive deduplication preserves first occurrence",
			base:       []string{"Authorization"},
			additional: []string{"authorization", "AUTHORIZATION"},
			want:       []string{"Authorization"},
		},
		{
			name:       "mixed case duplicates - base wins",
			base:       []string{"Content-Type", "Accept"},
			additional: []string{"content-type", "X-Custom"},
			want:       []string{"Content-Type", "Accept", "X-Custom"},
		},
		{
			name:       "both empty returns nil",
			base:       nil,
			additional: nil,
			want:       nil,
		},
		{
			name:       "preserves order - base first then additional",
			base:       []string{"X-First", "X-Second"},
			additional: []string{"X-Third", "X-Fourth"},
			want:       []string{"X-First", "X-Second", "X-Third", "X-Fourth"},
		},
		{
			name:       "deduplicates within base (case-insensitive)",
			base:       []string{"Accept", "accept", "ACCEPT"},
			additional: []string{"Content-Type"},
			want:       []string{"Accept", "Content-Type"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeHeaderSlices(tt.base, tt.additional)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveHeaders(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional headers",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: nil,
			},
			want: []string{"Authorization", "Content-Type"},
		},
		{
			name: "with additional headers",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"X-Custom-Header"},
			},
			want: []string{"Authorization", "Content-Type", "X-Custom-Header"},
		},
		{
			name: "additional header already in base is deduplicated",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"X-Custom", "Content-Type"},
			},
			want: []string{"Authorization", "Content-Type", "X-Custom"},
		},
		{
			name: "case-insensitive deduplication - base casing preserved",
			cfg: CORSConfig{
				AllowedHeaders:    []string{"Authorization", "Content-Type"},
				AdditionalHeaders: []string{"authorization", "content-type", "X-New"},
			},
			want: []string{"Authorization", "Content-Type", "X-New"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveHeaders()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCORSConfig_EffectiveExposedHeaders(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		want []string
	}{
		{
			name: "no additional exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link"},
				AdditionalExposedHeaders: nil,
			},
			want: []string{"Link"},
		},
		{
			name: "with additional exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link"},
				AdditionalExposedHeaders: []string{"X-Custom-Exposed"},
			},
			want: []string{"Link", "X-Custom-Exposed"},
		},
		{
			name: "empty base with additional",
			cfg: CORSConfig{
				ExposedHeaders:           nil,
				AdditionalExposedHeaders: []string{"X-Custom-Exposed"},
			},
			want: []string{"X-Custom-Exposed"},
		},
		{
			name: "case-insensitive deduplication for exposed headers",
			cfg: CORSConfig{
				ExposedHeaders:           []string{"Link", "X-Request-Id"},
				AdditionalExposedHeaders: []string{"link", "x-request-id", "X-New-Header"},
			},
			want: []string{"Link", "X-Request-Id", "X-New-Header"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveExposedHeaders()
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCORSMiddleware_WildcardOrigin tests that the CORS middleware correctly handles
// wildcard origin configuration with credentials enabled. Per CORS spec, when
// credentials are allowed, the response must reflect the actual origin, not "*".
func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	// Configure CORS the same way as newHTTPServer does
	cfg := CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           3600,
	}

	// Create the CORS handler using the same pattern as server.go
	corsHandler := cors.New(cors.Options{
		AllowOriginFunc: func(_ *http.Request, origin string) bool {
			for _, allowedOrigin := range cfg.AllowedOrigins {
				if allowedOrigin == "*" {
					return true
				}
				if strings.EqualFold(origin, allowedOrigin) {
					return true
				}
			}
			return false
		},
		AllowedMethods:   cfg.EffectiveMethods(),
		AllowedHeaders:   cfg.EffectiveHeaders(),
		ExposedHeaders:   cfg.EffectiveExposedHeaders(),
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge,
	})

	// Create a simple handler wrapped with CORS
	handler := corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		origin         string
		method         string
		requestHeaders string
		wantOrigin     string
		wantCreds      string
	}{
		{
			name:           "preflight from localhost:3000",
			origin:         "http://localhost:3000",
			method:         http.MethodOptions,
			requestHeaders: "authorization,content-type",
			wantOrigin:     "http://localhost:3000",
			wantCreds:      "true",
		},
		{
			name:           "preflight from example.com",
			origin:         "https://example.com",
			method:         http.MethodOptions,
			requestHeaders: "authorization",
			wantOrigin:     "https://example.com",
			wantCreds:      "true",
		},
		{
			name:           "preflight from arbitrary origin",
			origin:         "https://any-site.io",
			method:         http.MethodOptions,
			requestHeaders: "content-type",
			wantOrigin:     "https://any-site.io",
			wantCreds:      "true",
		},
		{
			name:       "actual request from localhost",
			origin:     "http://localhost:3000",
			method:     http.MethodGet,
			wantOrigin: "http://localhost:3000",
			wantCreds:  "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			if tt.method == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "POST")
				if tt.requestHeaders != "" {
					req.Header.Set("Access-Control-Request-Headers", tt.requestHeaders)
				}
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify origin is reflected back (not "*" since credentials are enabled)
			gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			require.Equal(t, tt.wantOrigin, gotOrigin,
				"Origin should be reflected back, not '*', when credentials are enabled")

			// Verify credentials header
			gotCreds := rr.Header().Get("Access-Control-Allow-Credentials")
			require.Equal(t, tt.wantCreds, gotCreds)

			// For preflight, verify allowed headers
			if tt.method == http.MethodOptions {
				gotHeaders := rr.Header().Get("Access-Control-Allow-Headers")
				require.NotEmpty(t, gotHeaders, "Preflight should include allowed headers")
			}
		})
	}
}

// TestCORSMiddleware_WildcardWithSpecificOrigins tests that wildcard takes precedence
// when mixed with specific origins - all origins are allowed if "*" is in the list.
func TestCORSMiddleware_WildcardWithSpecificOrigins(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://specific.com", "*", "https://another.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization"},
		AllowCredentials: true,
	}

	corsHandler := cors.New(cors.Options{
		AllowOriginFunc: func(_ *http.Request, origin string) bool {
			for _, allowedOrigin := range cfg.AllowedOrigins {
				if allowedOrigin == "*" {
					return true
				}
				if strings.EqualFold(origin, allowedOrigin) {
					return true
				}
			}
			return false
		},
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		AllowCredentials: cfg.AllowCredentials,
	})

	handler := corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// When "*" is in the list, ANY origin should be allowed
	tests := []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{
			name:       "specific origin still works",
			origin:     "https://specific.com",
			wantOrigin: "https://specific.com",
		},
		{
			name:       "random origin allowed due to wildcard",
			origin:     "https://random-site.io",
			wantOrigin: "https://random-site.io",
		},
		{
			name:       "evil origin also allowed due to wildcard",
			origin:     "https://evil.com",
			wantOrigin: "https://evil.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", "GET")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			assert.Equal(t, tt.wantOrigin, gotOrigin,
				"Wildcard in list should allow ALL origins")
		})
	}
}

// TestCORSMiddleware_SpecificOrigins tests CORS with specific origin list (not wildcard)
func TestCORSMiddleware_SpecificOrigins(t *testing.T) {
	cfg := CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://allowed.com", "https://also-allowed.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization"},
		AllowCredentials: true,
	}

	corsHandler := cors.New(cors.Options{
		AllowOriginFunc: func(_ *http.Request, origin string) bool {
			for _, allowedOrigin := range cfg.AllowedOrigins {
				if allowedOrigin == "*" {
					return true
				}
				if strings.EqualFold(origin, allowedOrigin) {
					return true
				}
			}
			return false
		},
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		AllowCredentials: cfg.AllowCredentials,
	})

	handler := corsHandler.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{
			name:       "allowed origin",
			origin:     "https://allowed.com",
			wantOrigin: "https://allowed.com",
		},
		{
			name:       "also allowed origin",
			origin:     "https://also-allowed.com",
			wantOrigin: "https://also-allowed.com",
		},
		{
			name:       "disallowed origin - no CORS headers",
			origin:     "https://evil.com",
			wantOrigin: "", // No Access-Control-Allow-Origin header
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", "GET")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			assert.Equal(t, tt.wantOrigin, gotOrigin)
		})
	}
}
