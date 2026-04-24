package enumnormalize

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxBodySize is the upper bound on request bodies the middleware will read
// into memory for normalization. Policy API request bodies are small (typically
// under 10 KB); this cap prevents abuse while being generous enough for any
// legitimate request. ConnectRPC enforces its own message size limits downstream.
const maxBodySize = 1 << 20 // 1 MB

// NewMiddleware returns HTTP middleware that normalises shorthand enum string
// values in JSON request bodies for the given RPC paths. Requests that do not
// match (wrong content-type, wrong path) are forwarded unchanged with zero
// overhead.
func NewMiddleware(rules []EnumFieldRule, paths []string) func(http.Handler) http.Handler {
	lookup := buildLookup(rules)

	pathSet := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		pathSet[p] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only rewrite JSON bodies on matching RPC paths.
			if !isJSON(r) || !matchesPath(r, pathSet) {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			normalized, err := normalizeJSON(body, lookup)
			if err != nil {
				// On normalisation failure, send the original body so
				// ConnectRPC can surface its own error.
				normalized = body
			}

			r.Body = io.NopCloser(bytes.NewReader(normalized))
			r.ContentLength = int64(len(normalized))
			r.Header.Set("Content-Length", strconv.Itoa(len(normalized)))

			next.ServeHTTP(w, r)
		})
	}
}

// isJSON returns true when the request Content-Type indicates a JSON payload
// (application/json or application/connect+json).
func isJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "json")
}

// matchesPath returns true when the request URL path is in pathSet.
func matchesPath(r *http.Request, pathSet map[string]struct{}) bool {
	_, ok := pathSet[r.URL.Path]
	return ok
}
