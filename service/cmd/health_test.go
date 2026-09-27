package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func healthServer(t *testing.T, code int, body string) (*httptest.Server, *string) {
	t.Helper()
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &query
}

func runHealth(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newHealthCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestHealthSucceedsWhenThePlatformIsServing(t *testing.T) {
	server, query := healthServer(t, http.StatusOK, `{"status":"SERVING"}`)

	out, err := runHealth(t, "--url", server.URL+"/healthz")

	require.NoError(t, err)
	require.Contains(t, out, "SERVING")
	require.Empty(t, *query)
}

func TestHealthFailsWhenThePlatformIsNotServing(t *testing.T) {
	server, _ := healthServer(t, http.StatusServiceUnavailable, `{"status":"NOT_SERVING"}`)

	_, err := runHealth(t, "--url", server.URL+"/healthz")

	require.ErrorContains(t, err, "NOT_SERVING")
}

func TestHealthFailsOnAnUnexpectedAnswer(t *testing.T) {
	server, _ := healthServer(t, http.StatusOK, `not json`)

	_, err := runHealth(t, "--url", server.URL+"/healthz")

	require.ErrorContains(t, err, "unexpected health answer")
}

func TestHealthFailsWhenThePlatformIsUnreachable(t *testing.T) {
	server, _ := healthServer(t, http.StatusOK, `{"status":"SERVING"}`)
	server.Close()

	_, err := runHealth(t, "--url", server.URL+"/healthz", "--timeout", "1s")

	require.ErrorContains(t, err, "health check failed")
}

func TestHealthAsksForTheRequestedService(t *testing.T) {
	server, query := healthServer(t, http.StatusOK, `{"status":"SERVING"}`)

	_, err := runHealth(t, "--url", server.URL+"/healthz", "--service", "all")

	require.NoError(t, err)
	require.Equal(t, "service=all", *query)
}
