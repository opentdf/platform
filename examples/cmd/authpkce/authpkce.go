// Command-line PKCE OAuth2 demo for Keycloak @ localhost:8888
// Usage: go run examples/cmd/authpkce/authpkce.go
package authpkce

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

const (
	timeoutDuration = 15 * 1e9 // 15 seconds
)

//go:embed pkce-demo.html
var pkceDemoHTML []byte

var Cmd = &cobra.Command{
	Use:   "auth-pkce",
	Short: "Serve the PKCE OAuth2 demo web page only (no CLI mode)",
	RunE: func(_ *cobra.Command, _ []string) error {
		return servePKCEDemo()
	},
}

const platformWellKnown = "/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration"

func servePKCEDemo() error {
	http.HandleFunc("/pkce-demo", func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			clientID = "opentdf-public"
		}

		platformEndpoint := r.URL.Query().Get("platform_endpoint")
		if platformEndpoint == "" {
			platformEndpoint = "https://localhost:8080"
		}
		// Ensure platformEndpoint is a valid URL and does not contain script or other unsafe content
		parsedURL, err := url.Parse(platformEndpoint)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			log.Printf("Invalid platform_endpoint: %v", platformEndpoint)
			http.Error(w, "Invalid platform_endpoint", http.StatusBadRequest)
			return
		}

		scope := r.URL.Query().Get("scope")
		if scope == "" {
			scope = "openid profile email"
		}

		httpClient := &http.Client{
			Timeout: timeoutDuration,
		}
		resp, err := httpClient.Do(&http.Request{
			Method: http.MethodPost,
			URL:    &url.URL{Path: platformEndpoint + platformWellKnown},
			Header: http.Header{
				"Content-Type": {"application/json"},
			},
			Body: io.NopCloser(bytes.NewBufferString("{}")),
		})
		var oidcConfig map[string]interface{}
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var data map[string]interface{}
			err := json.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				log.Printf("Error decoding response: %v\n", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			conf, ok := data["configuration"].(map[string]interface{})
			if !ok {
				log.Printf("No configuration found in response: %v", data)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			oidcConfig, ok = conf["idp"].(map[string]interface{})
			if !ok {
				log.Printf("No IDP configuration found in response: %v", conf)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}

		oidcConfigJSON, _ := json.Marshal(oidcConfig)
		replacer := map[string]string{
			"__PLATFORM_WELLKNOWN_CONFIG__": string(oidcConfigJSON),
			"__CLIENT_ID__":                 html.EscapeString(clientID),
			"__SCOPE__":                     html.EscapeString(scope),
			"__PLATFORM_ENDPOINT__":         html.EscapeString(platformEndpoint),
		}
		html := string(pkceDemoHTML)
		for k, v := range replacer {
			html = strings.ReplaceAll(html, k, v)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err = w.Write([]byte(html))
		if err != nil {
			log.Printf("Error writing response: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	log.Printf("Serving PKCE demo at http://localhost:9000/pkce-demo")
	server := &http.Server{
		Addr:    ":9000",
		Handler: nil,
		// Set a reasonable timeout (e.g., 15 seconds)
		ReadTimeout:  timeoutDuration,
		WriteTimeout: timeoutDuration,
	}
	return server.ListenAndServe()
}
