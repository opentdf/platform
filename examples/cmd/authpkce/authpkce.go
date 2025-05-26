// Command-line PKCE OAuth2 demo for Keycloak @ localhost:8888
// Usage: go run examples/cmd/authpkce/authpkce.go
package authpkce

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
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
		clientId := r.URL.Query().Get("client_id")
		if clientId == "" {
			clientId = "opentdf-public"
		}

		platformEndpoint := r.URL.Query().Get("platform_endpoint")
		if platformEndpoint == "" {
			platformEndpoint = "https://localhost:8080"
		}

		scope := r.URL.Query().Get("scope")
		if scope == "" {
			scope = "openid profile email"
		}

		resp, err := http.Post(platformEndpoint+platformWellKnown, "application/json", bytes.NewBufferString("{}"))
		var oidcConfig map[string]interface{}
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var data map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&data)
			if conf, ok := data["configuration"].(map[string]interface{}); ok {
				if idp, ok := conf["idp"].(map[string]interface{}); ok {
					oidcConfig = idp
				}
			}
		}
		// Prepare template variables
		oidcConfigJSON, _ := json.MarshalIndent(oidcConfig, "", "  ")
		replacer := map[string]string{
			"__PLATFORM_WELLKNOWN_CONFIG__": string(oidcConfigJSON),
			"__CLIENT_ID__":                 clientId,
			"__SCOPE__":                     "openid profile email",
			"__PLATFORM_ENDPOINT__":         platformEndpoint,
		}
		html := string(pkceDemoHTML)
		for k, v := range replacer {
			html = strings.ReplaceAll(html, k, v)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	})

	fmt.Println("Serving PKCE demo at http://localhost:9000/pkce-demo")
	return http.ListenAndServe(":9000", nil)
}

func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
