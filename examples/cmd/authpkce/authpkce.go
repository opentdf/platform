// Command-line PKCE OAuth2 demo for Keycloak @ localhost:8888
// Usage: go run examples/cmd/authpkce/authpkce.go
package authpkce

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"

	"embed"

	"github.com/spf13/cobra"
)

const (
	timeoutDuration   = 15 * 1e9 // 15 seconds
	platformWellKnown = "/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration"
)

var (
	//go:embed pkce-demo.html
	embeddedHTML []byte

	//go:embed assets/*
	embeddedAssetsFS embed.FS
	clientID         string
	platformEndpoint string
	scope            string

	Cmd = &cobra.Command{
		Use:   "auth-pkce",
		Short: "Serve the PKCE OAuth2 demo web page only (no CLI mode)",
		RunE:  servePKCEDemo,
	}
)

type platformWellKnownConfig struct {
	Configuration struct {
		IDP struct {
			Issuer                string `json:"issuer"`
			AuthorizationEndpoint string `json:"authorization_endpoint"`
			TokenEndpoint         string `json:"token_endpoint"`
			UserinfoEndpoint      string `json:"userinfo_endpoint"`
			EndSessionEndpoint    string `json:"end_session_endpoint"`
		} `json:"idp"`
	} `json:"configuration"`
}

type configInjector struct {
	AuthUrl          string `json:"authUrl"`
	TokenUrl         string `json:"tokenUrl"`
	UserinfoUrl      string `json:"userinfoUrl"`
	EndSessionUrl    string `json:"endSessionUrl"`
	ClientId         string `json:"clientId"`
	Scope            string `json:"scope"`
	PlatformEndpoint string `json:"platformEndpoint"`
}

func init() {
	Cmd.Flags().StringVar(&clientID, "client-id", "opentdf-public", "Client ID to use for the PKCE demo")
	Cmd.Flags().StringVar(&platformEndpoint, "platform-endpoint", "https://localhost:8080", "Platform endpoint to use for the PKCE demo")
	Cmd.Flags().StringVar(&scope, "scope", "openid profile email", "Scope to request in the PKCE demo")
}

func servePKCEDemo(cmd *cobra.Command, args []string) error {

	platformConfig, err := processPlatformWellKnown(platformEndpoint)
	if err != nil {
		log.Fatalf("Failed to process platform well-known configuration: %v", err)
	}

	config := configInjector{
		AuthUrl:          html.EscapeString(platformConfig.Configuration.IDP.AuthorizationEndpoint),
		TokenUrl:         html.EscapeString(platformConfig.Configuration.IDP.TokenEndpoint),
		UserinfoUrl:      html.EscapeString(platformConfig.Configuration.IDP.UserinfoEndpoint),
		EndSessionUrl:    html.EscapeString(platformConfig.Configuration.IDP.EndSessionEndpoint),
		ClientId:         html.EscapeString(clientID),
		Scope:            html.EscapeString(scope),
		PlatformEndpoint: html.EscapeString(platformEndpoint),
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}

	injector := fmt.Sprintf(`<script>window.__APP_CONFIG__ = %s;</script>`, string(configJSON))
	html := strings.Replace(string(embeddedHTML), "<!-- CONFIG DIRECTIVE -->", injector, 1)

	// Serve static files from embedded assets
	assetsFS, err := fs.Sub(embeddedAssetsFS, "assets")
	if err != nil {
		log.Fatalf("Failed to get assets subdirectory: %v", err)
	}

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))))
	http.HandleFunc("/pkce-demo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err = w.Write([]byte(html)); err != nil {
			log.Printf("Error writing response: %v\n", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	log.Printf("\n\n\tServing PKCE demo at http://localhost:9000/pkce-demo")
	server := &http.Server{
		Addr:    ":9000",
		Handler: nil,
		// Set a reasonable timeout (e.g., 15 seconds)
		ReadTimeout:  timeoutDuration,
		WriteTimeout: timeoutDuration,
	}
	return server.ListenAndServe()
}

func processPlatformWellKnown(platformEndpoint string) (platformWellKnownConfig, error) {
	httpClient := &http.Client{
		Timeout: timeoutDuration,
	}

	fullURL, err := url.Parse(platformEndpoint + platformWellKnown)
	if err != nil {
		return platformWellKnownConfig{}, fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fullURL.String(), bytes.NewBufferString("{}"))
	if err != nil {
		return platformWellKnownConfig{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return platformWellKnownConfig{}, fmt.Errorf("error making request to %s: %w", platformEndpoint+platformWellKnown, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return platformWellKnownConfig{}, fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, platformEndpoint+platformWellKnown)
	}

	var platformConfig platformWellKnownConfig
	if err := json.NewDecoder(resp.Body).Decode(&platformConfig); err != nil {
		return platformWellKnownConfig{}, fmt.Errorf("error decoding response: %w", err)
	}

	return platformConfig, nil
}
