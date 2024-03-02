package cmd

// import (
// 	"bytes"
// 	"context"
// 	"fmt"
// 	"log/slog"
// 	"net/http"

// 	"github.com/Nerzal/gocloak/v13"
// 	"github.com/spf13/cobra"
// )

// var (
// 	provisionKeycloakCmd = &cobra.Command{
// 		Use:   "keycloak",
// 		Short: "Run local provision of Keycloak data",
// 		Long: `
// ** Local Development and Testing Only **
// This command will create the following Keyclaok resource:
// - Realm
// - Client
// - Users

// This command is intended for local development and testing purposes only.
// `,
// 		RunE: func(cmd *cobra.Command, args []string) error {
// 			client := gocloak.NewClient("http://localhost:8888/auth")

// 			ctx := context.Background()

// 			token, err := client.LoginAdmin(ctx, "admin", "changeme", "master")
// 			if err != nil {
// 				return err
// 			}

// 			// Create realm
// 			r, err := client.GetRealm(ctx, token.AccessToken, "opentdf")
// 			if err != nil {
// 				return err
// 			}

// 			if r == nil {

// 				realm := gocloak.RealmRepresentation{
// 					Realm:   gocloak.StringP("opentdf"),
// 					Enabled: gocloak.BoolP(true),
// 				}

// 				if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
// 					return err
// 				}
// 				slog.Info("✅ Realm created", slog.String("realm", "opentdf"))
// 			} else {
// 				slog.Info("Realm already exists", slog.String("realm", "opentdf"))
// 			}

// 			// Create Client
// 			id := "5787f268-4d59-429d-aebd-0d9f900b1b59"
// 			existingClient, err := client.GetClient(ctx, token.AccessToken, "opentdf", id)
// 			if err != nil {
// 				if err.Error() != "404 Not Found: Could not find client" {
// 					return err
// 				}
// 			}

// 			if existingClient == nil {
// 				cc := gocloak.Client{
// 					ClientID:               gocloak.StringP("opentdf"),
// 					Enabled:                gocloak.BoolP(true),
// 					Name:                   gocloak.StringP("opentdf"),
// 					ServiceAccountsEnabled: gocloak.BoolP(true),
// 					Secret:                 gocloak.StringP("secret"),
// 					ID:                     gocloak.StringP(id),
// 				}
// 				if _, err := client.CreateClient(ctx, token.AccessToken, "opentdf", cc); err != nil {
// 					return err
// 				}
// 				slog.Info("✅ Client created", slog.String("client", "opentdf"))
// 			} else {
// 				slog.Info("Client already exists", slog.String("client", "opentdf"))
// 			}

// 			// Enable permissions on the client to support token-exchange
// 			hc := client.RestyClient().GetClient()
// 			req, err := http.NewRequest("PUT", "http://localhost:8888/auth/admin/realms/opentdf/clients/5787f268-4d59-429d-aebd-0d9f900b1b59/management/permissions", bytes.NewReader([]byte("{\"enabled\":true}")))
// 			req.Header.Set("Content-Type", "application/json")
// 			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
// 			resp, err := hc.Do(req)
// 			if err != nil {
// 				return err
// 			}
// 			if resp.StatusCode != 200 {
// 				return fmt.Errorf("error setting client permissions: %d", resp.StatusCode)
// 			}

// 			return nil

// 		},
// 	}
// )

// func init() {
// 	provisionCmd.AddCommand(provisionKeycloakCmd)
// }
