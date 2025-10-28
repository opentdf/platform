package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"github.com/opentdf/platform/examples/ckms/vaultkms"
	"github.com/opentdf/platform/service/pkg/server"
	"github.com/opentdf/platform/service/trust"
)

func start() error {
	configFile := "./cfg-vault.yaml"
	configKey := "opentdf"

	config := vault.DefaultConfig()
	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	kmf := trust.NamedKeyManagerCtxFactory{
		Name: "vault",
		Factory: func(ctx context.Context, _ *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
			kms, err := newVaultTrustService(ctx, vaultClient)
			if err != nil {
				return nil, err
			}
			return kms, nil
		},
	}

	customStartOptions := []server.StartOptions{
		server.WithWaitForShutdownSignal(),
		server.WithConfigFile(configFile),
		server.WithConfigKey(configKey),
		server.WithTrustKeyManagerCtxFactories(kmf),
	}

	// Start the platform server with the custom options
	if err := server.Start(customStartOptions...); err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
	return nil
}

func newVaultTrustService(ctx context.Context, vaultClient *vault.Client) (*vaultkms.VaultKeyService, error) {
	roleID := os.Getenv("KAS_APPROLE_ROLEID")
	if roleID == "" {
		return nil, errors.New("no role ID was provided in KAS_APPROLE_ROLEID env var")
	}

	// FIXME: The Secret ID is a value that needs to be protected, so do this!!
	// // The Secret ID is a value that needs to be protected, so instead of the
	// // app having knowledge of the secret ID directly, we have a trusted orchestrator (https://learn.hashicorp.com/tutorials/vault/secure-introduction?in=vault/app-integration#trusted-orchestrator)
	// // give the app access to a short-lived response-wrapping token (https://developer.hashicorp.com/vault/docs/concepts/response-wrapping).
	// // Read more at: https://learn.hashicorp.com/tutorials/vault/approle-best-practices?in=vault/auth-methods#secretid-delivery-best-practices
	// secretID := &auth.SecretID{FromFile: "path/to/wrapping-token"}

	secretID := &auth.SecretID{FromString: os.Getenv("KAS_APPROLE_SECRETID")}
	if secretID.FromString == "" {
		return nil, errors.New("no role secret ID was provided in KAS_APPROLE_SECRETID env var")
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := vaultClient.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, errors.New("no auth info was returned after login")
	}

	kms := vaultkms.NewVaultKeyService(vaultClient)
	return kms, nil
}

func main() {
	log.Println("Starting CKMS...")
	if err := start(); err != nil {
		log.Fatalf("Error starting CKMS: %v", err)
	}
	log.Println("CKMS started successfully.")
}
