package vault

import (
	"context"
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func GetSecretWithAppRole() (string, error) {
	config := vault.DefaultConfig() // modify for more granular configuration

	client, err := vault.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	// A combination of a Role ID and Secret ID is required to log in to Vault
	// with an AppRole.
	// First, let's get the role ID given to us by our Vault administrator.
	roleID := os.Getenv("KAS_APPROLE_ROLEID")
	if roleID == "" {
		return "", fmt.Errorf("no role ID was provided in KAS_APPROLE_ROLEID env var")
	}

	// FIXME: The Secret ID is a value that needs to be protected, so do this!!
	// // The Secret ID is a value that needs to be protected, so instead of the
	// // app having knowledge of the secret ID directly, we have a trusted orchestrator (https://learn.hashicorp.com/tutorials/vault/secure-introduction?in=vault/app-integration#trusted-orchestrator)
	// // give the app access to a short-lived response-wrapping token (https://developer.hashicorp.com/vault/docs/concepts/response-wrapping).
	// // Read more at: https://learn.hashicorp.com/tutorials/vault/approle-best-practices?in=vault/auth-methods#secretid-delivery-best-practices
	// secretID := &auth.SecretID{FromFile: "path/to/wrapping-token"}

	secretID := &auth.SecretID{FromString: os.Getenv("KAS_APPROLE_SECRETID")}
	if secretID.FromString == "" {
		return "", fmt.Errorf("no role secret ID was provided in KAS_APPROLE_SECRETID env var")
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		secretID,
		// auth.WithWrappingToken(), // Only required if the secret ID is response-wrapped.
	)
	if err != nil {
		return "", fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return "", fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return "", fmt.Errorf("no auth info was returned after login")
	}

	secrets_path := "secret/metadata/kas_keypair"
	lra, err := client.Logical().ListWithContext(context.Background(), secrets_path)
	if err != nil {
		return "", fmt.Errorf("unable to list secrets at %s: %w", secrets_path, err)
	}

	var kids []string
	for _, keys := range lra.Data["keys"].([]interface{}) {
		kids = append(kids, keys.(string))
	}

	// get secret from the default mount path for KV v2 in dev mode, "secret"
	s0, err := client.KVv2("secret").Get(context.Background(), "kas_keypair/"+kids[0])
	if err != nil {
		return "", fmt.Errorf("unable to read secret: %w", err)
	}
	fmt.Printf("Secret: %v\n", s0)

	privateKey, ok := s0.Data["private"].(string)
	if !ok {
		return "", fmt.Errorf("unable to assert type of private key to string")
	}
	return privateKey, nil
}
