package vault

import (
	"context"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	trust "github.com/opentdf/platform/service/trust"
)

type VaultItem struct {
	kid     trust.KeyIdentifier
	alg     string
	public  string
	private string
}

func (v *VaultItem) ID() trust.KeyIdentifier {
	return v.kid
}

func (v *VaultItem) Algorithm() string {
	return v.alg
}

func (v *VaultItem) IsLegacy() bool {
	return false
}

func (v *VaultItem) ExportPublicKey(ctx context.Context, format trust.KeyType) (string, error) {
	return v.public, nil
}

func (v *VaultItem) ExportCertificate(ctx context.Context) (string, error) {
	return "", fmt.Errorf("certificate export not supported")
}

func (v *VaultItem) System() string {
	return "io.opentdf.examples/vault"
}

type VaultManager struct {
	client *vault.Client
	items  map[trust.KeyIdentifier]*VaultItem
}

func NewVaultManager(client *vault.Client) *VaultManager {
	return &VaultManager{
		client: client,
		items:  make(map[trust.KeyIdentifier]*VaultItem),
	}
}

func (vm *VaultManager) LoadKeys(ctx context.Context) error {
	secretsPath := "secret/metadata/kas_keypair"
	lra, err := vm.client.Logical().ListWithContext(ctx, secretsPath)
	if err != nil {
		return fmt.Errorf("unable to list secrets at %s: %w", secretsPath, err)
	}

	for _, key := range lra.Data["keys"].([]interface{}) {
		kid := trust.KeyIdentifier(key.(string))
		secretPath := fmt.Sprintf("secret/data/kas_keypair/%s", kid)
		secret, err := vm.client.KVv2("secret").Get(ctx, secretPath)
		if err != nil {
			return fmt.Errorf("unable to read secret at %s: %w", secretPath, err)
		}

		privateKey, ok := secret.Data["private"].(string)
		if !ok {
			return fmt.Errorf("unable to assert type of private key to string")
		}

		publicKey, ok := secret.Data["public"].(string)
		if !ok {
			return fmt.Errorf("unable to assert type of public key to string")
		}

		algorithm, ok := secret.Data["algorithm"].(string)
		if !ok {
			return fmt.Errorf("unable to assert type of algorithm to string")
		}

		vm.items[kid] = &VaultItem{
			kid:     kid,
			alg:     algorithm,
			public:  publicKey,
			private: privateKey,
		}
	}

	return nil
}

func (vm *VaultManager) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (trust.KeyDetails, error) {
	for _, item := range vm.items {
		if item.Algorithm() == algorithm {
			return item, nil
		}
	}
	return nil, fmt.Errorf("no key found for algorithm: %s", algorithm)
}

func (vm *VaultManager) FindKeyByID(ctx context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	item, exists := vm.items[id]
	if !exists {
		return nil, fmt.Errorf("no key found for ID: %s", id)
	}
	return item, nil
}

func (vm *VaultManager) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	keys := make([]trust.KeyDetails, 0, len(vm.items))
	for _, item := range vm.items {
		keys = append(keys, item)
	}
	return keys, nil
}
