package vault

import (
	"context"
	"crypto/elliptic"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/trust"
)

type VaultItem struct {
	kid     trust.KeyIdentifier
	alg     string
	public  ocrypto.PublicKeyEncryptor
	private ocrypto.PrivateKeyDecryptor
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
	return v.public.PublicKeyInPemFormat()
}

func (v *VaultItem) ExportCertificate(ctx context.Context) (string, error) {
	return "", fmt.Errorf("certificate export not supported")
}

func (v *VaultItem) System() string {
	return "io.opentdf.examples/vault"
}

type VaultKeyService struct {
	client *vault.Client
	items  map[trust.KeyIdentifier]*VaultItem
}

func NewVaultManager(client *vault.Client) *VaultKeyService {
	return &VaultKeyService{
		client: client,
		items:  make(map[trust.KeyIdentifier]*VaultItem),
	}
}

func (vm *VaultKeyService) LoadKeys(ctx context.Context) error {
	secretsPath := "secret/metadata/kas_keypair"
	lra, err := vm.client.Logical().ListWithContext(ctx, secretsPath)
	if err != nil {
		return fmt.Errorf("unable to list secrets at %s: %w", secretsPath, err)
	}

	for _, key := range lra.Data["keys"].([]interface{}) {
		if k, err := vm.loadKey(ctx, key); err != nil {
			return err
		} else {
			vm.items[k.ID()] = k
		}
	}

	if len(vm.items) == 0 {
		return fmt.Errorf("no valid keys were found")
	}
	return nil
}

func (vm *VaultKeyService) loadKey(ctx context.Context, key interface{}) (*VaultItem, error) {
	kid := trust.KeyIdentifier(key.(string))
	secretPath := fmt.Sprintf("secret/data/kas_keypair/%s", kid)
	secret, err := vm.client.KVv2("secret").Get(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret at %s: %v", secretPath, err)
	}

	privateKeyPEM, ok := secret.Data["private"].(string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of private key to string for key %s", kid)
	}

	privateKey, err := ocrypto.FromPrivatePEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key from PEM: %w", err)
	}

	var publicKey ocrypto.PublicKeyEncryptor
	if publicKeyPEM, ok := secret.Data["public"].(string); ok {
		publicKey, err = ocrypto.FromPublicPEM(publicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to create public key from PEM: %w", err)
		}
	} else {
		publicKey = privateKey.PublicKey()
	}

	algorithm, ok := secret.Data["algorithm"].(string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of algorithm to string for key %s", kid)
	}

	return &VaultItem{
		kid:     kid,
		alg:     algorithm,
		public:  publicKey,
		private: privateKey,
	}, nil
}

func (vm *VaultKeyService) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (trust.KeyDetails, error) {
	for _, item := range vm.items {
		if item.Algorithm() == algorithm {
			return item, nil
		}
	}
	return nil, fmt.Errorf("no key found for algorithm: %s", algorithm)
}

func (vm *VaultKeyService) FindKeyByID(ctx context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	item, exists := vm.items[id]
	if !exists {
		return nil, fmt.Errorf("no key found for ID: %s", id)
	}
	return item, nil
}

func (vm *VaultKeyService) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	keys := make([]trust.KeyDetails, 0, len(vm.items))
	for _, item := range vm.items {
		keys = append(keys, item)
	}
	return keys, nil
}

type InProcessWrappedKey struct {
	keyData []byte
}

func (k *InProcessWrappedKey) VerifyBinding(ctx context.Context, policy, binding []byte) error {
	// Implement HMAC or other binding verification logic here
	return nil
}

func (k *InProcessWrappedKey) Export(encapsulator trust.Encapsulator) ([]byte, error) {
	if encapsulator == nil {
		return k.keyData, nil
	}
	return encapsulator.Encrypt(k.keyData)
}

func (k *InProcessWrappedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	// Implement AES-GCM decryption logic here
	return nil, fmt.Errorf("DecryptAESGCM not implemented")
}

func (vm *VaultKeyService) Decrypt(ctx context.Context, keyID trust.KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (trust.ProtectedKey, error) {
	item, exists := vm.items[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	decryptedData, err := item.private.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &InProcessWrappedKey{keyData: decryptedData}, nil
}

func (vm *VaultKeyService) DeriveKey(ctx context.Context, kasKID trust.KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (trust.ProtectedKey, error) {
	// Implement key derivation logic here
	return nil, fmt.Errorf("DeriveKey not implemented")
}

func (vm *VaultKeyService) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	// Implement EC session key generation logic here
	return nil, fmt.Errorf("GenerateECSessionKey not implemented")
}

func (vm *VaultKeyService) Close() {
	// Implement any cleanup logic if necessary
}
