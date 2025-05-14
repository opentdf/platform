package vaultkms

import (
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	vault "github.com/hashicorp/vault/api"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/service/trust"
)

type VaultItem struct {
	kid     trust.KeyIdentifier
	alg     string
	public  ocrypto.PublicKeyEncryptor
	private ocrypto.PrivateKeyDecryptor
	nano    *ocrypto.ECDecryptor
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

func (v VaultItem) System() string {
	return "examples.opentdf.io/vault"
}

type VaultKeyService struct {
	client *vault.Client
	items  map[trust.KeyIdentifier]*VaultItem
}

func (v VaultKeyService) Name() string {
	return "examples.opentdf.io/vault"
}

func NewVaultKeyService(client *vault.Client) *VaultKeyService {
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

	var keys []interface{}
	if lra == nil || lra.Data == nil || lra.Data["keys"] == nil {
		return fmt.Errorf("no keys found at %s", secretsPath)
	}

	keys, ok := lra.Data["keys"].([]interface{})
	if !ok {
		return fmt.Errorf("unable to assert type of keys to []interface{} for path %s", secretsPath)
	}

	for _, key := range keys {
		if k, err := vm.loadKey(ctx, key); err != nil {
			slog.ErrorContext(ctx, "failed to load key", "key", key, "err", err)
		} else {
			slog.DebugContext(ctx, "loaded key", "key", key)
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
	secretPath := fmt.Sprintf("kas_keypair/%s", kid)
	secret, err := vm.client.KVv2("secret").Get(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret in kv store secret with path [%s]: %v", secretPath, err)
	}

	privateKeyPEM, ok := secret.Data["private"].(string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of private key to string for key %s", kid)
	}

	privateKey, err := ocrypto.FromPrivatePEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key from PEM: %w", err)
	}
	var nanoKey *ocrypto.ECDecryptor
	if _, ok := privateKey.(*ocrypto.ECDecryptor); ok {
		salt := nanoSalt()
		nk, err := ocrypto.FromPrivatePEMWithSalt(privateKeyPEM, salt, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create EC decryptor from PEM: %w", err)
		}
		if ec2, ok := nk.(ocrypto.ECDecryptor); ok {
			nanoKey = &ec2
		} else {
			return nil, fmt.Errorf("failed to assert type of EC decryptor for key %s", kid)
		}
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
		nano:    nanoKey,
	}, nil
}

func nanoSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	salt := digest.Sum(nil)
	return salt
}

func (vm *VaultKeyService) refreshKeys(ctx context.Context) error {
	if len(vm.items) > 0 {
		return nil
	}
	return vm.LoadKeys(ctx)
}

func (vm *VaultKeyService) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (trust.KeyDetails, error) {
	if err := vm.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	for _, item := range vm.items {
		if item.Algorithm() == algorithm {
			return item, nil
		}
	}
	return nil, nil
}

func (vm *VaultKeyService) FindKeyByID(ctx context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	if err := vm.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	item, exists := vm.items[id]
	if !exists {
		return nil, fmt.Errorf("no key found for ID: %s", id)
	}
	return item, nil
}

func (vm *VaultKeyService) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	if err := vm.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	keys := make([]trust.KeyDetails, 0, len(vm.items))
	for _, item := range vm.items {
		keys = append(keys, item)
	}
	return keys, nil
}

type InProcessWrappedKey struct {
	rawKey []byte
	cipher ocrypto.AesGcm
}

func NewInProcessAESKey(key []byte) (*InProcessWrappedKey, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	cipher, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return &InProcessWrappedKey{
		rawKey: key,
		cipher: cipher,
	}, nil
}

func (k *InProcessWrappedKey) generateHMACDigest(ctx context.Context, msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.rawKey)
	_, err := mac.Write(msg)
	if err != nil {
		panic("failed to compute hmac")
	}
	return mac.Sum(nil), nil
}

func (k *InProcessWrappedKey) VerifyBinding(ctx context.Context, policy, binding []byte) error {
	actualHMAC, err := k.generateHMACDigest(ctx, policy)
	if err != nil {
		return fmt.Errorf("unable to generate policy hmac: %w", err)
	}

	if !hmac.Equal(actualHMAC, binding) {
		return errors.New("policy hmac mismatch")
	}

	return nil
}

func (k *InProcessWrappedKey) Export(encapsulator trust.Encapsulator) ([]byte, error) {
	return encapsulator.Encrypt(k.rawKey)
}

func (k *InProcessWrappedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	decryptedData, err := k.cipher.DecryptWithIVAndTagSize(iv, body, tagSize)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func (vm *VaultKeyService) Decrypt(ctx context.Context, keyID trust.KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (trust.ProtectedKey, error) {
	if err := vm.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	item, exists := vm.items[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	decryptedData, err := item.private.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return NewInProcessAESKey(decryptedData)
}

func (vm *VaultKeyService) DeriveKey(ctx context.Context, kasKID trust.KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (trust.ProtectedKey, error) {
	if err := vm.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	vi := vm.items[kasKID]
	if vi == nil {
		return nil, fmt.Errorf("key not found: %s", kasKID)
	}
	if vi.nano == nil {
		return nil, fmt.Errorf("key %s is not a nano key", kasKID)
	}
	key, err := vi.nano.DeriveNanoTDFSymmetricKey(curve, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return NewInProcessAESKey(key)
}

func (vm *VaultKeyService) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (trust.Encapsulator, error) {
	return ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, nanoSalt(), nil)
}

func (vm *VaultKeyService) Close() {
	// Implement any cleanup logic if necessary
}
