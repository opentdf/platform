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
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/trust"
)

type VaultItem struct {
	kid     trust.KeyIdentifier
	alg     ocrypto.KeyType
	public  ocrypto.PublicKeyEncryptor
	private ocrypto.PrivateKeyDecryptor
	nano    *ocrypto.ECDecryptor
}

func (v *VaultItem) ID() trust.KeyIdentifier {
	return v.kid
}

func (v *VaultItem) Algorithm() ocrypto.KeyType {
	return v.alg
}

func (v *VaultItem) ProviderConfig() *policy.KeyProviderConfig {
	return &policy.KeyProviderConfig{
		Manager: "vault",
	}
}

func (v *VaultItem) IsLegacy() bool {
	return false
}

func (v *VaultItem) ExportPrivateKey(_ context.Context) (*trust.PrivateKey, error) {
	return nil, errors.New("private key export not supported")
}

func (v *VaultItem) ExportPublicKey(_ context.Context, format trust.KeyType) (string, error) {
	if format != trust.KeyTypePKCS8 {
		return "", fmt.Errorf("unsupported key format: %v", format)
	}
	return v.public.PublicKeyInPemFormat()
}

func (v *VaultItem) ExportCertificate(_ context.Context) (string, error) {
	return "", errors.New("certificate export not supported")
}

func (v VaultItem) System() string {
	return "examples.opentdf.io/vault"
}

type VaultKeyService struct {
	client *vault.Client
	items  map[trust.KeyIdentifier]*VaultItem
}

func NewVaultKeyService(client *vault.Client) *VaultKeyService {
	return &VaultKeyService{
		client: client,
		items:  make(map[trust.KeyIdentifier]*VaultItem),
	}
}

func (v VaultKeyService) Name() string {
	return "examples.opentdf.io/vault"
}

func (v *VaultKeyService) LoadKeys(ctx context.Context) error {
	secretsPath := "secret/metadata/kas_keypair"
	lra, err := v.client.Logical().ListWithContext(ctx, secretsPath)
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
		if k, err := v.loadKey(ctx, key); err != nil {
			slog.ErrorContext(ctx, "failed to load key",
				slog.Any("key", key),
				slog.Any("err", err))
		} else {
			slog.DebugContext(ctx, "loaded key", slog.Any("key", key))
			v.items[k.ID()] = k
		}
	}

	if len(v.items) == 0 {
		return errors.New("no valid keys were found")
	}
	return nil
}

func nanoSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	salt := digest.Sum(nil)
	return salt
}

func (v *VaultKeyService) FindKeyByAlgorithm(ctx context.Context, algorithm ocrypto.KeyType, _ bool) (trust.KeyDetails, error) {
	// Legacy keys are not supported
	if err := v.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	for _, item := range v.items {
		if item.Algorithm() == algorithm {
			return item, nil
		}
	}
	return nil, errors.New("no key found for algorithm: " + string(algorithm))
}

func (v *VaultKeyService) FindKeyByID(ctx context.Context, id trust.KeyIdentifier) (trust.KeyDetails, error) {
	if err := v.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	item, exists := v.items[id]
	if !exists {
		return nil, fmt.Errorf("no key found for ID: %s", id)
	}
	return item, nil
}

func (v *VaultKeyService) ListKeys(ctx context.Context) ([]trust.KeyDetails, error) {
	if err := v.LoadKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	keys := make([]trust.KeyDetails, 0, len(v.items))
	for _, item := range v.items {
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
		return nil, errors.New("key cannot be empty")
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

func (k *InProcessWrappedKey) VerifyBinding(_ context.Context, policy, binding []byte) error {
	actualHMAC, err := k.generateHMACDigest(policy)
	if err != nil {
		return fmt.Errorf("unable to generate policy hmac: %w", err)
	}

	if !hmac.Equal(actualHMAC, binding) {
		return errors.New("policy hmac mismatch")
	}

	return nil
}

func (k *InProcessWrappedKey) Export(encapsulator ocrypto.Encapsulator) ([]byte, error) {
	return encapsulator.Encrypt(k.rawKey)
}

func (k *InProcessWrappedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	decryptedData, err := k.cipher.DecryptWithIVAndTagSize(iv, body, tagSize)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func (v *VaultKeyService) Decrypt(ctx context.Context, keyDetails trust.KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ocrypto.ProtectedKey, error) {
	if err := v.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	item, exists := v.items[keyDetails.ID()]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyDetails.ID())
	}

	decryptedData, err := item.private.DecryptWithEphemeralKey(ciphertext, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return NewInProcessAESKey(decryptedData)
}

func (v *VaultKeyService) DeriveKey(ctx context.Context, keyDetails trust.KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ocrypto.ProtectedKey, error) {
	if err := v.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}
	vi := v.items[keyDetails.ID()]
	if vi == nil {
		return nil, fmt.Errorf("key not found: %s", keyDetails.ID())
	}
	if vi.nano == nil {
		return nil, fmt.Errorf("key %s is not a nano key", keyDetails.ID())
	}
	key, err := vi.nano.DeriveNanoTDFSymmetricKey(curve, ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return NewInProcessAESKey(key)
}

type OCEncapsulator struct {
	ocrypto.PublicKeyEncryptor
}

func (e *OCEncapsulator) Encapsulate(dek ocrypto.ProtectedKey) ([]byte, error) {
	// Delegate to the ProtectedKey to avoid exposing raw key material
	return dek.Export(e)
}

func (e *OCEncapsulator) PublicKeyAsPEM() (string, error) {
	return e.PublicKeyInPemFormat()
}

func (v *VaultKeyService) GenerateECSessionKey(_ context.Context, ephemeralPublicKey string) (ocrypto.Encapsulator, error) {
	pke, err := ocrypto.FromPublicPEMWithSalt(ephemeralPublicKey, nanoSalt(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key encryptor: %w", err)
	}
	return &OCEncapsulator{PublicKeyEncryptor: pke}, nil
}

func (v *VaultKeyService) Close() {
	// Implement any cleanup logic if necessary
}

func (k *InProcessWrappedKey) generateHMACDigest(msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.rawKey)
	_, err := mac.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to write to HMAC: %w", err)
	}
	return mac.Sum(nil), nil
}

func (v *VaultKeyService) loadKey(ctx context.Context, key interface{}) (*VaultItem, error) {
	var kid trust.KeyIdentifier
	if keyStr, ok := key.(string); ok {
		kid = trust.KeyIdentifier(keyStr)
	} else {
		return nil, fmt.Errorf("key is not a string: %T", key)
	}

	secretPath := fmt.Sprintf("kas_keypair/%s", kid)
	secret, err := v.client.KVv2("secret").Get(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret in kv store secret with path [%s]: %w", secretPath, err)
	}

	var privateKeyPEM string
	if pem, ok := secret.Data["private"].(string); ok {
		privateKeyPEM = pem
	} else {
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
		if ec2, ecOK := nk.(ocrypto.ECDecryptor); ecOK {
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

	alg := ocrypto.KeyType(algorithm)
	if !alg.IsEC() && !alg.IsRSA() {
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithm)
	}

	return &VaultItem{
		kid:     kid,
		alg:     alg,
		public:  publicKey,
		private: privateKey,
		nano:    nanoKey,
	}, nil
}

func (v *VaultKeyService) refreshKeys(ctx context.Context) error {
	if len(v.items) > 0 {
		return nil
	}
	return v.LoadKeys(ctx)
}
