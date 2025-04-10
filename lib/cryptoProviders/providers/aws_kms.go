package providers

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/opentdf/platform/lib/cryptoProviders"
)

type AWS struct {
	client *kms.Client
}

type awsKey struct {
	KeyID string `json:"keyId"`
}

func NewAWS() *AWS {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic("configuration error, " + err.Error())
	}
	kmsClient := kms.NewFromConfig(cfg)
	// AWS KMS client initialization here
	return &AWS{
		client: kmsClient,
	}
}

func (a *AWS) Identifier() string {
	return "aws"
}

// Implement other methods for AWS provider
func (a *AWS) EncryptRSAOAEP(ctx context.Context, hash crypto.Hash, keyRef cryptoProviders.KeyRef, data []byte) ([]byte, error) {
	// AWS KMS encryption logic here
	fmt.Println("AWS RSA Encrypt!!!!!!!!!!")

	key := &awsKey{}

	err := json.Unmarshal([]byte(keyRef.Key), key)
	if err != nil {
		return nil, err
	}

	encOut, err := a.client.Encrypt(ctx, &kms.EncryptInput{
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1,
		KeyId:               aws.String(key.KeyID),
		Plaintext:           data,
	})
	if err != nil {
		return nil, err
	}

	return encOut.CiphertextBlob, nil
}

func (a *AWS) DecryptRSAOAEP(ctx context.Context, keyRef cryptoProviders.KeyRef, cipherText []byte) ([]byte, error) {
	fmt.Println("AWS RSA Decrypt!!!!!!!!!!")

	// AWS KMS decryption logic here
	key := &awsKey{}

	err := json.Unmarshal([]byte(keyRef.Key), key)
	if err != nil {
		return nil, err
	}

	decOut, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1,
		KeyId:               aws.String(key.KeyID),
		CiphertextBlob:      cipherText,
	})
	if err != nil {
		return nil, err
	}
	return decOut.Plaintext, nil
}

func (d *AWS) EncryptEC(ctx context.Context, keyRef cryptoProviders.KeyRef, ephemeralPublicKey []byte, data []byte) ([]byte, []byte, error) {
	fmt.Println("AWS EC Encrypt!!!!!!!!!!")

	return nil, nil, nil
}

func (d *AWS) DecryptEC(ctx context.Context, keyRef cryptoProviders.KeyRef, ephemeralPublicKey []byte, cipherText []byte) ([]byte, error) {
	fmt.Println("AWS EC Decrypt!!!!!!!!!!")
	key := &awsKey{}

	err := json.Unmarshal([]byte(keyRef.Key), key)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(ephemeralPublicKey))

	block, _ := pem.Decode(ephemeralPublicKey)
	if block == nil {
		return nil, errors.New("failed to decode ephemeral public key")
	}

	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	}

	sk, err := d.client.DeriveSharedSecret(ctx, &kms.DeriveSharedSecretInput{
		KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh, // Only value allowed
		KeyId:                 aws.String(key.KeyID),
		PublicKey:             block.Bytes,
	})
	if err != nil {
		return nil, err
	}
	fmt.Println("Shared Secret:", hex.EncodeToString(sk.SharedSecret))
	return sk.SharedSecret, nil
}

func (a *AWS) DecryptSymmetric(ctx context.Context, keyRef []byte, cipherText []byte) ([]byte, error) {
	fmt.Println("AWS Symmetric Decrypt!!!!!!!!!!")
	key := &awsKey{}

	err := json.Unmarshal(keyRef, key)
	if err != nil {
		return nil, err
	}

	decOut, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		KeyId:               aws.String(key.KeyID),
		CiphertextBlob:      cipherText,
	})
	if err != nil {
		return nil, err
	}
	return decOut.Plaintext, nil
}
