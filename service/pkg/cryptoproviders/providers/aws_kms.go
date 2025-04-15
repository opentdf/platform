package providers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/opentdf/platform/service/pkg/cryptoproviders"
)

type AWS struct {
	client *kms.Client
}

type awsKey struct {
	KeyID string `json:"keyId"`
}

type publicKeyInfo struct {
	Algorithm struct { // Field @1 (Implicit Sequence)
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString // Field @2 <<-- ERROR HERE
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

// EncryptAsymmetric provides a unified interface for asymmetric encryption
func (a *AWS) EncryptAsymmetric(ctx context.Context, opts cryptoproviders.EncryptOpts) ([]byte, []byte, error) {
	key := &awsKey{}
	if err := json.Unmarshal(opts.KeyRef.GetRawBytes(), key); err != nil {
		return nil, nil, err
	}

	if opts.KeyRef.IsRSA() {
		encOut, err := a.client.Encrypt(ctx, &kms.EncryptInput{
			EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1,
			KeyId:               aws.String(key.KeyID),
			Plaintext:           opts.Data,
		})
		if err != nil {
			return nil, nil, err
		}
		return encOut.CiphertextBlob, nil, nil
	}

	if opts.KeyRef.IsEC() {
		return nil, nil, fmt.Errorf("EC encryption not implemented for AWS KMS")
	}

	return nil, nil, fmt.Errorf("unsupported algorithm")
}

// DecryptAsymmetric provides a unified interface for asymmetric decryption
func (a *AWS) DecryptAsymmetric(ctx context.Context, opts cryptoproviders.DecryptOpts) ([]byte, error) {
	key := &awsKey{}
	if err := json.Unmarshal(opts.KeyRef.GetRawBytes(), key); err != nil {
		return nil, err
	}

	if opts.KeyRef.IsRSA() {
		decOut, err := a.client.Decrypt(ctx, &kms.DecryptInput{
			EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha1,
			KeyId:               aws.String(key.KeyID),
			CiphertextBlob:      opts.CipherText,
		})
		if err != nil {
			return nil, err
		}
		return decOut.Plaintext, nil
	}

	if opts.KeyRef.IsEC() {
		var ephemeralKey []byte
		switch opts.EphemeralKey[0] {
		case 0x04: // Uncompressed
			ephemeralKey = opts.EphemeralKey
		case 0x02, 0x03: // Compressed
			publicKey, err := uncompressECPublicKey(elliptic.P256(), opts.EphemeralKey)
			if err != nil {
				return nil, fmt.Errorf("failed to uncompress public key: %w", err)
			}

			spkiBytes, err := x509.MarshalPKIXPublicKey(publicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal public key to SPKI DER format: %w", err)
			}
			ephemeralKey = spkiBytes
		default:
			return nil, fmt.Errorf("unsupported public key format: %x", opts.EphemeralKey[0])
		}

		// Derive shared secret using AWS KMS
		sk, err := a.client.DeriveSharedSecret(ctx, &kms.DeriveSharedSecretInput{
			KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh,
			KeyId:                 aws.String(key.KeyID),
			PublicKey:             ephemeralKey,
		})
		if err != nil {
			return nil, err
		}
		return sk.SharedSecret, nil
	}

	return nil, fmt.Errorf("unsupported algorithm")
}

// EncryptSymmetric encrypts data using AWS KMS symmetric encryption.
func (a *AWS) EncryptSymmetric(ctx context.Context, keyRef []byte, data []byte) ([]byte, error) {
	key := &awsKey{}
	if err := json.Unmarshal(keyRef, key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AWS key reference: %w", err)
	}

	encOut, err := a.client.Encrypt(ctx, &kms.EncryptInput{
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		KeyId:               aws.String(key.KeyID),
		Plaintext:           data,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS encrypt failed: %w", err)
	}
	return encOut.CiphertextBlob, nil
}

// DecryptSymmetric decrypts data using AWS KMS symmetric decryption.
func (a *AWS) DecryptSymmetric(ctx context.Context, keyRef []byte, cipherText []byte) ([]byte, error) {
	fmt.Println("AWS Symmetric Decrypt!!!!!!!!!!")
	key := &awsKey{}

	err := json.Unmarshal(keyRef, key)
	if err != nil {
		return nil, err
	}

	decOut, err := a.client.Decrypt(context.Background(), &kms.DecryptInput{
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		KeyId:               aws.String(key.KeyID),
		CiphertextBlob:      cipherText,
	})
	if err != nil {
		return nil, err
	}
	return decOut.Plaintext, nil
}

func uncompressECPublicKey(curve elliptic.Curve, compressed []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, errors.New("failed to unmarshal compressed key")
	}
	// Basic check: Ensure the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("decompressed point is not on the specified curve")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
