package p11

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"

	"github.com/miekg/pkcs11"
)

// See https://github.com/ThalesIgnite/crypto11/blob/d334790e12893aa2f8a2c454b16003dfd9f7d2de/rsa.go
const (
	ErrUnsupportedRSAOptions = Error("hsm unsupported RSA option value")
	ErrHsmDecrypt            = Error("hsm decrypt error")
)
const keyLength = 32

type Pkcs11Session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

type Pkcs11PrivateKeyRSA struct {
	handle pkcs11.ObjectHandle
}

type Pkcs11PrivateKeyEC struct {
	handle pkcs11.ObjectHandle
}

func NewSession(ctx *pkcs11.Ctx, handle pkcs11.SessionHandle) Pkcs11Session {
	return Pkcs11Session{
		handle: handle,
		ctx:    ctx,
	}
}

func NewPrivateKeyRSA(handle pkcs11.ObjectHandle) Pkcs11PrivateKeyRSA {
	return Pkcs11PrivateKeyRSA{
		handle: handle,
	}
}

func NewPrivateKeyEC(handle pkcs11.ObjectHandle) Pkcs11PrivateKeyEC {
	return Pkcs11PrivateKeyEC{
		handle: handle,
	}
}

func DecryptOAEP(session *Pkcs11Session, key *Pkcs11PrivateKeyRSA, ciphertext []byte, hashFunction crypto.Hash, label []byte) ([]byte, error) {
	hashAlg, mgfAlg, _, err := hashToPKCS11(hashFunction)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(hashAlg, mgfAlg, pkcs11.CKZ_DATA_SPECIFIED, label))

	err = session.ctx.DecryptInit(session.handle, []*pkcs11.Mechanism{mech}, key.handle)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}
	decrypt, err := session.ctx.Decrypt(session.handle, ciphertext)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}
	return decrypt, nil
}

func hashToPKCS11(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, ErrUnsupportedRSAOptions
	}
}

func GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte, session *Pkcs11Session, key *Pkcs11PrivateKeyEC) ([]byte, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	params := pkcs11.ECDH1DeriveParams{KDF: pkcs11.CKD_NULL, PublicKeyData: ephemeralPublicKeyBytes}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, &params),
	}

	handle, err := session.ctx.DeriveKey(session.handle, mech, key.handle, template)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attr, err := session.ctx.GetAttributeValue(session.handle, handle, template)
	if err != nil {
		return nil, err
	}

	symmetricKey := attr[0].Value

	salt := versionSalt()
	hkdf := hkdf.New(sha256.New, symmetricKey, salt, nil)

	derivedKey := make([]byte, keyLength)
	_, err = io.ReadFull(hkdf, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	return derivedKey, nil
}

func GenerateNanoTDFSessionKey(session *Pkcs11Session, privateKeyHandle pkcs11.ObjectHandle, ephemeralPublicKey []byte) ([]byte, error) {

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	params := pkcs11.ECDH1DeriveParams{KDF: pkcs11.CKD_NULL, PublicKeyData: ephemeralPublicKey}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, &params),
	}

	handle, err := session.ctx.DeriveKey(session.handle, mech, privateKeyHandle, template)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attr, err := session.ctx.GetAttributeValue(session.handle, handle, template)
	if err != nil {
		return nil, err
	}

	sessionKey := attr[0].Value
	salt := versionSalt()
	hkdf := hkdf.New(sha256.New, sessionKey, salt, nil)

	derivedKey := make([]byte, keyLength)
	_, err = io.ReadFull(hkdf, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	return derivedKey, nil
}

func GenerateEphemeralKasKeys(session *Pkcs11Session) (pkcs11.ObjectHandle, []byte, error) {
	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}), // P-256 OID
	}

	prvKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	pubHandle, prvHandle, err := session.ctx.GenerateKeyPair(session.handle,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubKeyTemplate, prvKeyTemplate)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	pubBytes, err := session.ctx.GetAttributeValue(session.handle, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to retrieve public key bytes: %w", err)
	}
	publicKeyBytes := pubBytes[0].Value

	return prvHandle, publicKeyBytes, nil
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	return digest.Sum(nil)
}

type Error string

func (e Error) Error() string {
	return string(e)
}
