package ocrypto

import (
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// kem is the post-quantum KEM contract implemented by the pure ML-KEM schemes.
// It collapses the `mlkem-wrapped` wrap/unwrap path into one envelope and one
// AES-GCM call site. The hybrid PQ/T schemes (X-Wing and the NIST EC + ML-KEM
// composites) are IETF-draft-conformant and live behind their own per-scheme
// encryptor/decryptor types in hybrid_nist.go and xwing.go, reached via the
// OID-routed dispatcher in asym_encryption.go / asym_decryption.go.
type kem interface {
	keyType() KeyType
	scheme() SchemeType
	pubSize() int
	privSize() int
	ctSize() int
	encapsulate(pub []byte) (sharedSecret, ciphertext []byte, err error)
	decapsulate(priv, ct []byte) (sharedSecret []byte, err error)
	// publicKeyPEM returns the PEM serialization for the given raw public key.
	// Each adapter handles its own format. After the planned follow-up moves
	// X-Wing and the NIST hybrid keys onto standard SPKI PEM blocks this
	// per-adapter hook collapses to a single shared helper.
	publicKeyPEM(pub []byte) (string, error)
	// wrapKey returns the AES-256 key used to seal the DEK from the
	// shared secret produced by encapsulate / decapsulate.
	//
	// ML-KEM returns the 32-byte Decaps output verbatim (no KDF) so that an
	// HSM-backed KAS holding the shared secret as a CKK_AES, non-extractable
	// object can perform AES-GCM directly. See FIPS 203 §6.3 / §7.3 and
	// adr/decisions/2026-06-16-mlkem-direct-key-wrap.md.
	//
	// Hybrid PQ/T schemes (X-Wing, NIST EC + ML-KEM) concatenate two
	// shared-secret halves and still require HKDF-SHA256 over (salt, info)
	// for proper combiner hygiene.
	wrapKey(sharedSecret, salt, info []byte) ([]byte, error)
}

// kemEnvelope is the ASN.1 wire format for every KEM-wrapped DEK across
// `hybrid-wrapped` and `mlkem-wrapped` KAOs. It is byte-identical to the three
// legacy structs (MLKEMWrappedKey, XWingWrappedKey, HybridNISTWrappedKey) it
// replaces — same tags, same field order.
type kemEnvelope struct {
	KEMCiphertext []byte `asn1:"tag:0"`
	EncryptedDEK  []byte `asn1:"tag:1"`
}

// kemWrapKeySize is the AES-256 wrap key length. Pure ML-KEM uses the
// 32-byte Decaps output directly; hybrid PQ/T schemes derive it via
// HKDF-SHA256 over the combined shared secret.
const kemWrapKeySize = 32

// kemRegistry maps the SPKI/PKCS#8 OID published for a KEM scheme to a
// constructor that returns a kem adapter bound to that scheme. ML-KEM is the
// only family with standardized OIDs landed today; the planned hybrid PQ/T
// SPKI follow-up adds X-Wing and the two NIST hybrid OIDs by inserting
// registry entries here.
var kemRegistry = map[string]func() kem{
	OIDMLKEM768.String():  func() kem { return mlkemKEM{variant: mlkem768} },
	OIDMLKEM1024.String(): func() kem { return mlkemKEM{variant: mlkem1024} },
}

// kemByOID returns the kem adapter registered for the supplied OID, or false
// if the OID is not a recognised KEM algorithm.
func kemByOID(oid asn1.ObjectIdentifier) (kem, bool) {
	ctor, ok := kemRegistry[oid.String()]
	if !ok {
		return nil, false
	}
	return ctor(), true
}

// hybridKEMByOID returns the hybrid PQ/T kem adapter for the supplied
// AlgorithmIdentifier OID. The hybrid schemes are kept out of kemRegistry
// because their PKCS#8 private-key encoding differs from the RFC 5958 KEM
// CHOICE that parseKEMPrivatePKCS8 expects (X-Wing/NIST store the raw key
// directly, ML-KEM double-wraps the seed in a [0] IMPLICIT OCTET STRING).
// The OID-routing dispatchers in asym_encryption.go / asym_decryption.go use
// this helper to build kemEncryptor / kemDecryptor for hybrid keys.
func hybridKEMByOID(oid asn1.ObjectIdentifier) (kem, bool) {
	switch {
	case oid.Equal(oidXWing):
		return xwingKEM{}, true
	case oid.Equal(oidCompositeMLKEM768P256):
		return hybridNISTKEM{params: &p256mlkem768Params}, true
	case oid.Equal(oidCompositeMLKEM1024P384):
		return hybridNISTKEM{params: &p384mlkem1024Params}, true
	default:
		return nil, false
	}
}

// IsKEMKeyType reports whether the supplied KeyType is one of the KEM schemes
// — pure ML-KEM or hybrid PQ/T — that wrap a DEK through FromPublicPEM /
// FromPrivatePEM rather than the RSA/EC paths. Callers use it as the routing
// gate before delegating to WrapDEK.
func IsKEMKeyType(kt KeyType) bool {
	return IsMLKEMKeyType(kt) || IsHybridKeyType(kt)
}

// --- mlkemKEM adapter -------------------------------------------------------

type mlkemVariant int

const (
	mlkem768 mlkemVariant = iota
	mlkem1024
)

type mlkemKEM struct {
	variant mlkemVariant
}

func (m mlkemKEM) keyType() KeyType {
	if m.variant == mlkem1024 {
		return MLKEM1024Key
	}
	return MLKEM768Key
}

func (mlkemKEM) scheme() SchemeType { return MLKEM }

func (m mlkemKEM) pubSize() int {
	if m.variant == mlkem1024 {
		return MLKEM1024PublicKeySize
	}
	return MLKEM768PublicKeySize
}

func (m mlkemKEM) privSize() int {
	if m.variant == mlkem1024 {
		return MLKEM1024PrivateKeySize
	}
	return MLKEM768PrivateKeySize
}

func (m mlkemKEM) ctSize() int {
	if m.variant == mlkem1024 {
		return MLKEM1024CiphertextSize
	}
	return MLKEM768CiphertextSize
}

func (m mlkemKEM) encapsulate(pub []byte) ([]byte, []byte, error) {
	if len(pub) != m.pubSize() {
		return nil, nil, fmt.Errorf("invalid %s public key size: got %d want %d", m.keyType(), len(pub), m.pubSize())
	}
	if m.variant == mlkem1024 {
		ek, err := mlkem.NewEncapsulationKey1024(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey1024 failed: %w", err)
		}
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	}
	ek, err := mlkem.NewEncapsulationKey768(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem.NewEncapsulationKey768 failed: %w", err)
	}
	ss, ct := ek.Encapsulate()
	return ss, ct, nil
}

func (m mlkemKEM) decapsulate(priv, ct []byte) ([]byte, error) {
	if len(priv) != m.privSize() {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", m.keyType(), len(priv), m.privSize())
	}
	if m.variant == mlkem1024 {
		dk, err := mlkem.NewDecapsulationKey1024(priv)
		if err != nil {
			return nil, fmt.Errorf("mlkem.NewDecapsulationKey1024 failed: %w", err)
		}
		ss, err := dk.Decapsulate(ct)
		if err != nil {
			return nil, fmt.Errorf("mlkem1024 decapsulate failed: %w", err)
		}
		return ss, nil
	}
	dk, err := mlkem.NewDecapsulationKey768(priv)
	if err != nil {
		return nil, fmt.Errorf("mlkem.NewDecapsulationKey768 failed: %w", err)
	}
	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("mlkem768 decapsulate failed: %w", err)
	}
	return ss, nil
}

func (m mlkemKEM) publicKeyPEM(pub []byte) (string, error) {
	oid := OIDMLKEM768
	if m.variant == mlkem1024 {
		oid = OIDMLKEM1024
	}
	der, err := marshalKEMPublicSPKI(oid, pub)
	if err != nil {
		return "", fmt.Errorf("marshal %s SPKI failed: %w", m.keyType(), err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPublicKey, Bytes: der})), nil
}

// wrapKey returns the ML-KEM Decaps output directly as the AES-256 wrap key.
//
// FIPS 203 §6.3 / §7.3 specify that ML-KEM Decaps emits a uniformly random
// 32-byte shared secret K that is suitable for direct use as a symmetric key,
// and ML-KEM produces a fresh K per encapsulation by construction. salt and
// info are ignored on purpose so that HSM-backed KAS providers that can only
// materialize the shared secret as a non-extractable CKK_AES object (e.g.
// Thales Luna T-Series 7.15.1 in strict-FIPS mode, which rejects HMAC over
// the Decaps output with CKR_ATTRIBUTE_TYPE_INVALID) can still complete
// AES-GCM unwrap without an HKDF step.
func (mlkemKEM) wrapKey(sharedSecret, _ /*salt*/, _ /*info*/ []byte) ([]byte, error) {
	if len(sharedSecret) != kemWrapKeySize {
		return nil, fmt.Errorf("invalid ML-KEM shared secret size: got %d want %d", len(sharedSecret), kemWrapKeySize)
	}
	return append([]byte(nil), sharedSecret...), nil
}

// --- wrap / unwrap ----------------------------------------------------------

// wrapDEKWithKEM encapsulates against pub, asks the scheme adapter for an
// AES-256 wrap key (HKDF for hybrid PQ/T, direct shared-secret for pure
// ML-KEM), and emits the kemEnvelope ASN.1 DER blob carrying (KEM
// ciphertext, AES-GCM-encrypted DEK).
func wrapDEKWithKEM(k kem, pub, dek, salt, info []byte) ([]byte, error) {
	sharedSecret, ciphertext, err := k.encapsulate(pub)
	if err != nil {
		return nil, err
	}

	wrapKey, err := k.wrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	encryptedDEK, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}

	wrappedDER, err := asn1.Marshal(kemEnvelope{
		KEMCiphertext: ciphertext,
		EncryptedDEK:  encryptedDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return wrappedDER, nil
}

// unwrapDEKWithKEM parses the kemEnvelope DER blob, decapsulates with priv to
// recover the shared secret, asks the scheme adapter for the matching AES-256
// wrap key, and AES-GCM decrypts the DEK.
func unwrapDEKWithKEM(k kem, priv, der, salt, info []byte) ([]byte, error) {
	var env kemEnvelope
	rest, err := asn1.Unmarshal(der, &env)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("asn1.Unmarshal left %d trailing bytes", len(rest))
	}
	if len(env.KEMCiphertext) != k.ctSize() {
		return nil, fmt.Errorf("invalid %s ciphertext size: got %d want %d", k.keyType(), len(env.KEMCiphertext), k.ctSize())
	}

	sharedSecret, err := k.decapsulate(priv, env.KEMCiphertext)
	if err != nil {
		return nil, err
	}

	wrapKey, err := k.wrapKey(sharedSecret, salt, info)
	if err != nil {
		return nil, err
	}

	gcm, err := NewAESGcm(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("NewAESGcm failed: %w", err)
	}

	plaintext, err := gcm.Decrypt(env.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	return plaintext, nil
}

// --- unified encryptor / decryptor ------------------------------------------

// kemEncryptor satisfies PublicKeyEncryptor for every KEM family. It replaces
// the per-variant MLKEMEncryptor*, XWingEncryptor, and HybridNISTEncryptor
// types behind the FromPublicPEM factory.
type kemEncryptor struct {
	k         kem
	publicKey []byte
	salt      []byte
	info      []byte
}

func newKEMEncryptor(k kem, publicKey, salt, info []byte) (*kemEncryptor, error) {
	if len(publicKey) != k.pubSize() {
		return nil, fmt.Errorf("invalid %s public key size: got %d want %d", k.keyType(), len(publicKey), k.pubSize())
	}
	return &kemEncryptor{
		k:         k,
		publicKey: append([]byte(nil), publicKey...),
		salt:      cloneOrNil(salt),
		info:      cloneOrNil(info),
	}, nil
}

func (e *kemEncryptor) Encrypt(data []byte) ([]byte, error) {
	return wrapDEKWithKEM(e.k, e.publicKey, data, e.salt, e.info)
}

func (e *kemEncryptor) PublicKeyInPemFormat() (string, error) {
	return e.k.publicKeyPEM(e.publicKey)
}

func (e *kemEncryptor) Type() SchemeType     { return e.k.scheme() }
func (e *kemEncryptor) KeyType() KeyType     { return e.k.keyType() }
func (e *kemEncryptor) EphemeralKey() []byte { return nil }

func (e *kemEncryptor) Metadata() (map[string]string, error) {
	return make(map[string]string), nil
}

// kemDecryptor satisfies PrivateKeyDecryptor for every KEM family. It replaces
// the per-variant MLKEMDecryptor*, XWingDecryptor, and HybridNISTDecryptor
// types behind the FromPrivatePEM factory.
type kemDecryptor struct {
	k          kem
	privateKey []byte
	salt       []byte
	info       []byte
}

func newKEMDecryptor(k kem, privateKey, salt, info []byte) (*kemDecryptor, error) {
	// A negative privSize signals a variable-length encoding (the NIST hybrid's
	// mlkemSeed||ECPrivateKey DER), whose exact length is validated inside
	// decapsulate. Fixed-size schemes (ML-KEM, X-Wing) keep the strict check.
	if k.privSize() >= 0 && len(privateKey) != k.privSize() {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", k.keyType(), len(privateKey), k.privSize())
	}
	return &kemDecryptor{
		k:          k,
		privateKey: append([]byte(nil), privateKey...),
		salt:       cloneOrNil(salt),
		info:       cloneOrNil(info),
	}, nil
}

func (d *kemDecryptor) Decrypt(data []byte) ([]byte, error) {
	return unwrapDEKWithKEM(d.k, d.privateKey, data, d.salt, d.info)
}

// KeyType reports the KEM scheme this decryptor was built for. It lets callers
// (e.g. the service layer's assertDecryptorAlgorithm guard) confirm that a PEM
// dispatched to the scheme they expected.
func (d *kemDecryptor) KeyType() KeyType { return d.k.keyType() }
