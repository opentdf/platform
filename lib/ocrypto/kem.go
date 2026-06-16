package ocrypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

// kem is the post-quantum KEM contract implemented by ML-KEM, X-Wing, and the
// NIST hybrid PQ/T schemes. Unifying behind this single interface collapses the
// `hybrid-wrapped` and `mlkem-wrapped` wrap/unwrap paths into one envelope and
// one AES-GCM call site; per-scheme key-derivation policy is selected by
// wrapKey below.
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

// kemWrapKeySize is the AES-256 wrap key length derived via HKDF.
const kemWrapKeySize = 32

// kemRegistry maps the SPKI/PKCS#8 OID published for a KEM scheme to a
// constructor that returns a kem adapter bound to that scheme. ML-KEM is the
// only family with standardized OIDs landed today; the planned hybrid PQ/T
// SPKI follow-up adds X-Wing and the two NIST hybrid OIDs by inserting
// registry entries here.
var kemRegistry = map[string]func() kem{
	OidMLKEM768.String():  func() kem { return mlkemKEM{variant: mlkem768} },
	OidMLKEM1024.String(): func() kem { return mlkemKEM{variant: mlkem1024} },
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

// kemByKeyType returns the kem adapter for the supplied KeyType, covering both
// pure ML-KEM and hybrid PQ/T schemes. This is the entry point for wrap-side
// dispatch where the caller knows the KAS algorithm but has not yet decoded a
// public key.
func kemByKeyType(kt KeyType) (kem, bool) {
	switch kt { //nolint:exhaustive // only handle KEM types; other KeyTypes return false
	case MLKEM768Key:
		return mlkemKEM{variant: mlkem768}, true
	case MLKEM1024Key:
		return mlkemKEM{variant: mlkem1024}, true
	case HybridXWingKey:
		return xwingKEM{}, true
	case HybridSecp256r1MLKEM768Key:
		return nistHybridKEM{params: &p256mlkem768Params}, true
	case HybridSecp384r1MLKEM1024Key:
		return nistHybridKEM{params: &p384mlkem1024Params}, true
	default:
		return nil, false
	}
}

// IsKEMKeyType reports whether the supplied KeyType is one of the KEM schemes
// — pure ML-KEM or hybrid PQ/T — handled by the unified wrap/unwrap path.
func IsKEMKeyType(kt KeyType) bool {
	_, ok := kemByKeyType(kt)
	return ok
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
	oid := OidMLKEM768
	if m.variant == mlkem1024 {
		oid = OidMLKEM1024
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

// --- xwingKEM adapter -------------------------------------------------------

type xwingKEM struct{}

func (xwingKEM) keyType() KeyType   { return HybridXWingKey }
func (xwingKEM) scheme() SchemeType { return Hybrid }
func (xwingKEM) pubSize() int       { return XWingPublicKeySize }
func (xwingKEM) privSize() int      { return XWingPrivateKeySize }
func (xwingKEM) ctSize() int        { return XWingCiphertextSize }

func (xwingKEM) encapsulate(pub []byte) ([]byte, []byte, error) {
	if len(pub) != XWingPublicKeySize {
		return nil, nil, fmt.Errorf("invalid X-Wing public key size: got %d want %d", len(pub), XWingPublicKeySize)
	}
	ss, ct, err := xwing.Encapsulate(pub, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("xwing.Encapsulate failed: %w", err)
	}
	return ss, ct, nil
}

func (xwingKEM) decapsulate(priv, ct []byte) ([]byte, error) {
	if len(priv) != XWingPrivateKeySize {
		return nil, fmt.Errorf("invalid X-Wing private key size: got %d want %d", len(priv), XWingPrivateKeySize)
	}
	return xwing.Decapsulate(ct, priv), nil
}

func (xwingKEM) publicKeyPEM(pub []byte) (string, error) {
	return rawToPEM(PEMBlockXWingPublicKey, pub, XWingPublicKeySize)
}

// wrapKey derives a 32-byte AES key from the X-Wing shared secret via
// HKDF-SHA256 over (salt, info).
func (xwingKEM) wrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	return hkdfWrapKey(sharedSecret, salt, info)
}

// --- nistHybridKEM adapter --------------------------------------------------

type nistHybridKEM struct {
	params *hybridNISTParams
}

func (h nistHybridKEM) keyType() KeyType { return h.params.keyType }
func (nistHybridKEM) scheme() SchemeType { return Hybrid }
func (h nistHybridKEM) pubSize() int     { return h.params.ecPubSize + h.params.mlkemPubSize }
func (h nistHybridKEM) privSize() int    { return h.params.ecPrivSize + h.params.mlkemPrivSize }
func (h nistHybridKEM) ctSize() int      { return h.params.ecPubSize + h.params.mlkemCtSize }

// mlkemAdapter returns the ML-KEM half of this hybrid scheme.
func (h nistHybridKEM) mlkemAdapter() mlkemKEM {
	if h.params.mlkemPubSize == MLKEM1024PublicKeySize {
		return mlkemKEM{variant: mlkem1024}
	}
	return mlkemKEM{variant: mlkem768}
}

func (h nistHybridKEM) encapsulate(pub []byte) ([]byte, []byte, error) {
	if len(pub) != h.pubSize() {
		return nil, nil, fmt.Errorf("invalid %s public key size: got %d want %d", h.keyType(), len(pub), h.pubSize())
	}
	ecPubBytes := pub[:h.params.ecPubSize]
	mlkemPubBytes := pub[h.params.ecPubSize:]

	ecPub, err := h.params.curve.NewPublicKey(ecPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid EC public key: %w", err)
	}
	ephemeral, err := h.params.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH ephemeral key generation failed: %w", err)
	}
	ecdhSecret, err := ephemeral.ECDH(ecPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	mlkemSecret, mlkemCt, err := h.mlkemAdapter().encapsulate(mlkemPubBytes)
	if err != nil {
		return nil, nil, err
	}

	combinedSecret := make([]byte, 0, len(ecdhSecret)+len(mlkemSecret))
	combinedSecret = append(combinedSecret, ecdhSecret...)
	combinedSecret = append(combinedSecret, mlkemSecret...)

	hybridCt := make([]byte, 0, len(ephemeralPub)+len(mlkemCt))
	hybridCt = append(hybridCt, ephemeralPub...)
	hybridCt = append(hybridCt, mlkemCt...)

	return combinedSecret, hybridCt, nil
}

func (h nistHybridKEM) decapsulate(priv, ct []byte) ([]byte, error) {
	if len(priv) != h.privSize() {
		return nil, fmt.Errorf("invalid %s private key size: got %d want %d", h.keyType(), len(priv), h.privSize())
	}
	if len(ct) != h.ctSize() {
		return nil, fmt.Errorf("invalid %s ciphertext size: got %d want %d", h.keyType(), len(ct), h.ctSize())
	}

	ephemeralPubBytes := ct[:h.params.ecPubSize]
	mlkemCtBytes := ct[h.params.ecPubSize:]
	ecPrivBytes := priv[:h.params.ecPrivSize]
	mlkemPrivBytes := priv[h.params.ecPrivSize:]

	ecPriv, err := h.params.curve.NewPrivateKey(ecPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC private key: %w", err)
	}
	ephemeralPub, err := h.params.curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral EC public key: %w", err)
	}
	ecdhSecret, err := ecPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// FIPS 203 §6.3 implicit rejection: a wrong-key ciphertext yields a
	// pseudorandom shared secret without an error here; authentication is
	// enforced by AES-GCM at the wrap layer.
	mlkemSecret, err := h.mlkemAdapter().decapsulate(mlkemPrivBytes, mlkemCtBytes)
	if err != nil {
		return nil, err
	}

	combinedSecret := make([]byte, 0, len(ecdhSecret)+len(mlkemSecret))
	combinedSecret = append(combinedSecret, ecdhSecret...)
	combinedSecret = append(combinedSecret, mlkemSecret...)

	return combinedSecret, nil
}

func (h nistHybridKEM) publicKeyPEM(pub []byte) (string, error) {
	return rawToPEM(h.params.pubPEMBlock, pub, h.pubSize())
}

// wrapKey derives a 32-byte AES key from the concatenated EC+ML-KEM shared
// secret via HKDF-SHA256 over (salt, info). The KDF here is load-bearing: it
// is the combiner that binds the two halves of the hybrid into a single
// uniformly-random wrap key.
func (nistHybridKEM) wrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	return hkdfWrapKey(sharedSecret, salt, info)
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

// hkdfWrapKey derives the AES-256 wrap key used by the hybrid PQ/T KEM
// schemes (X-Wing, NIST EC + ML-KEM). Pure ML-KEM uses the shared secret
// directly and does not call this helper.
func hkdfWrapKey(sharedSecret, salt, info []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = defaultTDFSalt()
	}
	hkdfObj := hkdf.New(sha256.New, sharedSecret, salt, info)
	derivedKey := make([]byte, kemWrapKeySize)
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}
	return derivedKey, nil
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
	if len(privateKey) != k.privSize() {
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
