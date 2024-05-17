package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/hkdf"
)

const (
	ErrCertNotFound        = Error("not found")
	ErrCertificateEncode   = Error("certificate encode error")
	ErrPublicKeyMarshal    = Error("public key marshal error")
	ErrHSMUnexpected       = Error("hsm unexpected")
	ErrHSMDecrypt          = Error("hsm decrypt error")
	ErrHSMNotFound         = Error("hsm unavailable")
	ErrKeyConfig           = Error("key configuration error")
	ErrUnknownHashFunction = Error("unknown hash function")
)
const keyLength = 32

type Error string

func (e Error) Error() string {
	return string(e)
}

// A session with a security module; useful for abstracting basic cryptographic
// operations.
//
// HSM Session HAS-A PKCS11 Context
// HSM Session HAS-A login for a given USER TYPE to a single SLOT
// When you start this application, you assign a slot and user to the associated
// security module.
type HSMSession struct {
	ctx pkcs11.Ctx
	sh  pkcs11.SessionHandle
	RSA *RSAKeyPair
	EC  *ECKeyPair
}

type HSMConfig struct {
	ModulePath string             `yaml:"modulePath,omitempty"`
	PIN        string             `yaml:"pin,omitempty"`
	SlotID     uint               `yaml:"slotId,omitempty"`
	SlotLabel  string             `yaml:"slotLabel,omitempty"`
	Keys       map[string]KeyInfo `yaml:"keys,omitempty"`
}

type KeyInfo struct {
	Name  string `yaml:"name,omitempty"`
	Label string `yaml:"label,omitempty"`
}

type PrivateKeyRSA pkcs11.ObjectHandle

type PrivateKeyEC pkcs11.ObjectHandle

type ECKeyPair struct {
	PrivateKey PrivateKeyEC
	*ecdsa.PublicKey
	*x509.Certificate
}

type RSAKeyPair struct {
	PrivateKey PrivateKeyRSA
	*rsa.PublicKey
	*x509.Certificate
}

func sh(c string, arg ...string) (string, string, error) {
	cmd := exec.Command(c, arg...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	err = cmd.Start()
	if err != nil {
		return "", "", err
	}
	b, err := io.ReadAll(stdout)
	if err != nil {
		return "", "", err
	}
	o := strings.TrimSpace(string(b))

	b, err = io.ReadAll(stderr)
	if err != nil {
		return "", "", err
	}
	e := strings.TrimSpace(string(b))

	err = cmd.Wait()
	return o, e, err
}

func findHSMLibrary(paths ...string) string {
	for _, l := range paths {
		if l == "" {
			continue
		}
		i, err := os.Stat(l)
		slog.Info("stat", "path", l, "info", i, "err", err)
		if os.IsNotExist(err) {
			continue
		} else if err == nil {
			return l
		}
	}
	o, e, err := sh("brew", "--prefix")
	if err != nil {
		slog.Error("pkcs11 error finding module", "err", err, "stdout", o, "stderr", e)
		return ""
	}
	l := o + "/lib/softhsm/libsofthsm2.so"
	i, err := os.Stat(l)
	slog.Info("stat", "path", l, "info", i, "err", err)
	if os.IsNotExist(err) {
		slog.Warn("pkcs11 error: softhsm not installed by brew", "err", err)
		return ""
	} else if err == nil {
		return l
	}
	return ""
}

func newPKCS11Context(pkcs11ModulePath string) (*pkcs11.Ctx, error) {
	slog.Debug("loading pkcs11 module", "pkcs11ModulePath", pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("unable to load pkcs11 so [%s] %w", pkcs11ModulePath, ErrHSMUnexpected)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	return ctx, nil
}

func destroyPKCS11Context(ctx *pkcs11.Ctx) {
	defer ctx.Destroy()
	err := ctx.Finalize()
	if err != nil {
		slog.Error("pkcs11 error finalizing module", "err", err)
	}
}

func newHSMSession(hctx *pkcs11.Ctx, slot uint) (*HSMSession, error) {
	slog.Info("pkcs11 OpenSession", "slot", slot)
	session, err := hctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		slots, err := hctx.GetSlotList(true)
		if err != nil {
			slog.Error("pkcs11 error getting slots", "slot", slot, "err", err)
			return nil, errors.Join(ErrHSMUnexpected, err)
		}
		slog.Error("pkcs11 error opening session for slot", "slot", slot, "slots", slots)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	return &HSMSession{ctx: *hctx, sh: session}, nil
}

func (h *HSMSession) destroy() {
	defer func(ctx pkcs11.Ctx) {
		destroyPKCS11Context(&ctx)
	}(h.ctx)
	err := h.ctx.CloseSession(h.sh)
	if err != nil {
		slog.Error("pkcs11 error closing session", "err", err)
	}
}

func (c *HSMConfig) WithPIN(pin string) *HSMConfig {
	c.PIN = pin
	return c
}

func (c *HSMConfig) WithSlot(slot uint) *HSMConfig {
	c.SlotID = slot
	return c
}

func (c *HSMConfig) WithLabel(label string) *HSMConfig {
	c.SlotLabel = label
	return c
}

func lookupSlotWithLabel(ctx *pkcs11.Ctx, label string) (uint, error) {
	slog.Info("lookupSlotWithLabel", "label", label)
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		slog.Error("pkcs11 error getting slots for search", "err", err)
		return 0, errors.Join(ErrHSMUnexpected, err)
	}
	for _, slot := range slots {
		slotInfo, err := ctx.GetSlotInfo(slot)
		if err != nil {
			slog.Warn("pkcs11 unable to show slot info", "err", err, "slot", slot)
			continue
		}
		slog.Info("pkcs11 slot info", "slot", slot, "info", slotInfo)
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			slog.Warn("pkcs11 unable to show slot's token info", "err", err, "slot", slot)
			continue
		}
		slog.Info("pkcs11 token info", "slot", slot, "info", tokenInfo)
		if tokenInfo.Label == label {
			return slot, nil
		}
	}
	slog.Error("pkcs11 error no slot found with label", "label", label)
	return 0, ErrHSMUnexpected
}

func New(c *HSMConfig) (*HSMSession, error) {
	pkcs11Lib := findHSMLibrary(
		c.ModulePath,
		"/usr/lib/softhsm/libsofthsm2.so",
		"/lib/softhsm/libsofthsm2.so",
	)
	if pkcs11Lib == "" {
		slog.Error("pkcs11 error softhsm not available")
		return nil, ErrHSMNotFound
	}
	hctx, err := newPKCS11Context(pkcs11Lib)
	if err != nil {
		slog.Error("pkcs11 error initializing hsm", "err", err)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	info, err := hctx.GetInfo()
	if err != nil {
		destroyPKCS11Context(hctx)
		slog.Error("pkcs11 error querying module info", "err", err)
		return nil, errors.Join(err, ErrHSMUnexpected)
	}
	slog.Info("pkcs11 module", "pkcs11info", info, "cfg", c)

	if c.SlotLabel != "" {
		slog.Info("pkcs11 loading WithLabel", "label", c.SlotLabel)
		slotID, err := lookupSlotWithLabel(hctx, c.SlotLabel)
		if err != nil {
			return nil, ErrHSMUnexpected
		}
		c.SlotID = slotID
	}
	slog.Info("pkcs11 loading WithSlot", "slot", c.SlotID)
	hs, err := newHSMSession(hctx, c.SlotID)
	if err != nil {
		slog.Error("pkcs11 error initializing session", "err", err)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	fine := false
	defer func() {
		if !fine {
			hs.destroy()
			hs = nil
		}
	}()

	err = hctx.Login(hs.sh, pkcs11.CKU_USER, c.PIN)
	if err != nil {
		slog.Error("pkcs11 error logging in as CKU USER", "err", err)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		if !fine {
			err := ctx.Logout(sh)
			if err != nil {
				slog.Error("pkcs11 error logging out", "err", err)
			}
		}
	}(hctx, hs.sh)

	info, err = hctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	slog.Info("pkcs11 module info after initialization", "pkcs11info", info)

	fine = true
	err = hs.loadKeys(c.Keys)
	return hs, err
}

func (h *HSMSession) loadKeys(keys map[string]KeyInfo) error {
	for name, info := range keys {
		if info.Name == "" {
			info.Name = name
		}
		switch info.Name {
		case "rsa":
			pair, err := h.LoadRSAKey(info)
			if err != nil {
				slog.Error("pkcs11 error unable to load RSA key", "err", err)
			} else {
				h.RSA = pair
			}
		case "ec":
			pair, err := h.LoadECKey(info)
			if err != nil {
				slog.Error("pkcs11 error unable to load EC key", "err", err)
			} else {
				h.EC = pair
			}
		default:
			return fmt.Errorf("unrecognized key type [%s], %w", info.Name, ErrKeyConfig)
		}
	}
	return nil
}

func (h *HSMSession) Close() {
	if h == nil {
		return
	}
	ctx := h.ctx
	sh := h.sh
	if err := ctx.Logout(sh); err != nil {
		slog.Error("pkcs11 error logging out", "err", err)
	}
	h.destroy()
}

func (h *HSMSession) findKey(class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)))

	// CloudHSM does not support CKO_PRIVATE_KEY set to false
	if class == pkcs11.CKO_PRIVATE_KEY {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true))
	}
	var handle pkcs11.ObjectHandle
	var err error
	if err = h.ctx.FindObjectsInit(h.sh, template); err != nil {
		return handle, errors.Join(ErrHSMUnexpected, err)
	}
	defer func() {
		finalErr := h.ctx.FindObjectsFinal(h.sh)
		if err != nil {
			err = finalErr
			slog.Error("pcks11 FindObjectsFinal failure", "err", err)
		}
	}()

	var handles []pkcs11.ObjectHandle
	const maxHandles = 20
	handles, _, err = h.ctx.FindObjects(h.sh, maxHandles)
	if err != nil {
		return handle, errors.Join(ErrHSMUnexpected, err)
	}

	switch len(handles) {
	case 0:
		err = fmt.Errorf("key not found")
	case 1:
		handle = handles[0]
	default:
		err = fmt.Errorf("multiple key found")
	}

	return handle, err
}

func (h *HSMSession) LoadRSAKey(info KeyInfo) (*RSAKeyPair, error) {
	var pair RSAKeyPair

	slog.Debug("Finding RSA key to wrap.")
	keyHandle, err := h.findKey(pkcs11.CKO_PRIVATE_KEY, info.Label)
	if err != nil {
		slog.Error("pkcs11 error finding key", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	pair.PrivateKey = PrivateKeyRSA(keyHandle)

	slog.Debug("Finding RSA certificate", "rsaLabel", info.Label)
	certHandle, err := h.findKey(pkcs11.CKO_CERTIFICATE, info.Label)
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	if err != nil {
		slog.Error("pkcs11 error finding RSA cert", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}
	attrs, err := h.ctx.GetAttributeValue(h.sh, certHandle, certTemplate)
	if err != nil {
		slog.Error("pkcs11 error getting attribute from cert", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	for _, a := range attrs {
		if a.Type == pkcs11.CKA_VALUE {
			certRSA, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				return nil, errors.Join(ErrKeyConfig, err)
			}
			pair.Certificate = certRSA
			break
		}
	}
	if pair.Certificate == nil {
		slog.Error("pkcs11 unable to find rsa cert", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	// RSA Public key
	rsaPublicKey, ok := pair.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		slog.Error("public key RSA cert error")
		return nil, ErrKeyConfig
	}
	pair.PublicKey = rsaPublicKey
	return &pair, nil
}

func (h *HSMSession) LoadECKey(info KeyInfo) (*ECKeyPair, error) {
	var pair ECKeyPair

	slog.Debug("Finding EC private key", "ecLabel", info.Label)
	keyHandleEC, err := h.findKey(pkcs11.CKO_PRIVATE_KEY, info.Label)
	if err != nil {
		slog.Error("pkcs11 error finding ec key", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	pair.PrivateKey = PrivateKeyEC(keyHandleEC)

	// EC Cert
	certECHandle, err := h.findKey(pkcs11.CKO_CERTIFICATE, info.Label)
	if err != nil {
		slog.Error("public key EC cert error")
		return nil, errors.Join(ErrKeyConfig, err)
	}
	certECTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	ecCertAttrs, err := h.ctx.GetAttributeValue(h.sh, certECHandle, certECTemplate)
	if err != nil {
		slog.Error("public key EC cert error", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	for _, a := range ecCertAttrs {
		if a.Type == pkcs11.CKA_VALUE {
			// exponent := big.NewInt(0)
			// exponent.SetBytes(a.Value)
			certEC, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				panic(err)
			}
			pair.Certificate = certEC
		}
	}
	if pair.Certificate == nil {
		slog.Error("pkcs11 unable to find ec cert", "err", err)
		return nil, errors.Join(ErrKeyConfig, err)
	}

	ecPublicKey, ok := pair.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		slog.Error("public key from cert fail for EC")
		return nil, ErrKeyConfig
	}

	pair.PublicKey = ecPublicKey
	return &pair, nil
}

func oaepForHash(hashFunction crypto.Hash, keyLabel string) (*pkcs11.OAEPParams, error) {
	var hashAlg, mgfAlg uint

	switch hashFunction { //nolint:exhaustive // We only handle SHA family in this switch
	case crypto.SHA1:
		hashAlg = pkcs11.CKM_SHA_1
		mgfAlg = pkcs11.CKG_MGF1_SHA1
	case crypto.SHA224:
		hashAlg = pkcs11.CKM_SHA224
		mgfAlg = pkcs11.CKG_MGF1_SHA224
	case crypto.SHA256:
		hashAlg = pkcs11.CKM_SHA256
		mgfAlg = pkcs11.CKG_MGF1_SHA256
	case crypto.SHA384:
		hashAlg = pkcs11.CKM_SHA384
		mgfAlg = pkcs11.CKG_MGF1_SHA384
	case crypto.SHA512:
		hashAlg = pkcs11.CKM_SHA512
		mgfAlg = pkcs11.CKG_MGF1_SHA512
	default:
		return nil, ErrHSMUnexpected
	}
	return pkcs11.NewOAEPParams(hashAlg, mgfAlg, pkcs11.CKZ_DATA_SPECIFIED,
		[]byte(keyLabel)), nil
}

func (h *HSMSession) GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte) ([]byte, error) {
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

	handle, err := h.ctx.DeriveKey(h.sh, mech, pkcs11.ObjectHandle(h.EC.PrivateKey), template)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attr, err := h.ctx.GetAttributeValue(h.sh, handle, template)
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

func (h *HSMSession) GenerateNanoTDFSessionKey(
	privateKeyHandle PrivateKeyEC,
	ephemeralPublicKey []byte,
) ([]byte, error) {
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

	handle, err := h.ctx.DeriveKey(h.sh, mech, pkcs11.ObjectHandle(privateKeyHandle), template)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attr, err := h.ctx.GetAttributeValue(h.sh, handle, template)
	if err != nil {
		return nil, err
	}

	sessionKey := attr[0].Value
	salt := versionSalt()
	hkdf := hkdf.New(sha256.New, sessionKey, salt, nil)

	derivedKey := make([]byte, keyLength)
	_, err = io.ReadFull(hkdf, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	return derivedKey, nil
}

func (h *HSMSession) GenerateEphemeralKasKeys() (PrivateKeyEC, []byte, error) {
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

	pubHandle, prvHandle, err := h.ctx.GenerateKeyPair(h.sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubKeyTemplate, prvKeyTemplate)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	pubBytes, err := h.ctx.GetAttributeValue(h.sh, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to retrieve public key bytes: %w", err)
	}
	publicKeyBytes := pubBytes[0].Value

	return PrivateKeyEC(prvHandle), publicKeyBytes, nil
}

func (h *HSMSession) RSAPublicKey(keyID string) (string, error) {
	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	if h.RSA == nil {
		return "", ErrCertNotFound
	}

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(h.RSA.PublicKey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)
	if certPem == nil {
		return "", ErrCertificateEncode
	}
	return string(certPem), nil
}

func (h *HSMSession) RSAPublicKeyAsJSON(keyID string) (string, error) {
	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	if h.RSA == nil || h.RSA.PublicKey == nil {
		return "", ErrCertNotFound
	}
	rsaPublicKeyJwk, err := jwk.FromRaw(h.RSA.PublicKey)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	return string(jsonPublicKey), nil
}

func (h *HSMSession) ECPublicKey(string) (string, error) {
	if h.EC == nil || h.EC.PublicKey == nil {
		return "", ErrCertNotFound
	}
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(h.EC.PublicKey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func (h *HSMSession) RSADecrypt(hash crypto.Hash, keyID string, keyLabel string, ciphertext []byte) ([]byte, error) {
	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	oaepParams, err := oaepForHash(hash, keyLabel)
	if err != nil {
		return nil, errors.Join(ErrHSMDecrypt, err)
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams)

	err = h.ctx.DecryptInit(h.sh, []*pkcs11.Mechanism{mech}, pkcs11.ObjectHandle(h.RSA.PrivateKey))
	if err != nil {
		return nil, errors.Join(ErrHSMDecrypt, err)
	}
	decrypt, err := h.ctx.Decrypt(h.sh, ciphertext)
	if err != nil {
		return nil, errors.Join(ErrHSMDecrypt, err)
	}
	return decrypt, nil
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	return digest.Sum(nil)
}
