//go:build opentdf.hsm

package security

import (
	"crypto"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
)

// Skips if not in CI and failure due to library missing
func maybeSkip(t *testing.T, err error) {
	if os.Getenv("CI") != "" {
		return
	}
	if errors.Is(err, ErrHSMNotFound) {
		t.Skip(`WARNING Unable to load PKCS11 library

		Please install a PKCS 11 library, such as

			brew install softhsm


		`)
	}
}

func hsmInitSlot() {
	o, e, err := sh("softhsm2-util", "--show-slots")
	if err != nil {
		slog.Warn("softhsm --show-slots error", "err", err, "stdout", o, "stderr", e)
		return
	}
	if strings.Contains(o, "dev-token") {
		slog.Info("softhsm already initialized", "stdout", o, "stderr", e)
		return
	}
	o, e, err = sh("softhsm2-util", "--init-token", "--free", "--label=dev-token", "--pin=12345", "--so-pin=12345")
	if err != nil {
		slog.Warn("softhsm --init-token error", "err", err, "stdout", o, "stderr", e)
	}
	slog.Info("softhsm --init-token success", "stdout", o, "stderr", e)
}

func TestNewWithoutPIN(t *testing.T) {
	var c HSMConfig
	s, err := NewHSM(c.WithLabel("dev-token"))
	maybeSkip(t, err)
	var perr pkcs11.Error
	if errors.As(err, &perr) {
		assert.Equal(t, pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD), perr)
	} else {
		assert.Nil(t, s)
		assert.Failf(t, "wrong error", "%w", err)
	}
}

func TestNewWithIncorrectPIN(t *testing.T) {
	var c HSMConfig
	s, err := NewHSM(c.WithLabel("dev-token").WithPIN("1234567"))
	maybeSkip(t, err)
	var perr pkcs11.Error
	if errors.As(err, &perr) {
		assert.Equal(t, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), perr)
	} else {
		assert.Nil(t, s)
		assert.Failf(t, "wrong error", "%w", err)
	}
}

func TestOAEPForHash(t *testing.T) {
	testCases := []struct {
		inputHash     crypto.Hash
		expectedHash  uint
		expectedMGF   uint
		expectedError error
	}{
		{crypto.SHA1, pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil},
		{crypto.SHA224, pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil},
		{crypto.SHA256, pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil},
		{crypto.SHA384, pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil},
		{crypto.SHA512, pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil},
		{crypto.SHA3_256, 0, 0, ErrHSMUnexpected},
	}

	for _, tc := range testCases {
		p, err := oaepForHash(tc.inputHash, "test")
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
			continue
		}
		assert.Equal(t, tc.expectedHash, p.HashAlg)
		assert.Equal(t, tc.expectedMGF, p.MGF)
	}
}

func TestDecryptOAEPUnsupportedRSAFailure(t *testing.T) {
	sessionHandle := pkcs11.SessionHandle(1)
	session := &HSMSession{
		ctx: pkcs11.Ctx{},
		sh:  sessionHandle,
	}

	decrypted, err := session.RSADecrypt(crypto.BLAKE2b_384, "unknown", "sample label", []byte("sample ciphertext"))

	t.Log(err)
	t.Log(decrypted)

	if err == nil {
		t.Errorf("Expected error, but got: %v", err)
	}
}

func TestError(t *testing.T) {
	expectedResult := "hsm decrypt error"
	output := Error.Error(ErrHSMDecrypt)

	if reflect.TypeOf(output).String() != "string" {
		t.Error("Expected string")
	}

	if output != expectedResult {
		t.Errorf("Output %v not equal to expected %v", output, expectedResult)
	}
}

func TestMain(m *testing.M) {
	hsmInitSlot()
	os.Exit(m.Run())
}
