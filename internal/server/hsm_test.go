package server

import (
	"errors"
	"log/slog"
	"os"
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

func TestStartHSM_NoPIN(t *testing.T) {
	var s OpenTDFServer
	err := s.StartHSM(WithLabel("dev-token"))
	maybeSkip(t, err)
	var perr pkcs11.Error
	if errors.As(err, &perr) {
		assert.Equal(t, pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD), perr)
	} else {
		assert.Nil(t, s.hsmSession)
		assert.Failf(t, "wrong error", "%w", err)
	}
}

func TestStartHSM_IncorrectPIN(t *testing.T) {
	var s OpenTDFServer
	err := s.StartHSM(WithLabel("dev-token"), WithPIN("1234567"))
	maybeSkip(t, err)
	var perr pkcs11.Error
	if errors.As(err, &perr) {
		assert.Equal(t, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT), perr)
	} else {
		assert.Nil(t, s.hsmSession)
		assert.Failf(t, "wrong error", "%w", err)
	}
}

func TestMain(m *testing.M) {
	hsmInitSlot()
	os.Exit(m.Run())
}
