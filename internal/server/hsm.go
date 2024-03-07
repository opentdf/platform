package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/miekg/pkcs11"
)

const (
	ErrHSMUnexpected = Error("hsm unexpected")
	ErrHSMNotFound   = Error("hsm unavailable")
)

type hsmSession struct {
	ctx pkcs11.Ctx
	sh  pkcs11.SessionHandle
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

func findHSMLibrary() string {
	for _, l := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/lib/softhsm/libsofthsm2.so",
	} {
		i, err := os.Stat(l)
		slog.Info("stat", "path", l, "info", i, "err", err)
		if os.IsNotExist(err) {
			continue
		}
		return l
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
	}
	return ""
}

func newHSMContext(pkcs11ModulePath string) (*pkcs11.Ctx, error) {
	slog.Debug("loading pkcs11 module", "pkcs11ModulePath", pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("unable to load pkcs11 so [%s] %w", pkcs11ModulePath, ErrHSMUnexpected)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	return ctx, nil
}

func destroyHSMContext(ctx *pkcs11.Ctx) {
	defer ctx.Destroy()
	err := ctx.Finalize()
	if err != nil {
		slog.Error("pkcs11 error finalizing module", "err", err)
	}
}

func newHSMSession(hctx *pkcs11.Ctx, slot uint) (*hsmSession, error) {
	slog.Info("pkcs11 OpenSession", "slot", slot)
	session, err := hctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		slots, err := hctx.GetSlotList(true)
		if err != nil {
			slog.Error("pkcs11 error getting slots", "slot", slot, "err", err)
			return nil, errors.Join(ErrHSMUnexpected, err)
		}
		slog.Error("pkcs11 error opening session for slot", "slot", slot, "slots", slots)
		return nil, errors.Join(ErrHSMUnexpected, err)
	}
	return &hsmSession{*hctx, session}, nil
}

func destroyHSMSession(hs *hsmSession) {
	err := hs.ctx.CloseSession(hs.sh)
	if err != nil {
		slog.Error("pkcs11 error closing session", "err", err)
	}
}

type cfg struct {
	hasSlot bool
	slot    uint
	label   string
	pin     string
}

func WithPIN(pin string) func(*cfg) {
	return func(c *cfg) {
		c.pin = pin
	}
}

func WithSlot(slot uint) func(*cfg) {
	return func(c *cfg) {
		c.hasSlot = true
		c.slot = slot
	}
}

func WithLabel(label string) func(*cfg) {
	return func(c *cfg) {
		c.label = label
	}
}

func (s *OpenTDFServer) StartHSM(opts ...func(*cfg)) error {
	c := &cfg{}
	for _, opt := range opts {
		opt(c)
	}

	pkcs11Lib := findHSMLibrary()
	if pkcs11Lib == "" {
		slog.Error("pkcs11 error softhsm not available")
		return ErrHSMNotFound
	}
	hctx, err := newHSMContext(pkcs11Lib)
	if err != nil {
		slog.Error("pkcs11 error initializing hsm", "err", err)
		return errors.Join(ErrHSMUnexpected, err)
	}
	fine := false
	defer func() {
		// Destroy HSM context if we don't succeed in starting our session
		if !fine {
			destroyHSMContext(hctx)
		}
	}()
	info, err := hctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		return errors.Join(err, ErrHSMUnexpected)
	}
	slog.Info("pkcs11 module", "pkcs11info", info)

	var hs *hsmSession
	if c.hasSlot {
		slog.Info("pkcs11 loading WithSlot", "slot", c.slot)
		hs, err = newHSMSession(hctx, c.slot)
		if err != nil {
			slog.Error("pkcs11 error initializing session", "err", err)
			return errors.Join(ErrHSMUnexpected, err)
		}
	} else {
		slog.Info("pkcs11 loading WithLabel", "label", c.label)
		slots, err := hctx.GetSlotList(true)
		if err != nil {
			slog.Error("pkcs11 error getting slots for search", "err", err)
			return errors.Join(ErrHSMUnexpected, err)
		}
		if c.label != "" {
			for _, slot := range slots {
				slotInfo, err := hctx.GetSlotInfo(slot)
				if err != nil {
					slog.Warn("pkcs11 unable to show slot info", "err", err, "slot", slot)
					continue
				}
				slog.Info("pkcs11 slot info", "slot", slot, "info", slotInfo)
				tokenInfo, err := hctx.GetTokenInfo(slot)
				if err != nil {
					slog.Warn("pkcs11 unable to show slot's token info", "err", err, "slot", slot)
					continue
				}
				slog.Info("pkcs11 token info", "slot", slot, "info", tokenInfo)
				if tokenInfo.Label == c.label {
					hs, err = newHSMSession(hctx, slot)
					if err != nil {
						slog.Warn("pkcs11 unable to initialize session with slot", "err", err, "slot", slot)
						continue
					}
					break
				}
			}
			if hs == nil {
				slog.Error("pkcs11 error no slot found with label", "label", c.label)
				return ErrHSMUnexpected
			}
		} else {
			slog.Info("no hsm slot or label found")
			return ErrHSMUnexpected
		}
	}
	defer func() {
		if !fine {
			destroyHSMSession(hs)
		}
	}()

	err = hctx.Login(hs.sh, pkcs11.CKU_USER, c.pin)
	if err != nil {
		slog.Error("pkcs11 error logging in as CKU USER", "err", err)
		return errors.Join(ErrHSMUnexpected, err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		err := ctx.Logout(sh)
		if err != nil {
			slog.Error("pkcs11 error logging out", "err", err)
		}
	}(hctx, hs.sh)

	info, err = hctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		return errors.Join(ErrHSMUnexpected, err)
	}
	slog.Info("pkcs11 module info after initialization", "pkcs11info", info)

	s.hsmSession = hs
	fine = true

	return nil
}

func (s *OpenTDFServer) StopHSM() {
	if s.hsmSession == nil {
		return
	}
	ctx := s.hsmSession.ctx
	sh := s.hsmSession.sh
	if err := ctx.Logout(sh); err != nil {
		slog.Error("pkcs11 error logging out", "err", err)
	}
	destroyHSMSession(s.hsmSession)
	destroyHSMContext(&s.hsmSession.ctx)
	s.hsmSession = nil
}
