package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"connectrpc.com/connect"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/trust"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
)

func (p *Provider) lookupKid(ctx context.Context, algorithm string) (string, error) {
	if len(p.Keyring) == 0 {
		p.Logger.WarnContext(ctx, "no default keys found", "algorithm", algorithm)
		return "", connect.NewError(connect.CodeNotFound, errors.Join(ErrConfig, errors.New("no default keys configured")))
	}

	for _, k := range p.Keyring {
		if k.Algorithm == algorithm && !k.Legacy {
			return k.KID, nil
		}
	}
	p.Logger.WarnContext(ctx, "no (non-legacy) key for requested algorithm", "algorithm", algorithm)
	return "", connect.NewError(connect.CodeNotFound, errors.Join(ErrConfig, errors.New("no default key for algorithm")))
}

func (p *Provider) LegacyPublicKey(ctx context.Context, req *connect.Request[kaspb.LegacyPublicKeyRequest]) (*connect.Response[wrapperspb.StringValue], error) {
	algorithm := req.Msg.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	var pem string
	var err error

	// Get the security provider
	idx := p.GetKeyIndex()
	if idx == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Join(ErrConfig, errors.New("configuration error")))
	}

	// Find the key ID
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	// Convert string KID to KeyIdentifier type
	keyID := trust.KeyIdentifier(kid)

	// Find the key by ID
	keyDetails, err := idx.FindKeyByID(ctx, keyID)
	if err != nil {
		p.Logger.ErrorContext(ctx, "SecurityProvider.FindKeyByID failed", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.Join(ErrConfig, errors.New("configuration error")))
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		// For EC keys, return the certificate
		pem, err = keyDetails.ExportCertificate(ctx)
		if err != nil {
			p.Logger.ErrorContext(ctx, "keyDetails.ExportCertificate failed", "err", err)
			return nil, connect.NewError(connect.CodeInternal, errors.Join(ErrConfig, errors.New("configuration error")))
		}
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		// For RSA keys, return the public key in PKCS8 format
		pem, err = keyDetails.ExportPublicKey(ctx, trust.KeyTypePKCS8)
		if err != nil {
			p.Logger.ErrorContext(ctx, "keyDetails.ExportPublicKey failed", "err", err)
			return nil, connect.NewError(connect.CodeInternal, errors.Join(ErrConfig, errors.New("configuration error")))
		}
	default:
		return nil, connect.NewError(connect.CodeNotFound, errors.Join(ErrConfig, errors.New("invalid algorithm")))
	}

	return connect.NewResponse(&wrapperspb.StringValue{Value: pem}), nil
}

func (p *Provider) PublicKey(ctx context.Context, req *connect.Request[kaspb.PublicKeyRequest]) (*connect.Response[kaspb.PublicKeyResponse], error) {
	ctx, span := p.Start(ctx, "PublicKey")
	defer span.End()

	algorithm := req.Msg.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	fmt := req.Msg.GetFmt()

	// Find the key ID
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	// Get the security provider
	idx := p.GetKeyIndex()
	if idx == nil {
		p.Logger.ErrorContext(ctx, "no security provider available")
		return nil, connect.NewError(connect.CodeInternal, ErrInternal)
	}

	// Convert string KID to KeyIdentifier type
	keyID := trust.KeyIdentifier(kid)

	r := func(value, kid string, err error) (*connect.Response[kaspb.PublicKeyResponse], error) {
		if errors.Is(err, security.ErrCertNotFound) {
			p.Logger.ErrorContext(ctx, "no key found for", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, connect.NewError(connect.CodeNotFound, security.ErrCertNotFound)
		} else if err != nil {
			p.Logger.ErrorContext(ctx, "configuration error for key lookup", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, connect.NewError(connect.CodeInternal, ErrInternal)
		}
		if req.Msg.GetV() == "1" {
			p.Logger.WarnContext(ctx, "hiding kid in public key response for legacy client", "kid", kid, "v", req.Msg.GetV())
			return connect.NewResponse(&kaspb.PublicKeyResponse{PublicKey: value}), nil
		}
		return connect.NewResponse(&kaspb.PublicKeyResponse{PublicKey: value, Kid: kid}), nil
	}

	// Find the key by ID
	keyDetails, err := idx.FindKeyByID(ctx, keyID)
	if err != nil {
		return r("", kid, err)
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		// For EC keys, export the public key
		ecPublicKeyPem, err := keyDetails.ExportPublicKey(ctx, trust.KeyTypePKCS8)
		return r(ecPublicKeyPem, kid, err)
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		switch fmt {
		case "jwk":
			// For JWK format, export the public key as JWK
			rsaPublicKeyPem, err := keyDetails.ExportPublicKey(ctx, trust.KeyTypeJWK)
			return r(rsaPublicKeyPem, kid, err)
		case "pkcs8":
			fallthrough
		case "":
			// For PKCS8 format, export the public key as PKCS8
			rsaPublicKeyPem, err := keyDetails.ExportPublicKey(ctx, trust.KeyTypePKCS8)
			return r(rsaPublicKeyPem, kid, err)
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid algorithm or format"))
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
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

func exportEcPublicKeyAsPemStr(pubkey *ecdsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
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

func exportCertificateAsPemStr(cert *x509.Certificate) (string, error) {
	certBytes := cert.Raw
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   certBytes,
		},
	)
	if certPem == nil {
		return "", ErrCertificateEncode
	}
	return string(certPem) + "\n", nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
