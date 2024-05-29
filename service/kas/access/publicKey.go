package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
	algorithmEc384       = "ec:secp384r1"
	algorithmEc512       = "ec:secp521r1"
)

func (p Provider) lookupKid(ctx context.Context, algorithm string) (string, error) {
	if len(p.KASConfig.Keyring) == 0 {
		slog.WarnContext(ctx, "no default keys found", "algorithm", algorithm)
		return "", errors.Join(ErrConfig, status.Error(codes.NotFound, "no default keys configured"))
	}

	for _, k := range p.KASConfig.Keyring {
		if k.Algorithm == algorithm && !k.Legacy {
			return k.KID, nil
		}
	}
	slog.WarnContext(ctx, "no (non-legacy) key for requested algorithm", "algorithm", algorithm)
	return "", errors.Join(ErrConfig, status.Error(codes.NotFound, "no default key for algorithm"))
}

func (p Provider) LegacyPublicKey(ctx context.Context, in *kaspb.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	algorithm := in.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	var pem string
	var err error
	if p.CryptoProvider == nil {
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		pem, err = p.CryptoProvider.ECCertificate(kid)
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		pem, err = p.CryptoProvider.RSAPublicKey(kid)
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	default:
		return nil, errors.Join(ErrConfig, status.Error(codes.NotFound, "invalid algorithm"))
	}
	return &wrapperspb.StringValue{Value: pem}, nil
}

func (p Provider) PublicKey(ctx context.Context, in *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	algorithm := in.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	if algorithm == algorithmEc256 || algorithm == algorithmEc384 || algorithm == algorithmEc512 {
		var ecKeyID string
		as := strings.Split(algorithm, ":")
		if len(as) > 1 {
			ecKeyID = as[1]
		}
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey(ecKeyID)
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		return &kaspb.PublicKeyResponse{PublicKey: ecPublicKeyPem}, nil
	}
	fmt := in.GetFmt()
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	r := func(value, kid string, err error) (*kaspb.PublicKeyResponse, error) {
		if errors.Is(err, security.ErrCertNotFound) {
			slog.ErrorContext(ctx, "no key found for", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(err, status.Error(codes.NotFound, "no such key"))
		} else if err != nil {
			slog.ErrorContext(ctx, "configuration error for key lookup", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		if in.GetV() == "1" {
			slog.WarnContext(ctx, "hiding kid in public key response for legacy client", "kid", kid, "v", in.GetV())
			return &kaspb.PublicKeyResponse{PublicKey: value}, nil
		}
		return &kaspb.PublicKeyResponse{PublicKey: value, Kid: kid}, nil
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey(kid)
		return r(ecPublicKeyPem, kid, err)
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		switch fmt {
		case "jwk":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKeyAsJSON(kid)
			return r(rsaPublicKeyPem, kid, err)
		case "pkcs8":
			fallthrough
		case "":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey(kid)
			return r(rsaPublicKeyPem, kid, err)
		}
	}
	return nil, status.Error(codes.NotFound, "invalid algorithm or format")
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
