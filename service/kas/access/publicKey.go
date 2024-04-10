package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
)

func (p *Provider) LegacyPublicKey(ctx context.Context, in *kaspb.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	algorithm := in.GetAlgorithm()
	var pem string
	var err error
	if p.CryptoProvider == nil {
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	if algorithm == algorithmEc256 {
		pem, err = p.CryptoProvider.ECPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	} else {
		pem, err = p.CryptoProvider.RSAPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	}
	if err != nil {
		slog.ErrorContext(ctx, "unable to generate PEM", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	return &wrapperspb.StringValue{Value: pem}, nil
}

func (p *Provider) PublicKey(ctx context.Context, in *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	algorithm := in.GetAlgorithm()
	if algorithm == algorithmEc256 {
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}

		return &kaspb.PublicKeyResponse{PublicKey: ecPublicKeyPem}, nil
	}

	if in.GetFmt() == "jwk" {
		rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKeyAsJSON("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}

		return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
	}

	if in.GetFmt() == "pkcs8" {
		rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey("unknown")
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
	}

	rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey("unknown")
	if err != nil {
		slog.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}

	return &kaspb.PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
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
