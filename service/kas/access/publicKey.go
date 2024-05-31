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
	"github.com/opentdf/platform/service/internal/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
	algorithmRSA2048     = "rsa:2048"
)

func (p Provider) lookupKid(ctx context.Context, algorithm string) (string, error) {
	key := "unknown"
	defaultKid := "unknown"
	if algorithm == algorithmEc256 {
		defaultKid = "123"
		key = "eccertid"
	}

	if p.Config == nil || p.Config.ExtraProps == nil {
		slog.WarnContext(ctx, "using default kid", "kid", defaultKid, "algorithm", algorithm, "certid", key)
		return defaultKid, nil
	}

	certid, ok := p.Config.ExtraProps[key]
	if !ok {
		slog.WarnContext(ctx, "using default kid", "kid", defaultKid, "algorithm", algorithm, "certid", key)
		return defaultKid, nil
	}

	kid, ok := certid.(string)
	if !ok {
		slog.ErrorContext(ctx, "invalid key configuration", "kid", defaultKid, "algorithm", algorithm, "certid", key)
		return "", ErrConfig
	}
	return kid, nil
}

func (p Provider) LegacyPublicKey(ctx context.Context, in *kaspb.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	algorithm := in.GetAlgorithm()
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
	case algorithmEc256:
		pem, err = p.CryptoProvider.ECCertificate(kid)
		if err != nil {
			slog.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	case algorithmRSA2048:
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
	fmt := in.GetFmt()
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	r := func(k string, err error) (*kaspb.PublicKeyResponse, error) {
		if errors.Is(err, security.ErrCertNotFound) {
			slog.ErrorContext(ctx, "no key found for", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(err, status.Error(codes.NotFound, "no such key"))
		} else if err != nil {
			slog.ErrorContext(ctx, "configuration error for key lookup", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		return &kaspb.PublicKeyResponse{PublicKey: k}, nil
	}

	switch algorithm {
	case algorithmEc256:
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey(kid)
		return r(ecPublicKeyPem, err)
	case algorithmRSA2048:
		fallthrough
	case "":
		switch fmt {
		case "jwk":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKeyAsJSON(kid)
			return r(rsaPublicKeyPem, err)
		case "pkcs8":
			fallthrough
		case "":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey(kid)
			return r(rsaPublicKeyPem, err)
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
