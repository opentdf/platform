package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
)

func (p *Provider) LegacyPublicKey(ctx context.Context, in *LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	algorithm := in.Algorithm
	var pem string
	var err error
	if algorithm == algorithmEc256 {
		pem, err = exportCertificateAsPemStr(&p.CertificateEC)
		slog.DebugContext(ctx, "Legacy EC Public Key Handler found", "cert", pem)
	} else {
		pem, err = exportCertificateAsPemStr(&p.Certificate)
		slog.DebugContext(ctx, "Legacy RSA CERT Handler found", "cert", pem)
	}
	if err != nil {
		slog.ErrorContext(ctx, "unable to generate PEM", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	return &wrapperspb.StringValue{Value: pem}, nil
}

func (p *Provider) PublicKey(ctx context.Context, in *PublicKeyRequest) (*PublicKeyResponse, error) {
	algorithm := in.Algorithm
	if algorithm == algorithmEc256 {
		ecPublicKeyPem, err := exportEcPublicKeyAsPemStr(&p.PublicKeyEC)
		if err != nil {
			slog.ErrorContext(ctx, "EC public key from PKCS11", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		slog.DebugContext(ctx, "EC Public Key Handler found", "cert", ecPublicKeyPem)
		return &PublicKeyResponse{PublicKey: ecPublicKeyPem}, nil
	}

	if in.Fmt == "jwk" {
		rsaPublicKeyJwk, err := jwk.FromRaw(&p.PublicKeyRSA)
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse JWK", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		// Keys can be serialized back to JSON
		jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
		if err != nil {
			slog.ErrorContext(ctx, "failed to marshal JWK", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		slog.DebugContext(ctx, "JWK Public Key Handler found", "cert", jsonPublicKey)
		return &PublicKeyResponse{PublicKey: string(jsonPublicKey)}, nil
	}

	if in.Fmt == "pkcs8" {
		certificatePem, err := exportCertificateAsPemStr(&p.Certificate)
		if err != nil {
			slog.ErrorContext(ctx, "RSA public key from PKCS11", "err", err)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		slog.DebugContext(ctx, "RSA Cert Handler found", "cert", certificatePem)
		return &PublicKeyResponse{PublicKey: certificatePem}, nil
	}

	rsaPublicKeyPem, err := exportRsaPublicKeyAsPemStr(&p.PublicKeyRSA)
	if err != nil {
		slog.ErrorContext(ctx, "RSA public key export fail", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	slog.DebugContext(ctx, "RSA Public Key Handler found", "cert", rsaPublicKeyPem)
	return &PublicKeyResponse{PublicKey: rsaPublicKeyPem}, nil
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
