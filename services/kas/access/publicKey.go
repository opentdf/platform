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
	algorithm := in.Algorithm
	var pem string
	var err error
	if algorithm == algorithmEc256 {
		// if p.Session.EC == nil || p.Session.EC.Certificate == nil {
		// 	return nil, err404("not found")
		// }
		// pem, err = exportCertificateAsPemStr(p.Session.EC.Certificate)
		slog.DebugContext(ctx, "Legacy EC Public Key Handler found", "cert", pem)
	} else {
		pem := p.KeyProvider.PublicKey()
		slog.DebugContext(ctx, "Legacy RSA CERT Handler found", "cert", pem)
	}
	if err != nil {
		slog.ErrorContext(ctx, "unable to generate PEM", "err", err)
		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	return &wrapperspb.StringValue{Value: string(pem)}, nil
}

func (p *Provider) PublicKey(ctx context.Context, in *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	// algorithm := in.Algorithm
	// if algorithm == algorithmEc256 {
	// 	if p.Session.EC == nil {
	// 		return nil, err404("not found")
	// 	}
	// 	ecPublicKeyPem, err := exportEcPublicKeyAsPemStr(p.Session.EC.PublicKey)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "EC public key from PKCS11", "err", err)
	// 		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	// 	}
	// 	slog.DebugContext(ctx, "EC Public Key Handler found", "cert", ecPublicKeyPem)
	// 	return &kaspb.PublicKeyResponse{PublicKey: ecPublicKeyPem}, nil
	// }

	// if in.Fmt == "jwk" {
	// 	rsaPublicKeyJwk, err := jwk.FromRaw(p.Session.RSA.PublicKey)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "failed to parse JWK", "err", err)
	// 		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	// 	}
	// 	// Keys can be serialized back to JSON
	// 	jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "failed to marshal JWK", "err", err)
	// 		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	// 	}
	// 	slog.DebugContext(ctx, "JWK Public Key Handler found", "cert", jsonPublicKey)
	// 	return &kaspb.PublicKeyResponse{PublicKey: string(jsonPublicKey)}, nil
	// }

	// if in.Fmt == "pkcs8" {
	// 	certificatePem, err := exportCertificateAsPemStr(p.Session.RSA.Certificate)
	// 	if err != nil {
	// 		slog.ErrorContext(ctx, "RSA public key from PKCS11", "err", err)
	// 		return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	// 	}
	// 	slog.DebugContext(ctx, "RSA Cert Handler found", "cert", certificatePem)
	// 	return &kaspb.PublicKeyResponse{PublicKey: certificatePem}, nil
	// }

	rsaPublicKeyPem := p.KeyProvider.PublicKey()

	slog.DebugContext(ctx, "RSA Public Key Handler found", "cert", string(rsaPublicKeyPem))
	return &kaspb.PublicKeyResponse{PublicKey: string(rsaPublicKeyPem)}, nil
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
