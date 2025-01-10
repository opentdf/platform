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
	"github.com/opentdf/platform/service/kas/recrypt"
	"go.opentelemetry.io/otel/trace"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
)

func (p Provider) LegacyPublicKey(ctx context.Context, req *connect.Request[kaspb.LegacyPublicKeyRequest]) (*connect.Response[wrapperspb.StringValue], error) {
	algorithm, err := p.CryptoProvider.ParseAlgorithm(req.Msg.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	kids, err := p.CryptoProvider.CurrentKID(algorithm)
	if err != nil {
		return nil, err
	}
	if len(kids) == 0 {
		return nil, security.ErrCertNotFound
	}
	if len(kids) > 1 {
		p.Logger.ErrorContext(ctx, "multiple keys found for algorithm", "algorithm", algorithm, "kids", kids)
	}
	fmt := recrypt.KeyFormatPEM
	pem, err := p.CryptoProvider.PublicKey(algorithm, kids[:1], fmt)
	if err != nil {
		p.Logger.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.Join(ErrConfig, errors.New("configuration error")))
	}
	return connect.NewResponse(&wrapperspb.StringValue{Value: pem}), nil
}

func (p Provider) PublicKey(ctx context.Context, req *connect.Request[kaspb.PublicKeyRequest]) (*connect.Response[kaspb.PublicKeyResponse], error) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "publickey")
		defer span.End()
	}

	algorithm, err := p.CryptoProvider.ParseAlgorithm(req.Msg.GetAlgorithm())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if algorithm == recrypt.AlgorithmUndefined {
		algorithm = recrypt.AlgorithmRSA2048
	}

	kids, err := p.CryptoProvider.CurrentKID(algorithm)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if len(kids) == 0 {
		return nil, security.ErrCertNotFound
	}
	fmt, err := p.CryptoProvider.ParseKeyFormat(req.Msg.GetFmt())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if len(kids) > 1 && fmt != recrypt.KeyFormatJWK {
		p.Logger.WarnContext(ctx, "multiple active keys found for algorithm, only returning the first one", "algorithm", algorithm, "kids", kids, "fmt", fmt)
		kids = kids[:1]
	}

	r := func(value string, kid []recrypt.KeyIdentifier, err error) (*connect.Response[kaspb.PublicKeyResponse], error) {
		if errors.Is(err, security.ErrCertNotFound) {
			p.Logger.ErrorContext(ctx, "no key found for", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, connect.NewError(connect.CodeNotFound, err)
		} else if err != nil {
			p.Logger.ErrorContext(ctx, "configuration error for key lookup", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if req.Msg.GetV() == "1" {
			p.Logger.WarnContext(ctx, "hiding kid in public key response for legacy client", "kid", kid, "v", req.Msg.GetV())
			return connect.NewResponse(&kaspb.PublicKeyResponse{PublicKey: value}), nil
		}
		return connect.NewResponse(&kaspb.PublicKeyResponse{PublicKey: value, Kid: string(kid[0])}), nil
	}

	v, err := p.CryptoProvider.PublicKey(algorithm, kids, fmt)
	return r(v, kids, err)
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
