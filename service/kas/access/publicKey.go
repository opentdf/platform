package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
)

func (p Provider) lookupKid(ctx context.Context, algorithm string) (string, error) {
	if len(p.KASConfig.Keyring) == 0 {
		p.Logger.WarnContext(ctx, "no default keys found", "algorithm", algorithm)
		return "", errors.Join(ErrConfig, status.Error(codes.NotFound, "no default keys configured"))
	}

	for _, k := range p.KASConfig.Keyring {
		if k.Algorithm == algorithm && !k.Legacy {
			return k.KID, nil
		}
	}
	p.Logger.WarnContext(ctx, "no (non-legacy) key for requested algorithm", "algorithm", algorithm)
	return "", errors.Join(ErrConfig, status.Error(codes.NotFound, "no default key for algorithm"))
}

func (p Provider) LegacyPublicKey(ctx context.Context, req *connect.Request[kaspb.LegacyPublicKeyRequest]) (*connect.Response[wrapperspb.StringValue], error) {
	in := req.Msg
	algorithm := in.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	pem, err := legacyPublicKey(ctx, p, algorithm)
	if err != nil {
		return nil, err
	}
	rsp := &wrapperspb.StringValue{Value: pem}
	return &connect.Response[wrapperspb.StringValue]{Msg: rsp}, nil
}

func (p Provider) LegacyPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	algorithm := r.URL.Query().Get("algorithm")
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	pem, err := legacyPublicKey(r.Context(), p, algorithm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(pem)) //nolint:errcheck // ignore error
}

func legacyPublicKey(ctx context.Context, p Provider, algorithm string) (string, error) {
	var pem string
	var err error
	if p.CryptoProvider == nil {
		return "", errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
	}
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return "", err
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		pem, err = p.CryptoProvider.ECCertificate(kid)
		if err != nil {
			p.Logger.ErrorContext(ctx, "CryptoProvider.ECPublicKey failed", "err", err)
			return "", errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		pem, err = p.CryptoProvider.RSAPublicKey(kid)
		if err != nil {
			p.Logger.ErrorContext(ctx, "CryptoProvider.RSAPublicKey failed", "err", err)
			return "", errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
	default:
		return "", errors.Join(ErrConfig, status.Error(codes.NotFound, "invalid algorithm"))
	}
	return pem, nil
}

func (p Provider) PublicKey(ctx context.Context, req *connect.Request[kaspb.PublicKeyRequest]) (*connect.Response[kaspb.PublicKeyResponse], error) {
	in := req.Msg
	algorithm := in.GetAlgorithm()
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	fmt := in.GetFmt()
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return nil, err
	}

	r := func(value, kid string, err error) (*connect.Response[kaspb.PublicKeyResponse], error) {
		if errors.Is(err, security.ErrCertNotFound) {
			p.Logger.ErrorContext(ctx, "no key found for", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(err, status.Error(codes.NotFound, "no such key"))
		} else if err != nil {
			p.Logger.ErrorContext(ctx, "configuration error for key lookup", "err", err, "kid", kid, "algorithm", algorithm, "fmt", fmt)
			return nil, errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
		}
		rsp := &connect.Response[kaspb.PublicKeyResponse]{Msg: &kaspb.PublicKeyResponse{PublicKey: value}}

		if in.GetV() == "1" {
			p.Logger.WarnContext(ctx, "hiding kid in public key response for legacy client", "kid", kid, "v", in.GetV())
			return rsp, nil
		}
		rsp.Msg.Kid = kid
		return rsp, nil
	}

	pem, err := publicKey(ctx, p, algorithm, fmt)
	return r(pem, kid, err)

	// return nil, status.Error(codes.NotFound, "invalid algorithm or format")
}

func (p Provider) PublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	algorithm := r.URL.Query().Get("algorithm")
	if algorithm == "" {
		algorithm = security.AlgorithmRSA2048
	}
	fmt := r.URL.Query().Get("fmt")

	kid, err := p.lookupKid(r.Context(), algorithm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pem, err := publicKey(r.Context(), p, algorithm, fmt)
	if err != nil {
		if errors.Is(err, security.ErrCertNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pubkey := &kaspb.PublicKeyResponse{PublicKey: pem, Kid: kid}
	pubkeyByte, err := protojson.Marshal(pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(pubkeyByte) //nolint:errcheck // ignore error
}

func publicKey(ctx context.Context, p Provider, algorithm, fmt string) (string, error) {
	kid, err := p.lookupKid(ctx, algorithm)
	if err != nil {
		return "", err
	}

	switch algorithm {
	case security.AlgorithmECP256R1:
		ecPublicKeyPem, err := p.CryptoProvider.ECPublicKey(kid)
		if err != nil {
			return "", err
		}
		return ecPublicKeyPem, nil
	case security.AlgorithmRSA2048:
		fallthrough
	case "":
		switch fmt {
		case "jwk":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKeyAsJSON(kid)
			if err != nil {
				return "", errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
			}
			return rsaPublicKeyPem, nil
		case "pkcs8":
			fallthrough
		case "":
			rsaPublicKeyPem, err := p.CryptoProvider.RSAPublicKey(kid)
			if err != nil {
				return "", errors.Join(ErrConfig, status.Error(codes.Internal, "configuration error"))
			}
			return rsaPublicKeyPem, nil
		}
	}
	return "", status.Error(codes.NotFound, "invalid algorithm or format")
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
