//go:build unix

package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"runtime"
	"syscall"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// BenchmarkDPoPTransportBody measures the one-shot body path used by multipart
// clients. Run each sub-benchmark in a separate process for comparable max RSS.
func BenchmarkDPoPTransportBody(b *testing.B) {
	const partSize = 64 << 20
	payload := make([]byte, partSize)
	rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		b.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		b.Fatal(err)
	}
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return nil, err
		}
		if err := r.Body.Close(); err != nil {
			return nil, err
		}
		return emptyResponse(r, http.StatusOK), nil
	})
	for _, tc := range []struct {
		name   string
		source AccessTokenSource
	}{
		{"bearer", &mockCredentialTokenSource{mockTokenSource: mockTokenSource{token: "token"}, tokenType: TokenTypeBearer}},
		{"dpop", &mockCredentialTokenSource{mockTokenSource: mockTokenSource{token: "token"}, tokenType: TokenTypeDPoP}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			transport := &DPoPTransport{Base: base, DPoPKey: key, TokenSource: tc.source}
			b.SetBytes(partSize)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				req, err := http.NewRequest(http.MethodPut, "https://storage.invalid/part", nil)
				if err != nil {
					b.Fatal(err)
				}
				req.Body = io.NopCloser(bytes.NewReader(payload))
				req.ContentLength = partSize
				resp, err := transport.RoundTrip(req)
				if err != nil {
					b.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			var usage syscall.Rusage
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
				b.Fatal(err)
			}
			peakRSS := float64(usage.Maxrss)
			if runtime.GOOS == "linux" {
				peakRSS *= 1024
			}
			b.ReportMetric(peakRSS, "process-peak-RSS-B")
		})
	}
}
