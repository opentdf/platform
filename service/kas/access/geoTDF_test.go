package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"testing"

	"github.com/golang/geo/s2"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *logger.Logger {
	return &logger.Logger{
		Logger: slog.New(slog.Default().Handler()),
	}
}

func TestProvider_parseLocation(t *testing.T) {
	// happy tests
	for _, tt := range []struct {
		name string
		l    string
		want s2.LatLng
	}{
		{"origin", base64.StdEncoding.EncodeToString([]byte(`{"lat":0,"lng":0}`)), s2.LatLngFromDegrees(0, 0)},
		{"ten-by-ten", base64.StdEncoding.EncodeToString([]byte(`{"lat":10,"lng":10}`)), s2.LatLngFromDegrees(10, 10)},
		{"another-quadrant", base64.StdEncoding.EncodeToString([]byte(`{"lat":10,"lng":-10}`)), s2.LatLngFromDegrees(10, -10)},
		{"omitted-field", base64.StdEncoding.EncodeToString([]byte(`{"lat":10}`)), s2.LatLngFromDegrees(10, 0)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Logger: testLogger()}
			got, err := p.parseLocation(context.Background(), tt.l)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, *got)
		})
	}

	// sad tests
	for _, tt := range []struct {
		name string
		l    string
		e    string
	}{
		{"badEncoding", `{}`, "invalid base64"},
		{"badJson", base64.StdEncoding.EncodeToString([]byte(`{`)), "invalid json"},
		{"badLat", base64.StdEncoding.EncodeToString([]byte(`{"lat":10000,"lng":10}`)), "invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Logger: testLogger()}
			got, err := p.parseLocation(context.Background(), tt.l)
			require.ErrorContains(t, err, tt.e)
			assert.Nil(t, got)
		})
	}
}

func TestProvider_parseSignedLocation(t *testing.T) {
	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Encode public part of keyEC to a PEM file
	b, err := x509.MarshalPKIXPublicKey(keyEC.Public())
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)

	k := []security.KeyPairInfo{
		{Certificate: string(keyPEM), KID: "r", Algorithm: "ES256"},
	}

	// happy tests
	for _, tt := range []struct {
		name     string
		lat, lng float64
		want     s2.LatLng
	}{
		{"origin", 0, 0, s2.LatLngFromDegrees(0, 0)},
		{"another-quadrant", 10, -10, s2.LatLngFromDegrees(10, -10)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := Location{Lat: tt.lat, Lng: tt.lng}
			p := &Provider{Logger: testLogger(), KASConfig: KASConfig{Experimental: Experimental{GeoTDF: GeoTDF{Keys: k}}}}
			tok, err := p.SignLocation(context.Background(), &l, "r", keyEC)
			require.NoError(t, err)
			got, err := p.parseLocation(context.Background(), string(tok))
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.want, *got)
		})
	}
}

func TestProvider_parseRegion(t *testing.T) {
	// happy tests
	for _, tt := range []struct {
		name           string
		l              string
		contains       []s2.LatLng
		doesNotContain []s2.LatLng
	}{
		{
			"east-atlantic",
			base64.StdEncoding.EncodeToString([]byte(`[{"lat":10,"lng":-10},{"lat":-10,"lng":-10},{"lat":-10,"lng":10},{"lat":10,"lng":10}]`)),
			[]s2.LatLng{
				s2.LatLngFromDegrees(0, 0),
				s2.LatLngFromDegrees(-5, 0),
			},
			[]s2.LatLng{
				s2.LatLngFromDegrees(11, 10),
				s2.LatLngFromDegrees(-50, 0),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Logger: testLogger()}
			got, err := p.parseRegion(context.Background(), tt.l)
			require.NoError(t, err)
			require.NotNil(t, got)
			for _, p := range tt.contains {
				assert.True(t, got.ContainsPoint(s2.PointFromLatLng(p)), "region should contain point %v", p)
			}
			for _, p := range tt.doesNotContain {
				assert.False(t, got.ContainsPoint(s2.PointFromLatLng(p)), "region should not contain point %v", p)
			}
		})
	}

	// sad tests
	for _, tt := range []struct {
		name string
		l    string
		e    string
	}{
		{"badEncoding", `--`, "invalid base64"},
		{"badJson", base64.StdEncoding.EncodeToString([]byte(`{`)), "invalid json"},
		{"badRegion", base64.StdEncoding.EncodeToString([]byte(`[{"lat":10,"lng":10},{"lat":0,"lng":0}]`)), "invalid region"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Logger: testLogger()}
			got, err := p.parseRegion(context.Background(), tt.l)
			require.ErrorContains(t, err, tt.e)
			assert.Nil(t, got)
		})
	}
}
