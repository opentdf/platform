package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
		{"sample", "eyJsYXQiOi0zOC45MDA0NDIsImxuZyI6LTc3LjA0MTk4LCJ1c2VyIjoianNtaXRoIiwidGltZSI6MTcyNzM4Mjc1N30=", s2.LatLngFromDegrees(-38.900442, -77.04198)},
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

func mustRegionStr(l ...Location) string {
	j, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(j)
}

var (
	eastAtlantic = mustRegionStr(
		Location{10, -10, "", 0},
		Location{-10, -10, "", 0},
		Location{-10, 10, "", 0},
		Location{10, 10, "", 0},
	)
	office = mustRegionStr(
		Location{38.90034854189383, -77.04212675686254, "", 0},
		Location{38.90034852050663, -77.04186123377212, "", 0},
		Location{38.900838220852215, -77.04185361148076, "", 0},
		Location{38.90086633875238, -77.04223651735694, "", 0},
	)
	projectX = "W3sgImxhdCI6IDM3LjQyMzY5OCwgImxuZyI6IC0xMjIuMjE4Nzc3IH0seyAibGF0IjogMzcuNDIzMzMxLCAibG5nIjogLTEyMi4yMTAxMzcgfSx7ICJsYXQiOiAzNy40MTcyMDEsICJsbmciOiAtMTIyLjIxMDkxOCB9LHsgImxhdCI6IDM3LjQyMDA5OCwgImxuZyI6IC0xMjIuMjE3NzQ0IH0seyAibGF0IjogMzcuNDIzNjk4LCAibG5nIjogLTEyMi4yMTg3NzcgfV0="
)

func TestWithin(t *testing.T) {
	office := []Location{
		{38.90034854189383, -77.04212675686254, "", 0},  // SW
		{38.90034852050663, -77.04186123377212, "", 0},  // SE
		{38.900838220852215, -77.04185361148076, "", 0}, // NE
		{38.90086633875238, -77.04223651735694, "", 0},  // NW
	}
	loop, err := loopFromLocations(office...)
	require.NoError(t, err)
	assert.True(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(38.9005, -77.042))), "region should contain point")
	assert.False(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(38.9, -77.0))), "region should contain point")
}

func TestWithinPX(t *testing.T) {
	office := []Location{
		{37.423698, -122.218777, "", 0}, // N W
		{37.423331, -122.210137, "", 0}, // N -
		{37.417201, -122.210918, "", 0}, // S E
		{37.420098, -122.217744, "", 0}, // - W
		{37.423698, -122.218777, "", 0}, // N W
	}
	loop, err := loopFromLocations(office...)
	require.NoError(t, err)
	assert.True(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(38.9005, -77.042))), "region should contain point")
	assert.False(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(38.9, -77.0))), "region should not contain point")
}

func TestWithinPXReversed(t *testing.T) {
	office := []Location{
		{37.423698, -122.218777, "", 0}, // N W
		{37.420098, -122.217744, "", 0}, // - W
		{37.417201, -122.210918, "", 0}, // S E
		{37.423331, -122.210137, "", 0}, // N -
	}
	loop, err := loopFromLocations(office...)
	require.NoError(t, err)
	assert.True(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(37.42, -122.215))), "region should contain point")
	assert.False(t, loop.ContainsPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(38.9, -77.0))), "region should not contain point")
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
			eastAtlantic,
			[]s2.LatLng{
				s2.LatLngFromDegrees(0, 0),
				s2.LatLngFromDegrees(-5, 0),
			},
			[]s2.LatLng{
				s2.LatLngFromDegrees(11, 10),
				s2.LatLngFromDegrees(-50, 0),
			},
		},
		{
			"office",
			office,
			[]s2.LatLng{s2.LatLngFromDegrees(38.9005, -77.042)},
			[]s2.LatLng{
				s2.LatLngFromDegrees(11, 10),
				s2.LatLngFromDegrees(-50, 0),
			},
		},
		{
			"project-x",
			projectX,
			[]s2.LatLng{},
			[]s2.LatLng{s2.LatLngFromDegrees(-38.9004420, -77.0419800)},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{Logger: testLogger()}
			got, err := p.parseRegion(context.Background(), tt.l)
			require.NoError(t, err)
			require.NotNil(t, got)
			for _, loc := range tt.contains {
				assert.True(t, got.ContainsPoint(s2.PointFromLatLng(loc)), "region should contain point %v", got, loc)
			}
			for _, loc := range tt.doesNotContain {
				assert.False(t, got.ContainsPoint(s2.PointFromLatLng(loc)), "region %v should not contain point %v", got, loc)
			}x
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
