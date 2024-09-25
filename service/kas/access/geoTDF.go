package access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/golang/geo/s2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/opentdf/platform/service/internal/security"
)

type contextKey string

const ctxExperimentalGeoTDFKey contextKey = "accessExperimenal_geotdf"

// Checks to see if the given context defines a location and that location is
// within the geoCoord passed in. If not, fails.
func (p *Provider) checkGeoTDF(ctx context.Context, geoCoord string) error {
	l, ok := ctx.Value(ctxExperimentalGeoTDFKey).(s2.LatLng)
	if !ok {
		return errLocation("location not found")
	}

	r, err := p.parseRegion(ctx, geoCoord)
	if err != nil {
		return err
	}

	// test to see if r contains l
	if r.ContainsPoint(s2.PointFromLatLng(l)) {
		return nil
	}
	return errLocation("user location not in region")
}

// Parses the region, a base64 encoded JSON object, into an S2 region.
func (p *Provider) parseRegion(_ context.Context, r string) (*s2.Loop, error) {
	s, err := base64.StdEncoding.DecodeString(r)
	if err != nil {
		return nil, errLocation("invalid base64 encoding", err)
	}
	var region []Location
	if err := json.Unmarshal(s, &region); err != nil {
		return nil, errLocation("invalid json", err)
	}
	if len(region) < 3 { //nolint:mnd // 3 points are needed to form a loop
		return nil, errLocation("empty or invalid region found in policy", err)
	}
	// map region to a list of s2.Point objects
	points := make([]s2.Point, len(region))
	for i, loc := range region {
		p, err := ll2point(loc.Lat, loc.Lng)
		if err != nil {
			return nil, err
		}
		points[i] = s2.PointFromLatLng(*p)
	}
	return s2.LoopFromPoints(points), nil
}

type Location struct {
	Lat  float64 `json:"lat"`
	Lng  float64 `json:"lng"`
	User string  `json:"user"`
	Time int64   `json:"time"`
}

// SignedLocation generates a signed location JWS object for the given location.
// It is signed using the JWA algorithm PS256.
func (p *Provider) SignLocation(ctx context.Context, loc *Location, kid string, privateKey crypto.PrivateKey) ([]byte, error) {
	locBytes, err := json.Marshal(loc)
	if err != nil {
		p.Logger.ErrorContext(ctx, "failed to marshal location", "err", err, "loc", loc)
		return nil, err
	}
	h := jws.NewHeaders()
	err = h.Set(jws.KeyIDKey, kid)
	if err != nil {
		return nil, fmt.Errorf("error setting the kid on the token: %w", err)
	}
	j, err := jws.Sign(locBytes, jws.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(h)))
	if err != nil {
		p.Logger.ErrorContext(ctx, "failed to sign location", "err", err, "loc", loc)
		return nil, err
	}
	return j, nil
}

// maps from alg -> kid -> key
type keyset map[string](map[string]any)

func (k keyset) FetchKeys(_ context.Context, ks jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	a := sig.ProtectedHeaders().Algorithm()
	byKid, ok := k[a.String()]
	if !ok {
		return nil
	}
	kid := sig.ProtectedHeaders().KeyID()
	key, ok := byKid[kid]
	if !ok {
		return nil
	}
	ks.Key(a, key)
	return nil
}

func loadKeys(ks []security.KeyPairInfo) (keyset, error) {
	keys := keyset(make(map[string](map[string]any)))
	for _, k := range ks {
		slog.Info("loadKeys: loading", "id", k.KID, "alg", k.Algorithm)
		if k.KID == "" {
			return nil, fmt.Errorf("key missing key identifier (kid) [%s]", k)
		}
		if k.Algorithm == "" {
			return nil, fmt.Errorf("key missing algorithm (alg) [%s]", k)
		}
		if _, ok := keys[k.Algorithm]; !ok {
			keys[k.Algorithm] = make(map[string]any)
		}
		loadedKey, err := loadKey(k)
		if err != nil {
			return nil, err
		}
		keys[k.Algorithm][k.KID] = loadedKey
	}
	return keys, nil
}

func loadKey(k security.KeyPairInfo) (any, error) {
	switch {
	case k.Private != "":
		return loadPrivateKey(k)
	case k.Certificate != "":
		return loadCertOrPublicKey(k)
	default:
		return nil, fmt.Errorf("key missing file name (cert or private): %v", k)
	}
}

func loadCertOrPublicKey(k security.KeyPairInfo) (crypto.PublicKey, error) {
	certPEM, err := fileOrRawPEM(k.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file [%s]: %w", k.Certificate, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	if bytes.Contains(certPEM, []byte("BEGIN CERTIFICATE")) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("failed to parse PEM formatted public key")
		}
		return pub, nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
	}
	return pub, nil
}

func loadPrivateKey(k security.KeyPairInfo) (crypto.PrivateKey, error) {
	privatePEM, err := fileOrRawPEM(k.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file [%s]: %w", k.Private, err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	switch {
	case err == nil:
		return priv, nil
	case strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead"):
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKCS1PrivateKey failed: %w", err)
		}
		return priv, err
	case strings.Contains(err.Error(), "use ParseECPrivateKey instead"):
		priv, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseECPrivateKey failed: %w", err)
		}
		return priv, err
	}

	return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
}

func fileOrRawPEM(k string) ([]byte, error) {
	if strings.HasPrefix(k, "-----BEGIN ") {
		return []byte(k), nil
	}
	certPEM, err := os.ReadFile(k)
	return certPEM, err
}

// Parses the location, a base64 encoded JSON object, into an S2 lat/long pair.
// FIXME should include altitude and some kind of error estimate.
// Other options: particle cloud?
func (p *Provider) parseLocation(ctx context.Context, l string) (*s2.LatLng, error) {
	var loc Location
	var s []byte
	var err error
	if i0 := strings.Index(l, "."); i0 < 0 {
		// Not a JWS, just an encoded location.
		p.Logger.WarnContext(ctx, "location not a jws")
		s, err = base64.StdEncoding.DecodeString(l)
		if err != nil {
			return nil, errLocation("invalid base64 encoding")
		}
	} else {
		if err := p.initKeyset(); err != nil {
			return nil, err
		}
		payload, err := jws.Verify([]byte(l), jws.WithKeyProvider(p.keyset))
		if err != nil {
			return nil, errLocation("loc tok verify fail", err)
		}
		s = payload
	}

	if err := json.Unmarshal(s, &loc); err != nil {
		return nil, errLocation("invalid json", err)
	}
	return ll2point(loc.Lat, loc.Lng)
}

func (p *Provider) initKeyset() error {
	if p.keyset != nil {
		return nil
	}
	ks, err := loadKeys(p.Experimental.GeoTDF.Keys)
	if err != nil {
		return err
	}
	p.keyset = ks
	return nil
}

func ll2point(lat, lng float64) (*s2.LatLng, error) {
	if lat < -90 || lat > 90 {
		return nil, errLocation("invalid latitude")
	}
	if lng < -180 || lng > 180 {
		return nil, errLocation("invalid longitude")
	}
	ll := s2.LatLngFromDegrees(lat, lng)
	return &ll, nil
}
