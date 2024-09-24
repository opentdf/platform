package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang/geo/s2"
)

type contextKey string

const ctxExperimentalGeoTDFKey contextKey = "accessExperimenal_geotdf"

// Checks to see if the given context defines a location and that location is
// within the geoCoord passed in. If not, fails.
func (p *Provider) checkGeoTDF(ctx context.Context, geoCoord string) error {
	l, ok := ctx.Value(ctxExperimentalGeoTDFKey).(s2.LatLng)
	if !ok {
		return err403("user location not found")
	}

	r, err := p.parseRegion(ctx, geoCoord)
	if err != nil {
		return err
	}

	// test to see if r contains l
	if r.ContainsPoint(s2.PointFromLatLng(l)) {
		return nil
	}
	return err403("user location not in region")
}

// Parses the region, a base64 encoded JSON object, into an S2 region.
func (p *Provider) parseRegion(_ context.Context, r string) (*s2.Loop, error) {
	s, err := base64.StdEncoding.DecodeString(r)
	if err != nil {
		return nil, err400("invalid base64 encoding")
	}
	var region []Location
	if err := json.Unmarshal(s, &region); err != nil {
		return nil, err400("invalid json")
	}
	if len(region) < 3 { //nolint:mnd // 3 points are needed to form a loop
		return nil, err400("invalid region")
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

// Parses the location, a base64 encoded JSON object, into an S2 lat/long pair.
// FIXME should include altitude and some kind of error estimate.
// Other options: particle cloud?
func (p *Provider) parseLocation(ctx context.Context, l string) (*s2.LatLng, error) {
	var loc Location
	if i0 := strings.Index(l, "."); i0 < 0 {
		// Not a JWS, just an encoded location.
		p.Logger.WarnContext(ctx, "location not a jws")
	} else if i1 := strings.Index(l[i0+1:], "."); i1 < 0 {
		p.Logger.WarnContext(ctx, "invalid location jws", "location", l)
		l = l[i0+1:]
	} else {
		// TODO Get key
		// jws.Verify([]byte(l), jws.WithKey())
		l = l[i0+1 : i1]
	}

	s, err := base64.StdEncoding.DecodeString(l)
	if err != nil {
		return nil, err400("invalid base64 encoding")
	}

	if err := json.Unmarshal(s, &loc); err != nil {
		return nil, err400("invalid json")
	}
	return ll2point(loc.Lat, loc.Lng)
}

func ll2point(lat, lng float64) (*s2.LatLng, error) {
	if lat < -90 || lat > 90 {
		return nil, err400("invalid latitude")
	}
	if lng < -180 || lng > 180 {
		return nil, err400("invalid longitude")
	}
	ll := s2.LatLngFromDegrees(lat, lng)
	return &ll, nil
}
