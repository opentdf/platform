package kas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

const (
	resolverNameKey    = "resolver_name"
	kasURIKey          = "kas_uri"
	staticResolverName = "StaticRegisteredKasURIResolver"
)

var errKasURIEmpty = errors.New("error kasURI is empty")

// StaticRegisteredKasURIResolver returns a configured KAS URI as-is.
type StaticRegisteredKasURIResolver struct {
	kasURI string
}

func NewStaticRegisteredKasURIResolver(kasURI string) (*StaticRegisteredKasURIResolver, error) {
	if kasURI == "" {
		return nil, errKasURIEmpty
	}
	return &StaticRegisteredKasURIResolver{
		kasURI: kasURI,
	}, nil
}

func (r *StaticRegisteredKasURIResolver) ResolveURI(_ context.Context) (string, error) {
	if r.kasURI == "" {
		return "", fmt.Errorf("registered KAS URI is empty")
	}
	return r.kasURI, nil
}

func (r *StaticRegisteredKasURIResolver) String() string {
	return fmt.Sprintf("%s: %s, %s: %s", resolverNameKey, staticResolverName, kasURIKey, r.kasURI)
}

func (r *StaticRegisteredKasURIResolver) LogValue() slog.Value {
	return slog.StringValue(r.String())
}
