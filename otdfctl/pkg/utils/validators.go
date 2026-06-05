package utils

import (
	"errors"
	"net/url"
	"strings"
)

func NormalizeEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http":
		if u.Port() == "" {
			u.Host += ":80"
		}
	case "https":
		if u.Port() == "" {
			u.Host += ":443"
		}
	default:
		return nil, errors.New("invalid scheme")
	}
	for strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u, nil
}
