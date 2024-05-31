package sdk

import "log/slog"

func (s SDK) PlatformIssuer() string {
	value, ok := s.platformConfiguration["platform_issuer"].(string)
	if !ok {
		slog.Warn("platform_issuer not found in platform configuration")
	}
	return value
}
