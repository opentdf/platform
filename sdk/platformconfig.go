package sdk

import "log/slog"

func (s SDK) PlatformIssuer() string {
	// This check is needed if we want to fetch platform configuration over ipc
	if s.config.platformConfiguration == nil {
		cfg, err := getPlatformConfiguration(s.conn)
		if err != nil {
			slog.Warn("failed to get platform configuration", slog.Any("error", err))
		}
		s.config.platformConfiguration = cfg
	}
	value, ok := s.config.platformConfiguration["platform_issuer"].(string)
	if !ok {
		slog.Warn("platform_issuer not found in platform configuration")
	}
	return value
}
