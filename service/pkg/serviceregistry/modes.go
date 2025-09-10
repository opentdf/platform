package serviceregistry

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ModeName represents a typed mode identifier
type ModeName string

const (
	ModeALL       ModeName = "all"
	ModeCore      ModeName = "core"
	ModeKAS       ModeName = "kas"
	ModeERS       ModeName = "entityresolution"
	ModeEssential ModeName = "essential"
)

// String returns the string representation of ModeName
func (m ModeName) String() string {
	return string(m)
}

// ServiceConfigError represents errors in service configuration
type ServiceConfigError struct {
	Type    string
	Mode    string
	Service string
	Message string
}

func (e *ServiceConfigError) Error() string {
	if e.Mode != "" && e.Service != "" {
		return fmt.Sprintf("service config error [%s] for mode '%s', service '%s': %s", e.Type, e.Mode, e.Service, e.Message)
	} else if e.Mode != "" {
		return fmt.Sprintf("service config error [%s] for mode '%s': %s", e.Type, e.Mode, e.Message)
	}
	return fmt.Sprintf("service config error [%s]: %s", e.Type, e.Message)
}

// ParseModesWithNegation parses mode strings and separates included and excluded services
func ParseModesWithNegation(modes []string) ([]ModeName, []string, error) {
	var included []ModeName
	var excluded []string

	for _, mode := range modes {
		modeStr := string(mode)
		if serviceName, found := strings.CutPrefix(modeStr, "-"); found {
			// This is an exclusion
			if serviceName == "" {
				return nil, nil, errors.New("empty service name after '-'")
			}
			slog.Debug("negated registered service", slog.String("service", serviceName))
			excluded = append(excluded, serviceName)
		} else {
			m := ModeName(mode)
			// This is an inclusion
			included = append(included, m)
		}
	}

	// If we only have exclusions without inclusions, that's an error
	if len(included) == 0 && len(excluded) > 0 {
		return nil, nil, errors.New("cannot exclude services without including base modes")
	}

	return included, excluded, nil
}
