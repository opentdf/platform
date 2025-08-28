package serviceregistry

import "fmt"

// ServiceName represents a typed service identifier
type ServiceName string

// ModeName represents a typed mode identifier
type ModeName string

const (
	ModeALL       ModeName = "all"
	ModeCore      ModeName = "core"
	ModeKAS       ModeName = "kas"
	ModeERS       ModeName = "entityresolution"
	ModeEssential ModeName = "essential"

	ServiceKAS              ServiceName = "kas"
	ServicePolicy           ServiceName = "policy"
	ServiceWellKnown        ServiceName = "wellknown"
	ServiceEntityResolution ServiceName = "entityresolution"
	ServiceAuthorization    ServiceName = "authorization"
)

// String returns the string representation of ServiceName
func (s ServiceName) String() string {
	return string(s)
}

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
