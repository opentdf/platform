package profiles

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
)

var (
	ErrInvalidExtensionNamespace = errors.New("invalid extension namespace")
	ErrDuplicateExtension        = errors.New("duplicate extension registration")
	ErrExtensionNotRegistered    = errors.New("extension not registered for scope")
	ErrExtensionTypeMismatch     = errors.New("extension type does not match registration")
	ErrExtensionDecode           = errors.New("cannot decode extension")
	ErrExtensionEncode           = errors.New("cannot encode extension")
)

var extensionNamespace = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

type extensionScope uint8

const (
	globalExtension extensionScope = iota
	profileExtension
)

type extensionKey struct {
	scope     extensionScope
	namespace string
}

// ExtensionOption registers one consumer shape for a namespace and scope.
// Registrations belong to one ExtensionConfig, never to a package-wide registry.
type ExtensionOption func(*ExtensionConfig) error

func registerExtension[T any](scope extensionScope, namespace string) ExtensionOption {
	return func(config *ExtensionConfig) error {
		if !extensionNamespace.MatchString(namespace) {
			return ErrInvalidExtensionNamespace
		}
		key := extensionKey{scope, namespace}
		if _, exists := config.registry[key]; exists {
			return ErrDuplicateExtension
		}
		config.registry[key] = reflect.TypeFor[T]()
		return nil
	}
}

// WithGlobalExtension declares the JSON shape owned by namespace in global settings.
// The extender owns compatibility, unknown-field retention, validation, and versioning
// for its payload; typed writes replace this namespace without retaining omitted fields.
func WithGlobalExtension[T any](namespace string) ExtensionOption {
	return registerExtension[T](globalExtension, namespace)
}

// WithProfileExtension declares the JSON shape owned by namespace in each profile.
// The extender owns compatibility, unknown-field retention, validation, and versioning
// for its payload; typed writes replace this namespace without retaining omitted fields.
func WithProfileExtension[T any](namespace string) ExtensionOption {
	return registerExtension[T](profileExtension, namespace)
}

// ExtensionConfig binds registrations to an existing profiler/driver invocation.
// It does not automatically expose payloads through CLI output or diagnostics.
type ExtensionConfig struct {
	profiler *osprofiles.Profiler
	registry map[extensionKey]reflect.Type
}

// NewExtensionConfig accepts an existing profiler from CreateProfiler or NewProfiler.
// A global registration does not require any profile to exist.
func NewExtensionConfig(profiler *osprofiles.Profiler, opts ...ExtensionOption) (*ExtensionConfig, error) {
	if profiler == nil {
		return nil, errors.New("extension profiler is nil")
	}
	config := &ExtensionConfig{profiler: profiler, registry: make(map[extensionKey]reflect.Type, len(opts))}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("extension option is nil")
		}
		if err := opt(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func checkExtensionType[T any](config *ExtensionConfig, scope extensionScope, namespace string) error {
	if config == nil {
		return ErrExtensionNotRegistered
	}
	shape, ok := config.registry[extensionKey{scope, namespace}]
	if !ok {
		return ErrExtensionNotRegistered
	}
	if shape != reflect.TypeFor[T]() {
		return ErrExtensionTypeMismatch
	}
	return nil
}

func decodeExtension[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		// Do not include the raw value: an extension may contain credentials.
		return value, ErrExtensionDecode
	}
	return value, nil
}

// ReadGlobalExtension reports absence separately from a stored JSON null or decoding error.
func ReadGlobalExtension[T any](config *ExtensionConfig, namespace string) (T, bool, error) {
	var zero T
	if err := checkExtensionType[T](config, globalExtension, namespace); err != nil {
		return zero, false, err
	}
	raw, present, err := osprofiles.GetGlobalConfig(config.profiler).Extension(namespace)
	if err != nil || !present {
		return zero, present, err
	}
	value, err := decodeExtension[T](raw)
	return value, true, err
}

// ReadProfileExtension reads one named profile without selecting or changing the default.
func ReadProfileExtension[T any](config *ExtensionConfig, profileName, namespace string) (T, bool, error) {
	var zero T
	if err := checkExtensionType[T](config, profileExtension, namespace); err != nil {
		return zero, false, err
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](config.profiler, profileName)
	if err != nil {
		return zero, false, err
	}
	raw, present, err := profile.Extension(namespace)
	if err != nil || !present {
		return zero, present, err
	}
	value, err := decodeExtension[T](raw)
	return value, true, err
}

func prepareExtensionWrite[T any](config *ExtensionConfig, scope extensionScope, namespace string, value T) (json.RawMessage, error) {
	if err := checkExtensionType[T](config, scope, namespace); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		// MarshalJSON errors can contain secrets from the value being encoded.
		return nil, ErrExtensionEncode
	}
	return payload, nil
}

// WriteGlobalExtension fully replaces one global namespace with value, without
// retaining omitted payload fields. The extender owns compatibility, unknown-field
// retention, validation, and versioning for its replacement payload.
func WriteGlobalExtension[T any](config *ExtensionConfig, namespace string, value T) error {
	payload, err := prepareExtensionWrite(config, globalExtension, namespace, value)
	if err != nil {
		return err
	}
	return osprofiles.GetGlobalConfig(config.profiler).SetExtension(namespace, payload)
}

// WriteProfileExtension fully replaces one namespace in an existing named profile,
// without retaining omitted payload fields. The extender owns compatibility,
// unknown-field retention, validation, and versioning for its replacement payload.
func WriteProfileExtension[T any](config *ExtensionConfig, profileName, namespace string, value T) error {
	payload, err := prepareExtensionWrite(config, profileExtension, namespace, value)
	if err != nil {
		return err
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](config.profiler, profileName)
	if err != nil {
		return err
	}
	return profile.SetExtension(namespace, payload)
}
