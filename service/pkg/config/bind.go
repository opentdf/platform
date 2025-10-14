package config

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
)

// BindOptions controls how service config binding behaves.
type BindOptions struct {
	// Eagerly resolve secrets during binding; otherwise they resolve lazily.
	EagerResolve bool
}

// BindOption functional option.
type BindOption func(*BindOptions)

// WithEagerSecretResolution enables eager secret resolution during bind.
func WithEagerSecretResolution() BindOption { return func(o *BindOptions) { o.EagerResolve = true } }

// BindServiceConfig decodes a ServiceConfig map into a typed struct target using
// mapstructure with custom decode hooks (e.g., Secret). It optionally validates
// the result and can eagerly resolve secret values.
func BindServiceConfig[T any](ctx context.Context, svcCfg ServiceConfig, out *T, opts ...BindOption) error {
	var options BindOptions
	for _, o := range opts {
		o(&options)
	}

	if out == nil {
		return errors.New("nil output target")
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(secretDecodeHook),
		Result:     out,
		TagName:    "mapstructure",
		Squash:     true,
		ZeroFields: true,
	})
	if err != nil {
		return fmt.Errorf("bind decoder: %w", err)
	}
	if err := dec.Decode(svcCfg); err != nil {
		return fmt.Errorf("bind decode: %w", err)
	}

	// Eager secret resolution
	if options.EagerResolve {
		if err := resolveSecrets(ctx, out); err != nil {
			return err
		}
	}

	// Validate struct using go-playground/validator tags, if present
	if err := validator.New().Struct(out); err != nil {
		return err
	}
	return nil
}

// resolveSecrets walks the struct and resolves any Secret fields.
func resolveSecrets(ctx context.Context, v any) error {
	// Reflectively find Secret fields; keep it minimal and safe.
	// We only walk exported fields of structs and slices/maps.
	return walk(v, func(s *Secret) error {
		// Skip zero-value secrets (unset optional fields)
		if s.IsZero() {
			return nil
		}
		_, err := s.Resolve(ctx)
		return err
	})
}
