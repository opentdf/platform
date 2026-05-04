package audit

import (
	"context"
	"encoding"
	"encoding/json"
	"log/slog"
	"reflect"

	dotnotation "github.com/opentdf/platform/service/internal/dotnotation"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

func (a *Logger) buildLogEntry(ctx context.Context, event *EventObject) map[string]any {
	entry := event.emittedPayloadMap()
	a.applyJWTClaimEnrichment(ctx, entry)
	return entry
}

func (a *Logger) applyJWTClaimEnrichment(ctx context.Context, entry map[string]any) {
	if len(a.config.JWTClaimMappings) == 0 {
		return
	}

	token := ctxAuth.GetAccessTokenFromContext(ctx, a.logger)
	if token == nil {
		return
	}

	claimsMap, err := token.AsMap(ctx)
	if err != nil {
		a.logger.ErrorContext(ctx, "failed to read JWT claims for audit enrichment", slog.Any("error", err))
		return
	}

	a.applyMappedJWTClaims(ctx, entry, claimsMap)
}

func (a *Logger) applyMappedJWTClaims(ctx context.Context, entry map[string]any, claimsMap map[string]any) {
	for _, mapping := range a.config.JWTClaimMappings {
		if mapping.Claim == "" || mapping.Path == "" {
			continue
		}

		value := dotnotation.Get(claimsMap, mapping.Claim)
		if value == nil {
			continue
		}

		if err := dotnotation.Set(entry, mapping.Path, normalizeAuditValue(value)); err != nil {
			a.logger.ErrorContext(ctx,
				"failed to apply JWT claim mapping to audit log",
				slog.String("claim", mapping.Claim),
				slog.String("path", mapping.Path),
				slog.Any("error", err),
			)
		}
	}
}

func normalizeAuditValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		if typed == nil {
			return nil
		}
		normalized := make(map[string]any, len(typed))
		for key, nested := range typed {
			normalized[key] = normalizeAuditValue(nested)
		}
		return normalized
	case []any:
		if typed == nil {
			return nil
		}
		normalized := make([]any, len(typed))
		for idx, nested := range typed {
			normalized[idx] = normalizeAuditValue(nested)
		}
		return normalized
	}

	if marshaler, ok := value.(json.Marshaler); ok {
		encoded, err := marshaler.MarshalJSON()
		if err == nil {
			var decoded any
			if err := json.Unmarshal(encoded, &decoded); err == nil {
				return decoded
			}
		}
	}

	if marshaler, ok := value.(encoding.TextMarshaler); ok {
		encoded, err := marshaler.MarshalText()
		if err == nil {
			return string(encoded)
		}
	}

	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil
	}
	//nolint:exhaustive // only composite kinds need normalization; scalars can pass through unchanged
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
		return normalizeAuditValue(rv.Elem().Interface())
	case reflect.Struct:
		structType := rv.Type()
		normalized := make(map[string]any, structType.NumField())
		for i := 0; i < structType.NumField(); i++ {
			field := structType.Field(i)
			if !field.IsExported() {
				continue
			}
			opts, ok, _ := parseAuditFieldOptions(field)
			if !ok {
				continue
			}
			normalized[opts.name] = normalizeAuditValue(rv.Field(i).Interface())
		}
		return normalized
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		if rv.Type().Key().Kind() != reflect.String {
			return value
		}
		normalized := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			normalized[iter.Key().String()] = normalizeAuditValue(iter.Value().Interface())
		}
		return normalized
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		normalized := make([]any, rv.Len())
		for idx := range normalized {
			normalized[idx] = normalizeAuditValue(rv.Index(idx).Interface())
		}
		return normalized
	default:
		return value
	}
}
