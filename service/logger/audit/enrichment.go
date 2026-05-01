package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"

	internaldotnotation "github.com/opentdf/platform/service/internal/dotnotation"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

var reservedClaimDestinationPaths = map[string]struct{}{
	"requestID":           {},
	"timestamp":           {},
	"action.type":         {},
	"action.result":       {},
	"object.type":         {},
	"actor.id":            {},
	"clientInfo.platform": {},
}

func (a *Logger) buildLogEntry(ctx context.Context, event *EventObject) map[string]any {
	entry := event.logMap()
	a.applyJWTClaimEnrichment(ctx, entry)
	return entry
}

func (a *Logger) applyJWTClaimEnrichment(ctx context.Context, entry map[string]any) {
	if len(a.config.AuditedEntityJWTClaims) == 0 && len(a.config.JWTClaimMappings) == 0 {
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

	a.applyLegacyAuditedEntityClaims(ctx, entry, claimsMap)
	a.applyMappedJWTClaims(ctx, entry, claimsMap)
}

func (a *Logger) applyLegacyAuditedEntityClaims(ctx context.Context, entry map[string]any, claimsMap map[string]any) {
	if len(a.config.AuditedEntityJWTClaims) == 0 {
		return
	}

	entityMetadata, err := getOrCreateMapAtPath(entry, "eventMetaData.entityMetadata")
	if err != nil {
		a.logger.ErrorContext(ctx, "failed to create legacy audit entity metadata destination", slog.Any("error", err))
		return
	}

	for _, claim := range a.config.AuditedEntityJWTClaims {
		if claim == "" {
			continue
		}

		value := internaldotnotation.Get(claimsMap, claim)
		if value == nil {
			continue
		}

		entityMetadata[claim] = stringifyJWTClaimValue(value)
	}
}

func (a *Logger) applyMappedJWTClaims(ctx context.Context, entry map[string]any, claimsMap map[string]any) {
	for _, mapping := range a.config.JWTClaimMappings {
		if mapping.Claim == "" || mapping.Path == "" {
			continue
		}
		if _, reserved := reservedClaimDestinationPaths[mapping.Path]; reserved {
			a.logger.ErrorContext(ctx,
				"refusing to write JWT claim to reserved audit path",
				slog.String("claim", mapping.Claim),
				slog.String("path", mapping.Path),
			)
			continue
		}

		value := internaldotnotation.Get(claimsMap, mapping.Claim)
		if value == nil {
			continue
		}

		if err := internaldotnotation.Set(entry, mapping.Path, normalizeAuditValue(value)); err != nil {
			a.logger.ErrorContext(ctx,
				"failed to apply JWT claim mapping to audit log",
				slog.String("claim", mapping.Claim),
				slog.String("path", mapping.Path),
				slog.Any("error", err),
			)
		}
	}
}

func getOrCreateMapAtPath(root map[string]any, path string) (map[string]any, error) {
	if path == "" {
		return root, nil
	}

	current := internaldotnotation.Get(root, path)
	if current == nil {
		if err := internaldotnotation.Set(root, path, map[string]any{}); err != nil {
			return nil, err
		}
		current = internaldotnotation.Get(root, path)
	}

	converted, ok := normalizeAuditValue(current).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("path [%s] does not resolve to an object", path)
	}

	if err := internaldotnotation.Set(root, path, converted); err != nil {
		return nil, err
	}
	return converted, nil
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

	rv := reflect.ValueOf(value)
	//nolint:exhaustive // only composite kinds need normalization; scalars can pass through unchanged
	switch rv.Kind() {
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

func stringifyJWTClaimValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		normalized := normalizeAuditValue(typed)
		encoded, err := json.Marshal(normalized)
		if err != nil {
			return fmt.Sprintf("%v", normalized)
		}
		return string(encoded)
	}
}
