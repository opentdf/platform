package multistrategy

import (
	"context"
	"errors"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestMultiStrategyService_JWT_Claims_Provider(t *testing.T) {
	// Test configuration with JWT claims provider
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				InputMapping: []types.InputMapping{},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
					{
						SourceClaim: "email",
						ClaimName:   "email_address",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with JWT claims in context
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"aud":   "test-audience",
	})

	// Resolve entity
	result, err := service.ResolveEntity(ctx, "user123", types.JWTClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"aud":   "test-audience",
	})
	if err != nil {
		t.Fatalf("Failed to resolve entity: %v", err)
	}

	// Verify result
	if result.OriginalID != "user123" {
		t.Errorf("Expected OriginalID 'user123', got '%s'", result.OriginalID)
	}

	// Check mapped claims
	if result.Claims["subject"] != "user123" {
		t.Errorf("Expected subject 'user123', got '%v'", result.Claims["subject"])
	}

	if result.Claims["email_address"] != "user@example.com" {
		t.Errorf("Expected email_address 'user@example.com', got '%v'", result.Claims["email_address"])
	}

	// Check metadata
	if result.Metadata["provider_type"] != "claims" {
		t.Errorf("Expected provider_type 'claims', got '%v'", result.Metadata["provider_type"])
	}
}

func TestMultiStrategyService_No_Matching_Strategy(t *testing.T) {
	// Test configuration with strict conditions
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:     "strict_strategy",
				Provider: "jwt",
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "equals",
							Values:   []string{"specific-audience"},
						},
					},
				},
				InputMapping:  []types.InputMapping{},
				OutputMapping: []types.OutputMapping{},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with JWT claims that don't match strategy conditions
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "different-audience", // This won't match the strategy condition
	})

	// Should get a "no matching strategy" error
	if err == nil {
		t.Fatal("Expected error for no matching strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}

func TestMultiStrategyService_Provider_Not_Found(t *testing.T) {
	// Test configuration with invalid provider reference
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:     "invalid_strategy",
				Provider: "nonexistent_provider", // Provider doesn't exist
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				InputMapping:  []types.InputMapping{},
				OutputMapping: []types.OutputMapping{},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with valid JWT claims
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"aud": "test-audience",
	})

	// Should get a "provider not found" error
	if err == nil {
		t.Fatal("Expected error for provider not found, but got none")
	}

	var providerErr *types.MultiStrategyError
	if !errors.As(err, &providerErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	// The error could be either ErrorTypeProvider (if caught in executeStrategy)
	// or ErrorTypeStrategy (if caught in ResolveEntity loop)
	if providerErr.Type != types.ErrorTypeProvider && providerErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeProvider or ErrorTypeStrategy, got %v", providerErr.Type)
	}
}

func TestMultiStrategyService_FailureStrategyContinue(t *testing.T) {
	// Test configuration with global continue strategy where first fails, second succeeds
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue, // Global continue policy
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
			"good_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "failing_strategy",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
			{
				Name:       "success_strategy",
				Provider:   "good_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the bad provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	result, err := service.ResolveEntity(ctx, "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})
	if err != nil {
		t.Fatalf("Expected success with fallback strategy, got error: %v", err)
	}

	// Verify the second strategy was used
	if result.Metadata["strategy_name"] != "success_strategy" {
		t.Errorf("Expected strategy_name 'success_strategy', got '%v'", result.Metadata["strategy_name"])
	}

	// Verify entity type metadata
	if result.Metadata["entity_type"] != types.EntityTypeSubject {
		t.Errorf("Expected entity_type '%s', got '%v'", types.EntityTypeSubject, result.Metadata["entity_type"])
	}

	// Verify attempted strategies metadata
	attemptedStrategies, ok := result.Metadata["attempted_strategies"].([]string)
	if !ok || len(attemptedStrategies) != 2 {
		t.Errorf("Expected attempted_strategies to contain 2 strategies, got %v", result.Metadata["attempted_strategies"])
	}
}

func TestMultiStrategyService_FailureStrategyFailFast(t *testing.T) {
	// Test configuration with global fail-fast strategy
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyFailFast, // Global fail-fast policy
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "failing_strategy",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	// Should fail immediately
	if err == nil {
		t.Fatal("Expected error with fail-fast strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}

func TestMultiStrategyService_EntityTypeEnvironment(t *testing.T) {
	// Test configuration with environment entity type
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"env_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "environment_strategy",
				Provider:   "env_provider",
				EntityType: types.EntityTypeEnvironment, // Environment entity
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "client_ip",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "client_ip",
						ClaimName:   "source_ip",
					},
					{
						SourceClaim: "device_id",
						ClaimName:   "device_identifier",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Test with environment context
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"client_ip": "192.168.1.100",
		"device_id": "device-abc-123",
	})

	result, err := service.ResolveEntity(ctx, "env123", types.JWTClaims{
		"client_ip": "192.168.1.100",
		"device_id": "device-abc-123",
	})
	if err != nil {
		t.Fatalf("Failed to resolve environment entity: %v", err)
	}

	// Verify entity type metadata
	if result.Metadata["entity_type"] != types.EntityTypeEnvironment {
		t.Errorf("Expected entity_type '%s', got '%v'", types.EntityTypeEnvironment, result.Metadata["entity_type"])
	}

	// Check mapped claims
	if result.Claims["source_ip"] != "192.168.1.100" {
		t.Errorf("Expected source_ip '192.168.1.100', got '%v'", result.Claims["source_ip"])
	}

	if result.Claims["device_identifier"] != "device-abc-123" {
		t.Errorf("Expected device_identifier 'device-abc-123', got '%v'", result.Claims["device_identifier"])
	}
}

func TestMultiStrategyService_DefaultFailureStrategy(t *testing.T) {
	// Test that empty global failure_strategy defaults to fail-fast
	config := types.MultiStrategyConfig{
		// FailureStrategy not set - should default to fail-fast
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "strategy_no_failure_setting",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	// Should fail immediately (default fail-fast behavior)
	if err == nil {
		t.Fatal("Expected error with default fail-fast strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}

// TestResolveEntity_MetadataIsStructpbSerializable is the type-hygiene
// contract test called out in spec item 1: every value the multi-strategy
// service writes into EntityResult.Metadata on the success path MUST be
// acceptable to structpb.NewValue, because the v2 ResolveEntities handler
// passes the whole map through structpb.NewStruct. Any value that trips
// "proto: invalid type: T" causes the handler to silently drop the entity
// via `continue`, so this contract is what keeps the class of bug shut.
func TestResolveEntity_MetadataIsStructpbSerializable(t *testing.T) {
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "aud", Operator: "exists"},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "sub", ClaimName: "subject"},
				},
			},
		},
	}

	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	claims := types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	}
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, claims)
	result, err := service.ResolveEntity(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("Failed to resolve entity: %v", err)
	}

	for key, value := range result.Metadata {
		if _, err := structpb.NewValue(value); err != nil {
			t.Errorf("metadata key %q holds a value structpb.NewValue rejects: %v (type %T)", key, err, value)
		}
	}
}

// TestResolveEntity_AttemptedStrategiesStructpbSerializable is spec item 2:
// on the success path, result.Metadata["attempted_strategies"] must be a
// value structpb.NewValue accepts. A raw []string does not qualify — only
// []interface{}. This test asserts the specific field so a regression here
// is unmistakable in the failure output.
func TestResolveEntity_AttemptedStrategiesStructpbSerializable(t *testing.T) {
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{Claim: "aud", Operator: "exists"},
					},
				},
				OutputMapping: []types.OutputMapping{
					{SourceClaim: "sub", ClaimName: "subject"},
				},
			},
		},
	}

	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	claims := types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	}
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, claims)
	result, err := service.ResolveEntity(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("Failed to resolve entity: %v", err)
	}

	if _, err := structpb.NewValue(result.Metadata["attempted_strategies"]); err != nil {
		t.Fatalf("attempted_strategies must be structpb.NewValue-compatible, got error %v for type %T", err, result.Metadata["attempted_strategies"])
	}
}

// TestResolveEntity_AttemptedStrategiesAccumulatesAcrossContinue is spec
// item 3: with FailureStrategyContinue and earlier strategies erroring,
// attempted_strategies must accumulate every attempted name AND remain
// structpb-serializable. Guards against a fix that only handles the
// single-strategy success path.
func TestResolveEntity_AttemptedStrategiesAccumulatesAcrossContinue(t *testing.T) {
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue,
		Providers: map[string]types.ProviderConfig{
			"bad_provider_1": {Type: "claims", Connection: map[string]interface{}{}},
			"bad_provider_2": {Type: "claims", Connection: map[string]interface{}{}},
			"good_provider":  {Type: "claims", Connection: map[string]interface{}{}},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "failing_strategy_1",
				Provider:   "bad_provider_1",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{{Claim: "aud", Operator: "exists"}},
				},
				OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "subject"}},
			},
			{
				Name:       "failing_strategy_2",
				Provider:   "bad_provider_2",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{{Claim: "aud", Operator: "exists"}},
				},
				OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "subject"}},
			},
			{
				Name:       "success_strategy",
				Provider:   "good_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{{Claim: "aud", Operator: "exists"}},
				},
				OutputMapping: []types.OutputMapping{{SourceClaim: "sub", ClaimName: "subject"}},
			},
		},
	}

	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Delete the two bad providers so their strategies error and the loop
	// hits the `continue` path before the good provider succeeds.
	_ = service.providerRegistry.providers["bad_provider_1"].Close()
	delete(service.providerRegistry.providers, "bad_provider_1")
	_ = service.providerRegistry.providers["bad_provider_2"].Close()
	delete(service.providerRegistry.providers, "bad_provider_2")

	claims := types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	}
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, claims)
	result, err := service.ResolveEntity(ctx, "user123", claims)
	if err != nil {
		t.Fatalf("Expected success with fallback strategy, got error: %v", err)
	}

	value, err := structpb.NewValue(result.Metadata["attempted_strategies"])
	if err != nil {
		t.Fatalf("attempted_strategies must be structpb.NewValue-compatible, got error %v for type %T", err, result.Metadata["attempted_strategies"])
	}

	list := value.GetListValue()
	if list == nil {
		t.Fatalf("attempted_strategies must serialize to a ListValue, got %T", value.GetKind())
	}
	if got, want := len(list.GetValues()), 3; got != want {
		t.Fatalf("attempted_strategies length = %d, want %d", got, want)
	}
}
