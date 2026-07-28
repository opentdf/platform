package cukes

import (
	"context"
	"errors"
	"fmt"
	"text/template"

	"github.com/cucumber/godog"
	"gopkg.in/yaml.v2"
)

const ersConfigKey = "ers_inline_config"

type ERSInlineConfig struct {
	Mode            string
	FailureStrategy string
	Providers       map[string]ERSProviderConfig
	Strategies      []ERSMappingStrategyConfig
}

type ERSProviderConfig struct {
	Type         string
	AutoWireLDAP bool
}

type ERSMappingStrategyConfig struct {
	Name     string
	Provider string
	RawYAML  string
}

type ERSStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
	PlatformSteps        *LocalPlatformStepDefinitions
}

func getERSConfig(sc *PlatformScenarioContext) (*ERSInlineConfig, error) {
	obj := sc.GetObject(ersConfigKey)
	if obj == nil {
		return nil, errors.New("no ERS configuration found; use 'an ERS configuration' step first")
	}
	cfg, ok := obj.(*ERSInlineConfig)
	if !ok {
		return nil, errors.New("invalid ERS configuration object")
	}
	return cfg, nil
}

func (s *ERSStepDefinitions) anERSConfiguration(ctx context.Context, mode string, failureStrategy string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cfg := &ERSInlineConfig{
		Mode:            mode,
		FailureStrategy: failureStrategy,
		Providers:       make(map[string]ERSProviderConfig),
	}
	scenarioContext.RecordObject(ersConfigKey, cfg)
	return ctx, nil
}

func (s *ERSStepDefinitions) anERSProvider(ctx context.Context, name string, providerType string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cfg, err := getERSConfig(scenarioContext)
	if err != nil {
		return ctx, err
	}
	cfg.Providers[name] = ERSProviderConfig{Type: providerType}
	return ctx, nil
}

func (s *ERSStepDefinitions) anERSProviderConnectedToLDAP(ctx context.Context, name string, providerType string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cfg, err := getERSConfig(scenarioContext)
	if err != nil {
		return ctx, err
	}
	cfg.Providers[name] = ERSProviderConfig{
		Type:         providerType,
		AutoWireLDAP: true,
	}
	return ctx, nil
}

func (s *ERSStepDefinitions) anERSMappingStrategy(ctx context.Context, name string, provider string, doc *godog.DocString) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cfg, err := getERSConfig(scenarioContext)
	if err != nil {
		return ctx, err
	}
	cfg.Strategies = append(cfg.Strategies, ERSMappingStrategyConfig{
		Name:     name,
		Provider: provider,
		RawYAML:  doc.Content,
	})
	return ctx, nil
}

func (s *ERSStepDefinitions) aLocalPlatformWithInlineERSConfiguration(ctx context.Context) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cfg, err := getERSConfig(scenarioContext)
	if err != nil {
		return ctx, err
	}
	kt := template.Must(template.New("kc").Parse(keycloakBaseTemplate))
	return s.PlatformSteps.commonLocalPlatform(ctx, &platformStartOptions{
		kcProvisionPath: kt,
		ersConfig:       cfg,
	})
}

func buildEntityResolutionConfig(cfg *ERSInlineConfig, hostname string, ldapPort int) (map[string]interface{}, error) {
	providers := map[string]interface{}{}
	for name, p := range cfg.Providers {
		provider := map[string]interface{}{
			"type": p.Type,
		}
		if p.AutoWireLDAP {
			provider["connection"] = map[string]interface{}{
				"host":          hostname,
				"port":          ldapPort,
				"use_tls":       false,
				"bind_dn":       "cn=admin,dc=opentdf,dc=test",
				"bind_password": "admin123",
			}
		} else {
			provider["connection"] = map[string]interface{}{}
		}
		providers[name] = provider
	}

	var strategies []interface{}
	for _, s := range cfg.Strategies {
		var rawStrategy map[interface{}]interface{}
		if err := yaml.Unmarshal([]byte(s.RawYAML), &rawStrategy); err != nil {
			return nil, fmt.Errorf("failed to parse mapping strategy %q YAML: %w", s.Name, err)
		}
		strategy := map[string]interface{}{
			"name":     s.Name,
			"provider": s.Provider,
		}
		for k, v := range rawStrategy {
			strategy[fmt.Sprintf("%v", k)] = v
		}
		strategies = append(strategies, strategy)
	}

	return map[string]interface{}{
		"mode":               cfg.Mode,
		"failure_strategy":   cfg.FailureStrategy,
		"providers":          providers,
		"mapping_strategies": strategies,
	}, nil
}

func RegisterERSStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	steps := &ERSStepDefinitions{
		PlatformCukesContext: x,
		PlatformSteps:        &LocalPlatformStepDefinitions{PlatformCukesContext: x},
	}
	ctx.Step(`^an ERS configuration with mode "([^"]*)" and failure strategy "([^"]*)"$`, steps.anERSConfiguration)
	ctx.Step(`^an ERS provider "([^"]*)" of type "([^"]*)"$`, steps.anERSProvider)
	ctx.Step(`^an ERS provider "([^"]*)" of type "([^"]*)" connected to the LDAP directory$`, steps.anERSProviderConnectedToLDAP)
	ctx.Step(`^an ERS mapping strategy "([^"]*)" using provider "([^"]*)"$`, steps.anERSMappingStrategy)
	ctx.Step(`^a local platform with inline ERS configuration$`, steps.aLocalPlatformWithInlineERSConfiguration)
}
