package cukes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
)

const (
	bddKasPublicKeyCtx    = `YS1wZW0K`
	expectedKASKeyColumns = 2
	listKASKeysResponse   = "listKASKeysResponse"
)

type KasRegistryStepDefinitions struct{}

func (s *KasRegistryStepDefinitions) iCreateKASKeys(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	for i, row := range tbl.Rows {
		if i == 0 {
			continue
		}
		if len(row.Cells) < expectedKASKeyColumns {
			return ctx, errors.New("expected kas_uri and key_id columns")
		}

		kasURI := normalizeKASURI(row.Cells[0].Value)
		keyID := row.Cells[1].Value

		kasResp, err := scenarioContext.SDK.KeyAccessServerRegistry.CreateKeyAccessServer(ctx, &kasregistry.CreateKeyAccessServerRequest{
			Uri:        kasURI,
			Name:       keyID,
			SourceType: policy.SourceType_SOURCE_TYPE_EXTERNAL,
		})
		scenarioContext.SetError(err)
		if err != nil {
			return ctx, err
		}
		if kasResp == nil || kasResp.GetKeyAccessServer() == nil {
			return ctx, fmt.Errorf("create KAS response was nil for %q", keyID)
		}

		keyResp, err := scenarioContext.SDK.KeyAccessServerRegistry.CreateKey(ctx, &kasregistry.CreateKeyRequest{
			KasId:        kasResp.GetKeyAccessServer().GetId(),
			KeyId:        keyID,
			KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
			KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
			PublicKeyCtx: &policy.PublicKeyCtx{
				Pem: bddKasPublicKeyCtx,
			},
		})
		scenarioContext.SetError(err)
		if err != nil {
			return ctx, err
		}
		if keyResp == nil || keyResp.GetKasKey() == nil || keyResp.GetKasKey().GetKey() == nil {
			return ctx, fmt.Errorf("create KAS key response was nil for %q", keyID)
		}

		scenarioContext.RecordObject(keyID, keyResp.GetKasKey().GetKey().GetId())
		scenarioContext.RecordObject(keyID+"_kas_uri", kasURI)
		scenarioContext.RecordObject(keyID+"_kas_id", kasResp.GetKeyAccessServer().GetId())
	}

	return ctx, nil
}

func (s *KasRegistryStepDefinitions) iGetKASKey(ctx context.Context, keyID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	kasURI, ok := scenarioContext.GetObject(keyID + "_kas_uri").(string)
	if !ok {
		return ctx, fmt.Errorf("unable to extract KAS URI for %q", keyID)
	}

	scenarioContext.ClearError()
	_, err := scenarioContext.SDK.KeyAccessServerRegistry.GetKey(ctx, &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{Uri: kasURI},
				Kid:        keyID,
			},
		},
	})
	scenarioContext.SetError(err)
	return ctx, nil
}

func (s *KasRegistryStepDefinitions) iGetKASKeyByStoredID(ctx context.Context, keyID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	storedID, ok := scenarioContext.GetObject(keyID).(string)
	if !ok {
		return ctx, fmt.Errorf("unable to extract stored KAS key ID for %q", keyID)
	}

	scenarioContext.ClearError()
	_, err := scenarioContext.SDK.KeyAccessServerRegistry.GetKey(ctx, &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: storedID},
	})
	scenarioContext.SetError(err)
	return ctx, nil
}

func (s *KasRegistryStepDefinitions) iListKASKeys(ctx context.Context) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	resp, err := scenarioContext.SDK.KeyAccessServerRegistry.ListKeys(ctx, &kasregistry.ListKeysRequest{})
	scenarioContext.SetError(err)
	if resp != nil {
		scenarioContext.RecordObject(listKASKeysResponse, resp)
	}

	return ctx, nil
}

func (s *KasRegistryStepDefinitions) iListKASKeysForURI(ctx context.Context, kasURI string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	resp, err := scenarioContext.SDK.KeyAccessServerRegistry.ListKeys(ctx, &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{KasUri: normalizeKASURI(kasURI)},
	})
	scenarioContext.SetError(err)
	if resp != nil {
		scenarioContext.RecordObject(listKASKeysResponse, resp)
	}

	return ctx, nil
}

func (s *KasRegistryStepDefinitions) iListKASKeysByStoredKASID(ctx context.Context, keyID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	kasID, ok := scenarioContext.GetObject(keyID + "_kas_id").(string)
	if !ok {
		return ctx, fmt.Errorf("unable to extract stored KAS ID for %q", keyID)
	}

	scenarioContext.ClearError()
	resp, err := scenarioContext.SDK.KeyAccessServerRegistry.ListKeys(ctx, &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{KasId: kasID},
	})
	scenarioContext.SetError(err)
	if resp != nil {
		scenarioContext.RecordObject(listKASKeysResponse, resp)
	}

	return ctx, nil
}

func (s *KasRegistryStepDefinitions) listedKASKeysContain(ctx context.Context, keyIDs string) error {
	resp, err := getListKASKeysResponse(ctx)
	if err != nil {
		return err
	}

	listed := listedKASKeyIDs(resp)
	for _, keyID := range splitKASKeyIDs(keyIDs) {
		if _, ok := listed[keyID]; !ok {
			return fmt.Errorf("listed KAS keys did not contain %q", keyID)
		}
	}

	return nil
}

func (s *KasRegistryStepDefinitions) listedKASKeysContainOnly(ctx context.Context, keyIDs string) error {
	resp, err := getListKASKeysResponse(ctx)
	if err != nil {
		return err
	}

	expected := splitKASKeyIDs(keyIDs)
	listed := listedKASKeyIDs(resp)
	if len(listed) != len(expected) {
		return fmt.Errorf("expected %d listed KAS keys, got %d", len(expected), len(listed))
	}

	for _, keyID := range expected {
		if _, ok := listed[keyID]; !ok {
			return fmt.Errorf("listed KAS keys did not contain %q", keyID)
		}
	}

	return nil
}

func normalizeKASURI(uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	return "https://" + uri
}

func getListKASKeysResponse(ctx context.Context) (*kasregistry.ListKeysResponse, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	resp, ok := scenarioContext.GetObject(listKASKeysResponse).(*kasregistry.ListKeysResponse)
	if !ok || resp == nil {
		return nil, errors.New("list KAS keys response was not recorded")
	}
	return resp, nil
}

func listedKASKeyIDs(resp *kasregistry.ListKeysResponse) map[string]struct{} {
	keyIDs := make(map[string]struct{}, len(resp.GetKasKeys()))
	for _, kasKey := range resp.GetKasKeys() {
		keyID := kasKey.GetKey().GetKeyId()
		if keyID != "" {
			keyIDs[keyID] = struct{}{}
		}
	}
	return keyIDs
}

func splitKASKeyIDs(keyIDs string) []string {
	parts := strings.Split(keyIDs, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func RegisterKasRegistryStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := KasRegistryStepDefinitions{}
	ctx.Step(`^I create KAS keys:$`, stepDefinitions.iCreateKASKeys)
	ctx.Step(`^I send a request to get KAS key "([^"]*)"$`, stepDefinitions.iGetKASKey)
	ctx.Step(`^I send a request to get KAS key "([^"]*)" by stored ID$`, stepDefinitions.iGetKASKeyByStoredID)
	ctx.Step(`^I send a request to list KAS keys$`, stepDefinitions.iListKASKeys)
	ctx.Step(`^I send a request to list KAS keys for KAS URI "([^"]*)"$`, stepDefinitions.iListKASKeysForURI)
	ctx.Step(`^I send a request to list KAS keys for KAS key "([^"]*)" by stored KAS ID$`, stepDefinitions.iListKASKeysByStoredKASID)
	ctx.Step(`^the listed KAS keys should contain "([^"]*)"$`, stepDefinitions.listedKASKeysContain)
	ctx.Step(`^the listed KAS keys should contain only "([^"]*)"$`, stepDefinitions.listedKASKeysContainOnly)
}
