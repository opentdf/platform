package cukes

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
)

const bddKasPublicKeyCtx = `YS1wZW0K`

type KasRegistryStepDefinitions struct{}

func (s *KasRegistryStepDefinitions) iCreateKASKeys(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	for i, row := range tbl.Rows {
		if i == 0 {
			continue
		}
		if len(row.Cells) < 2 {
			return ctx, fmt.Errorf("expected kas_uri and key_id columns")
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

func (s *KasRegistryStepDefinitions) iListKASKeysForURI(ctx context.Context, kasURI string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	_, err := scenarioContext.SDK.KeyAccessServerRegistry.ListKeys(ctx, &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{KasUri: normalizeKASURI(kasURI)},
	})
	scenarioContext.SetError(err)
	return ctx, nil
}

func normalizeKASURI(uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	return "https://" + uri
}

func RegisterKasRegistryStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := KasRegistryStepDefinitions{}
	ctx.Step(`^I create KAS keys:$`, stepDefinitions.iCreateKASKeys)
	ctx.Step(`^I send a request to get KAS key "([^"]*)"$`, stepDefinitions.iGetKASKey)
	ctx.Step(`^I send a request to list KAS keys for URI "([^"]*)"$`, stepDefinitions.iListKASKeysForURI)
}
