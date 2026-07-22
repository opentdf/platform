package cukes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/entity"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type DirectEntitlementsStepDefinitions struct{}

const (
	directEntitlementColumnAttributeFQN = "attribute_value_fqn"
	directEntitlementColumnActions      = "actions"
)

// thereIsAClaimsSubjectEntityReferencedAsWithDirectEntitlements records a claims subject entity
// whose claims carry direct_entitlements, so the claims ERS (with allow_direct_entitlements) emits
// them on the entity representation for the PDP.
func (s *DirectEntitlementsStepDefinitions) thereIsAClaimsSubjectEntityReferencedAsWithDirectEntitlements(ctx context.Context, referenceID string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	directEntitlements, err := parseDirectEntitlementsTable(tbl)
	if err != nil {
		return ctx, err
	}

	claims := map[string]interface{}{
		"direct_entitlements": directEntitlements,
	}
	structClaims, err := structpb.NewStruct(claims)
	if err != nil {
		return ctx, err
	}
	anyClaims, err := anypb.New(structClaims)
	if err != nil {
		return ctx, err
	}

	subjectEntity := &entity.Entity{
		EphemeralId: referenceID,
		Category:    entity.Entity_CATEGORY_SUBJECT,
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
	}
	scenarioContext.RecordObject(referenceID, subjectEntity)
	return ctx, nil
}

// iAddClaimsToSubjectEntityWith merges additional claims into an existing claims subject entity so a
// subject mapping can also apply alongside direct entitlements.
func (s *DirectEntitlementsStepDefinitions) iAddClaimsToSubjectEntityWith(ctx context.Context, referenceID string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	entityObj, ok := scenarioContext.GetObject(referenceID).(*entity.Entity)
	if !ok || entityObj == nil {
		return ctx, fmt.Errorf("entity %s not found or invalid type", referenceID)
	}
	if entityObj.GetClaims() == nil {
		return ctx, errors.New("entity does not contain claims")
	}

	claimsStruct := &structpb.Struct{}
	if err := entityObj.GetClaims().UnmarshalTo(claimsStruct); err != nil {
		return ctx, err
	}
	claimsMap := claimsStruct.AsMap()

	updates, err := parseClaimsTable(tbl)
	if err != nil {
		return ctx, err
	}
	for key, value := range updates {
		claimsMap[key] = value
	}

	updatedStruct, err := structpb.NewStruct(claimsMap)
	if err != nil {
		return ctx, err
	}
	anyClaims, err := anypb.New(updatedStruct)
	if err != nil {
		return ctx, err
	}

	entityObj.EntityType = &entity.Entity_Claims{Claims: anyClaims}
	scenarioContext.RecordObject(referenceID, entityObj)
	return ctx, nil
}

func parseDirectEntitlementsTable(tbl *godog.Table) ([]interface{}, error) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return nil, errors.New("direct entitlements table is empty")
	}

	cellMap := map[string]int{}
	for ci, cell := range tbl.Rows[0].Cells {
		cellMap[cell.Value] = ci
	}

	attrIdx, ok := cellMap[directEntitlementColumnAttributeFQN]
	if !ok {
		return nil, fmt.Errorf("direct entitlements table requires column %s", directEntitlementColumnAttributeFQN)
	}
	actionsIdx, ok := cellMap[directEntitlementColumnActions]
	if !ok {
		return nil, fmt.Errorf("direct entitlements table requires column %s", directEntitlementColumnActions)
	}

	out := make([]interface{}, 0, len(tbl.Rows)-1)
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue
		}
		attrFQN := strings.TrimSpace(row.Cells[attrIdx].Value)
		if attrFQN == "" {
			return nil, errors.New("direct entitlements require attribute_value_fqn values")
		}

		rawActions := ""
		if actionsIdx < len(row.Cells) {
			rawActions = row.Cells[actionsIdx].Value
		}
		actions := make([]interface{}, 0)
		for _, action := range strings.Split(rawActions, ",") {
			action = strings.TrimSpace(action)
			if action == "" {
				continue
			}
			actions = append(actions, strings.ToLower(action))
		}
		if len(actions) == 0 {
			return nil, fmt.Errorf("direct entitlement for %s requires actions", attrFQN)
		}

		out = append(out, map[string]interface{}{
			"attribute_value_fqn": attrFQN,
			"actions":             actions,
		})
	}

	if len(out) == 0 {
		return nil, errors.New("direct entitlements table has no rows")
	}

	return out, nil
}

func parseClaimsTable(tbl *godog.Table) (map[string]interface{}, error) {
	if tbl == nil || len(tbl.Rows) == 0 {
		return nil, errors.New("claims table is empty")
	}

	cellMap := map[string]int{}
	for ci, cell := range tbl.Rows[0].Cells {
		cellMap[cell.Value] = ci
	}

	nameIdx, ok := cellMap["name"]
	if !ok {
		return nil, errors.New("claims table requires column name")
	}
	valueIdx, ok := cellMap["value"]
	if !ok {
		return nil, errors.New("claims table requires column value")
	}

	out := map[string]interface{}{}
	for ri, row := range tbl.Rows {
		if ri == 0 {
			continue
		}
		key := strings.TrimSpace(row.Cells[nameIdx].Value)
		if key == "" {
			return nil, errors.New("claims table requires name values")
		}
		rawValue := ""
		if valueIdx < len(row.Cells) {
			rawValue = strings.TrimSpace(row.Cells[valueIdx].Value)
		}

		var parsed interface{}
		if rawValue != "" {
			if err := json.Unmarshal([]byte(rawValue), &parsed); err != nil {
				parsed = rawValue
			}
		}
		out[key] = parsed
	}

	return out, nil
}

func RegisterDirectEntitlementsStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := &DirectEntitlementsStepDefinitions{}
	ctx.Step(`^there is a claims subject entity referenced as "([^"]*)" with direct entitlements:$`, stepDefinitions.thereIsAClaimsSubjectEntityReferencedAsWithDirectEntitlements)
	ctx.Step(`^I add claims to subject entity "([^"]*)" with:$`, stepDefinitions.iAddClaimsToSubjectEntityWith)
}
