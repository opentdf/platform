package attributes

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	attributeDefinitions int64
}

func (s objectLimitCounterStub) CountAttributeDefinitions(context.Context, string) (int64, error) {
	return s.attributeDefinitions, nil
}

func (objectLimitCounterStub) CountAttributeValues(context.Context, string) (int64, error) {
	return 0, nil
}

func (objectLimitCounterStub) CountObligationTriggersForAttributeDefinition(context.Context, string) (policydb.PolicyObjectCount, error) {
	return policydb.PolicyObjectCount{}, nil
}

func Test_EnforceCreateAttributeLimits_AttributeDefinitionAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &AttributesService{config: &policyconfig.Config{ObjectLimits: policyconfig.ObjectLimits{AttributeDefinitions: 10}}}
	err := service.enforceCreateAttributeLimits(t.Context(), objectLimitCounterStub{attributeDefinitions: 10}, &attributes.CreateAttributeRequest{NamespaceId: "tenant-id"})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
