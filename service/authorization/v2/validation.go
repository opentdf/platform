package authorization

import (
	"fmt"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
)

func (as *Service) validateGetDecisionRequest(request *authzV2.GetDecisionRequest) error {
	if err := as.validateEntityIdentifierRequestLimits(request.GetEntityIdentifier(), "entity_identifier"); err != nil {
		return err
	}
	if err := as.validateResourceRequestLimits(request.GetResource(), "resource"); err != nil {
		return err
	}
	return as.validateFulfillableObligationRequestLimits(request.GetFulfillableObligationFqns(), "fulfillable_obligation_fqns")
}

func (as *Service) validateGetDecisionMultiResourceRequest(request *authzV2.GetDecisionMultiResourceRequest, prefix string) error {
	if err := as.validateEntityIdentifierRequestLimits(request.GetEntityIdentifier(), prefix+"entity_identifier"); err != nil {
		return err
	}

	resources := request.GetResources()
	if len(resources) > as.config.RequestLimits.MultiResourceRequestMax {
		return limitExceededError(prefix+"resources", len(resources), as.config.RequestLimits.MultiResourceRequestMax)
	}
	for idx, resource := range resources {
		if err := as.validateResourceRequestLimits(resource, fmt.Sprintf("%sresources[%d]", prefix, idx)); err != nil {
			return err
		}
	}

	return as.validateFulfillableObligationRequestLimits(request.GetFulfillableObligationFqns(), prefix+"fulfillable_obligation_fqns")
}

func (as *Service) validateGetDecisionBulkRequest(request *authzV2.GetDecisionBulkRequest) error {
	decisionRequests := request.GetDecisionRequests()
	if len(decisionRequests) > as.config.RequestLimits.BulkDecisionRequestMax {
		return limitExceededError("decision_requests", len(decisionRequests), as.config.RequestLimits.BulkDecisionRequestMax)
	}

	for idx, decisionRequest := range decisionRequests {
		if err := as.validateGetDecisionMultiResourceRequest(decisionRequest, fmt.Sprintf("decision_requests[%d].", idx)); err != nil {
			return err
		}
	}

	return nil
}

func (as *Service) validateEntityIdentifierRequestLimits(entityIdentifier *authzV2.EntityIdentifier, path string) error {
	entityChain := entityIdentifier.GetEntityChain()
	if entityChain == nil {
		return nil
	}

	entities := entityChain.GetEntities()
	if len(entities) > as.config.RequestLimits.EntityChainEntitiesMax {
		return limitExceededError(path+".entity_chain.entities", len(entities), as.config.RequestLimits.EntityChainEntitiesMax)
	}

	return nil
}

func (as *Service) validateResourceRequestLimits(resource *authzV2.Resource, path string) error {
	attributeValues := resource.GetAttributeValues()
	if attributeValues == nil {
		return nil
	}

	fqns := attributeValues.GetFqns()
	if len(fqns) > as.config.RequestLimits.ResourceAttributeValuesMax {
		return limitExceededError(path+".attribute_values.fqns", len(fqns), as.config.RequestLimits.ResourceAttributeValuesMax)
	}

	return nil
}

func (as *Service) validateFulfillableObligationRequestLimits(fqns []string, path string) error {
	if len(fqns) > as.config.RequestLimits.FulfillableObligationFqnsMax {
		return limitExceededError(path, len(fqns), as.config.RequestLimits.FulfillableObligationFqnsMax)
	}

	return nil
}

func limitExceededError(path string, got int, limit int) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s exceeds maximum count: got %d, max %d", path, got, limit))
}
