package access

import (
	"context"
	"fmt"
	"slices"
	"strings"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/proto"
)

const (
	maxRequestPolicyCacheEntries     = 8
	maxRequestResolutionCacheEntries = 32
)

type resolutionCacheKey struct {
	messageType     string
	request         string
	skipEnvironment bool
}

type requestReuse struct {
	policies    map[string]*PolicyDecisionPoint
	resolutions map[resolutionCacheKey][]*entityresolutionV2.EntityRepresentation
}

// WithRequestReuse returns a PDP for sequential subrequests within one bulk RPC.
// Its bounded memo tables must never be shared across RPCs or caller contexts.
func (p *JustInTimePDP) WithRequestReuse() *JustInTimePDP {
	scoped := *p
	scoped.reuse = &requestReuse{policies: make(map[string]*PolicyDecisionPoint), resolutions: make(map[resolutionCacheKey][]*entityresolutionV2.EntityRepresentation)}
	return &scoped
}

func (p *JustInTimePDP) buildInnerPDP(ctx context.Context, fqns []string) (*PolicyDecisionPoint, error) {
	if p.reuse == nil || p.fullPolicyPDP != nil {
		return p.buildInnerPDPUncached(ctx, fqns)
	}
	normalized := make([]string, len(fqns))
	for i, fqn := range fqns {
		normalized[i] = strings.ToLower(fqn)
	}
	slices.Sort(normalized)
	normalized = slices.Compact(normalized)
	encoded, err := proto.Marshal(&attrs.GetEntitleableAttributesByFqnsRequest{Fqns: normalized})
	if err != nil {
		return nil, fmt.Errorf("encode policy lookup: %w", err)
	}
	key := string(encoded)
	if cached, ok := p.reuse.policies[key]; ok {
		return cached, nil
	}
	pdp, err := p.buildInnerPDPUncached(ctx, normalized)
	if err == nil && len(p.reuse.policies) < maxRequestPolicyCacheEntries {
		p.reuse.policies[key] = pdp
	}
	return pdp, err
}

func (p *JustInTimePDP) reuseResolution(request proto.Message, skipEnvironment bool, resolve func() ([]*entityresolutionV2.EntityRepresentation, error)) ([]*entityresolutionV2.EntityRepresentation, error) {
	if p.reuse == nil {
		return resolve()
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode entity resolution request: %w", err)
	}
	key := resolutionCacheKey{messageType: string(request.ProtoReflect().Descriptor().FullName()), request: string(encoded), skipEnvironment: skipEnvironment}
	if cached, ok := p.reuse.resolutions[key]; ok {
		return cached, nil
	}
	representations, err := resolve()
	if err == nil && len(p.reuse.resolutions) < maxRequestResolutionCacheEntries {
		p.reuse.resolutions[key] = representations
	}
	return representations, err
}

func (p *JustInTimePDP) resolveEntitiesFromEntityChain(ctx context.Context, chain *entity.EntityChain, skipEnvironment bool) ([]*entityresolutionV2.EntityRepresentation, error) {
	return p.reuseResolution(chain, skipEnvironment, func() ([]*entityresolutionV2.EntityRepresentation, error) {
		return p.resolveEntitiesFromEntityChainUncached(ctx, chain, skipEnvironment)
	})
}

func (p *JustInTimePDP) resolveEntitiesFromToken(ctx context.Context, token *entity.Token, skipEnvironment bool, resources []*authzV2.Resource) ([]*entityresolutionV2.EntityRepresentation, error) {
	request := &entityresolutionV2.CreateEntityChainsFromTokensRequest{Tokens: []*entity.Token{token}, Resources: resources}
	return p.reuseResolution(request, skipEnvironment, func() ([]*entityresolutionV2.EntityRepresentation, error) {
		return p.resolveEntitiesFromTokenUncached(ctx, token, skipEnvironment, resources)
	})
}
