package access

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	otdfSDK "github.com/opentdf/platform/sdk"
)

// maxEntitleableFQNsPerRequest mirrors the proto max_items limit on
// GetEntitleableAttributesByFqnsRequest.fqns, so batches never exceed what the
// server-side request validation accepts.
const maxEntitleableFQNsPerRequest = 250

// fetchEntitleableAttributes performs targeted GetEntitleableAttributesByFqns lookups for the
// provided attribute value FQNs and returns attribute definitions (with their values populated) plus
// the subject mappings that entitle them, in the shape NewPolicyDecisionPoint consumes.
//
// It mirrors the v1 authorization service's retrieveAttributeDefinitions
// (service/authorization/authorization.go); keep the two in sync. The v1 version returns a
// map[valueFQN]*AttributeAndValue for OPA input, whereas the v2 PDP is built from
// []*policy.Attribute + []*policy.SubjectMapping, so this emits those two slices instead.
//
// Subject mappings are carried ONLY in the returned slice, never on definition.Values[*].
// SubjectMappings: NewPolicyDecisionPoint seeds each value from the definition keeping its
// SubjectMappings and then appends the slice's mappings, so populating both would double-count.
//
// Definitions are registered even when a requested value resolves with an empty identity (a value
// that does not exist under an allow_traversal definition), so the decision path can still
// synthesize direct-entitlement / dynamic-mapping values from the definition. Missing FQNs are
// omitted (not an error): the v2 decision path denies per-resource on unknown FQNs. Empty but
// non-nil slices are returned when nothing resolves, since NewPolicyDecisionPoint rejects nil inputs.
func fetchEntitleableAttributes(
	ctx context.Context,
	sdk *otdfSDK.SDK,
	valueFQNs []string,
) ([]*policy.Attribute, []*policy.SubjectMapping, error) {
	// Normalize + dedupe requested value FQNs to lower case.
	normalizedFQNs := make([]string, 0, len(valueFQNs))
	seen := make(map[string]struct{}, len(valueFQNs))
	for _, fqn := range valueFQNs {
		normalized := strings.ToLower(fqn)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		normalizedFQNs = append(normalizedFQNs, normalized)
	}

	definitionsByFQN := make(map[string]*policy.Attribute)
	// Per-definition set of value FQNs already appended, to dedupe across requested values and batches.
	valuesSeenByDefinition := make(map[string]map[string]struct{})
	// Hierarchy definitions are expanded (ordered siblings + their SMs) exactly once.
	hierarchyExpanded := make(map[string]struct{})
	subjectMappings := make([]*policy.SubjectMapping, 0)

	ensureDefinition := func(definitionFQN string, def *attrs.GetEntitleableAttributesByFqnsResponse_EntitleableDefinition) *policy.Attribute {
		if existing, ok := definitionsByFQN[definitionFQN]; ok {
			return existing
		}
		attribute := &policy.Attribute{
			Fqn:       definitionFQN,
			Namespace: def.GetNamespace(),
			Rule:      def.GetRule(),
		}
		definitionsByFQN[definitionFQN] = attribute
		valuesSeenByDefinition[definitionFQN] = make(map[string]struct{})
		return attribute
	}

	addValue := func(definitionFQN string, attribute *policy.Attribute, valueID, valueFQN string) {
		valuesSeen := valuesSeenByDefinition[definitionFQN]
		if _, ok := valuesSeen[valueFQN]; ok {
			return
		}
		valuesSeen[valueFQN] = struct{}{}
		attribute.Values = append(attribute.Values, &policy.Value{
			Id:  valueID,
			Fqn: valueFQN,
		})
	}

	// process maps one entitleable response for the requested FQNs into the accumulators above.
	process := func(resp *attrs.GetEntitleableAttributesByFqnsResponse, fqns []string) error {
		for _, fqn := range fqns {
			entitleable, ok := resp.GetFqnEntitleableAttributes()[fqn]
			if !ok {
				// FQN not returned at all: omit so the decision path denies per-resource.
				continue
			}

			definitionFQN := entitleable.GetDefinitionFqn()
			def, defOK := resp.GetDefinitions()[definitionFQN]
			if definitionFQN == "" || !defOK || def == nil {
				return fmt.Errorf("entitleable attribute %q references missing definition %q", fqn, definitionFQN)
			}
			// Register the definition regardless of value presence so direct-entitlement / dynamic
			// synthesis can resolve the parent definition for allow_traversal values.
			attribute := ensureDefinition(definitionFQN, def)

			if def.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
				// Hierarchy rule evaluation and comprehensive-hierarchy expansion need the full
				// ordered value set and each value's subject mappings. Expand once per definition.
				if _, done := hierarchyExpanded[definitionFQN]; !done {
					hierarchyExpanded[definitionFQN] = struct{}{}
					for _, sibling := range def.GetValues() {
						if sibling.GetValueId() == "" {
							continue
						}
						addValue(definitionFQN, attribute, sibling.GetValueId(), sibling.GetFqn())
						subjectMappings = append(subjectMappings, sibling.GetSubjectMappings()...)
					}
				}
				continue
			}

			// Non-hierarchy: add the concrete value when present. An empty value identity is an
			// allow_traversal miss; the definition stays registered but no concrete value is added.
			value := entitleable.GetValue()
			if value.GetValueId() == "" {
				continue
			}
			addValue(definitionFQN, attribute, value.GetValueId(), value.GetFqn())
			subjectMappings = append(subjectMappings, value.GetSubjectMappings()...)
		}
		return nil
	}

	getBatch := func(fqns []string) (*attrs.GetEntitleableAttributesByFqnsResponse, error) {
		return sdk.Attributes.GetEntitleableAttributesByFqns(ctx, &attrs.GetEntitleableAttributesByFqnsRequest{Fqns: fqns})
	}

	// fetchOne resolves a single FQN, reporting skip=true when it does not exist in policy.
	fetchOne := func(fqn string) (*attrs.GetEntitleableAttributesByFqnsResponse, bool, error) {
		resp, err := getBatch([]string{fqn})
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("failed to get entitleable attributes by fqns: %w", err)
		}
		return resp, false, nil
	}

	// processBatch resolves a batch, falling back to per-FQN resolution on a batch NotFound. The
	// server rejects the whole batch with NotFound if any requested FQN does not exist, so the retry
	// keeps the values that DO exist and skips the missing ones (denied per-resource downstream). This
	// preserves valid decisions in a multi-resource request that also references an unknown FQN.
	processBatch := func(batch []string) error {
		resp, err := getBatch(batch)
		if err == nil {
			return process(resp, batch)
		}
		if connect.CodeOf(err) != connect.CodeNotFound {
			return fmt.Errorf("failed to get entitleable attributes by fqns: %w", err)
		}
		for _, fqn := range batch {
			single, skip, ferr := fetchOne(fqn)
			if ferr != nil {
				return ferr
			}
			if skip {
				continue
			}
			if perr := process(single, []string{fqn}); perr != nil {
				return perr
			}
		}
		return nil
	}

	for start := 0; start < len(normalizedFQNs); start += maxEntitleableFQNsPerRequest {
		end := min(start+maxEntitleableFQNsPerRequest, len(normalizedFQNs))
		if err := processBatch(normalizedFQNs[start:end]); err != nil {
			return nil, nil, err
		}
	}

	definitions := make([]*policy.Attribute, 0, len(definitionsByFQN))
	for _, def := range definitionsByFQN {
		definitions = append(definitions, def)
	}
	return definitions, subjectMappings, nil
}
