package filestore_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
)

const integrationPolicyYAML = `
namespaces:
  - name: example.com
attributes:
  - namespace: example.com
    name: classification
    rule: hierarchy
    values:
      - value: topsecret
      - value: secret
      - value: public
subject_mappings:
  - attribute_value_fqn: https://example.com/attr/classification/value/topsecret
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .roles
                  operator: IN
                  subject_external_values: [topsecret-cleared]
    actions:
      - name: read
registered_resources:
  - namespace: example.com
    name: laptop
    values:
      - value: corp
        action_attribute_values:
          - action: read
            attribute_value_fqn: https://example.com/attr/classification/value/secret
obligations:
  - namespace: example.com
    name: watermark
    values:
      - value: required
        triggers:
          - attribute_value_fqn: https://example.com/attr/classification/value/topsecret
            action: read
          - attribute_value_fqn: https://example.com/attr/classification/value/secret
            action: read
            context:
              - pep_client_id: pep-alpha
`

// Loads the snapshot and feeds it through the real v2 PDP constructors. A
// successful build proves the file-store output is shape-compatible with the
// decisioning code — every trigger/AAV reference resolved, no proto cycles
// killing proto.Clone, the obligation trigger graph populated.
func TestFileStoreFeedsV2PDPs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(integrationPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := filestore.NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewStoreFromFile: %v", err)
	}
	ctx := context.Background()
	log := logger.CreateTestLogger()

	allAttrs, err := store.ListAllAttributes(ctx)
	if err != nil {
		t.Fatalf("ListAllAttributes: %v", err)
	}
	allSMs, err := store.ListAllSubjectMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllSubjectMappings: %v", err)
	}
	allRRs, err := store.ListAllRegisteredResources(ctx)
	if err != nil {
		t.Fatalf("ListAllRegisteredResources: %v", err)
	}
	allObls, err := store.ListAllObligations(ctx)
	if err != nil {
		t.Fatalf("ListAllObligations: %v", err)
	}

	pdp, err := access.NewPolicyDecisionPoint(ctx, log, allAttrs, allSMs, allRRs, false, false)
	if err != nil {
		t.Fatalf("NewPolicyDecisionPoint: %v", err)
	}
	if pdp == nil {
		t.Fatal("nil PDP")
	}

	// The obligations PDP iterates every trigger during construction; if any
	// reference were malformed it would return an error here.
	attrsByFQN := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{}
	for _, a := range allAttrs {
		for _, v := range a.GetValues() {
			attrsByFQN[v.GetFqn()] = &attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				Attribute: a,
				Value:     v,
			}
		}
	}
	rrByFQN := map[string]*policy.RegisteredResourceValue{}
	for _, rr := range allRRs {
		for _, v := range rr.GetValues() {
			rrByFQN[v.GetFqn()] = v
		}
	}
	oblPDP, err := obligations.NewObligationsPolicyDecisionPoint(ctx, log, attrsByFQN, rrByFQN, allObls)
	if err != nil {
		t.Fatalf("NewObligationsPolicyDecisionPoint: %v", err)
	}
	if oblPDP == nil {
		t.Fatal("nil obligations PDP")
	}
}
