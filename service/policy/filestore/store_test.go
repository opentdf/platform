package filestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
)

const samplePolicyYAML = `
namespaces:
  - name: example.com
key_access_servers:
  - id: kas1
    uri: https://kas.example.com
attributes:
  - namespace: example.com
    name: classification
    rule: hierarchy
    grants:
      - id: kas1
    values:
      - value: topsecret
      - value: secret
      - value: public
  - namespace: example.com
    name: dept
    rule: anyOf
    values:
      - value: eng
      - value: sales
subject_mappings:
  - attribute_value_fqn: https://example.com/attr/classification/value/topsecret
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .realm_access.roles
                  operator: IN
                  subject_external_values: [topsecret-cleared]
    actions:
      - name: read
        standard: TRANSMIT
registered_resources:
  - namespace: example.com
    name: laptop
    values:
      - value: corp
        action_attribute_values:
          - action: read
            attribute_value_fqn: https://example.com/attr/dept/value/eng
          - action: create
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

func TestStore_LoadAndQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(samplePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewStoreFromFile: %v", err)
	}
	ctx := context.Background()

	attrs, err := store.ListAllAttributes(ctx)
	if err != nil {
		t.Fatalf("ListAllAttributes: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("want 2 attributes, got %d", len(attrs))
	}
	if attrs[0].GetFqn() != "https://example.com/attr/classification" {
		t.Fatalf("attribute fqn mismatch: %q", attrs[0].GetFqn())
	}
	if attrs[0].GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		t.Fatalf("expected hierarchy rule, got %v", attrs[0].GetRule())
	}
	if len(attrs[0].GetValues()) != 3 {
		t.Fatalf("want 3 values, got %d", len(attrs[0].GetValues()))
	}
	if len(attrs[0].GetGrants()) != 1 || attrs[0].GetGrants()[0].GetUri() != "https://kas.example.com" {
		t.Fatalf("kas grant not resolved: %+v", attrs[0].GetGrants())
	}

	sms, err := store.ListAllSubjectMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllSubjectMappings: %v", err)
	}
	if len(sms) != 1 {
		t.Fatalf("want 1 subject mapping, got %d", len(sms))
	}

	vals, err := store.GetAttributeValuesByFqns(ctx, []string{"https://example.com/attr/classification/value/secret"})
	if err != nil {
		t.Fatalf("GetAttributeValuesByFqns: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("want 1 value, got %d", len(vals))
	}

	matched, err := store.MatchSubjectMappings(ctx, []*policy.SubjectProperty{
		{ExternalSelectorValue: ".realm_access.roles"},
	})
	if err != nil {
		t.Fatalf("MatchSubjectMappings: %v", err)
	}
	if len(matched) != 1 {
		t.Fatalf("expected 1 matched subject mapping, got %d", len(matched))
	}
	if matched[0].GetAttributeValue().GetFqn() != "https://example.com/attr/classification/value/topsecret" {
		t.Fatalf("matched wrong attribute value: %q", matched[0].GetAttributeValue().GetFqn())
	}

	noMatch, err := store.MatchSubjectMappings(ctx, []*policy.SubjectProperty{
		{ExternalSelectorValue: ".other"},
	})
	if err != nil {
		t.Fatalf("MatchSubjectMappings no-match: %v", err)
	}
	if len(noMatch) != 0 {
		t.Fatalf("expected 0 matched subject mappings, got %d", len(noMatch))
	}
}

func TestStore_RegisteredResourcesWithActionAttributeValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(samplePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewStoreFromFile: %v", err)
	}
	regs, err := store.ListAllRegisteredResources(context.Background())
	if err != nil {
		t.Fatalf("ListAllRegisteredResources: %v", err)
	}
	if len(regs) != 1 {
		t.Fatalf("want 1 registered resource, got %d", len(regs))
	}
	rr := regs[0]
	if rr.GetName() != "laptop" {
		t.Fatalf("registered resource name mismatch: %q", rr.GetName())
	}
	if rr.GetNamespace().GetName() != "example.com" {
		t.Fatalf("registered resource namespace not resolved: %+v", rr.GetNamespace())
	}
	if len(rr.GetValues()) != 1 {
		t.Fatalf("want 1 value, got %d", len(rr.GetValues()))
	}
	v := rr.GetValues()[0]
	if v.GetFqn() != "https://example.com/reg_res/laptop/value/corp" {
		t.Fatalf("registered resource value FQN mismatch: %q", v.GetFqn())
	}
	if len(v.GetActionAttributeValues()) != 2 {
		t.Fatalf("want 2 action_attribute_values, got %d", len(v.GetActionAttributeValues()))
	}
	aav0 := v.GetActionAttributeValues()[0]
	if aav0.GetAction().GetName() != "read" {
		t.Fatalf("first AAV action mismatch: %q", aav0.GetAction().GetName())
	}
	if aav0.GetAttributeValue().GetFqn() != "https://example.com/attr/dept/value/eng" {
		t.Fatalf("first AAV attribute_value_fqn mismatch: %q", aav0.GetAttributeValue().GetFqn())
	}
}

func TestStore_ObligationsWithTriggers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(samplePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewStoreFromFile: %v", err)
	}
	obs, err := store.ListAllObligations(context.Background())
	if err != nil {
		t.Fatalf("ListAllObligations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("want 1 obligation, got %d", len(obs))
	}
	ob := obs[0]
	if ob.GetName() != "watermark" {
		t.Fatalf("obligation name mismatch: %q", ob.GetName())
	}
	if ob.GetNamespace().GetName() != "example.com" {
		t.Fatalf("obligation namespace not resolved: %+v", ob.GetNamespace())
	}
	if len(ob.GetValues()) != 1 {
		t.Fatalf("want 1 value, got %d", len(ob.GetValues()))
	}
	ov := ob.GetValues()[0]
	if ov.GetFqn() != "https://example.com/obl/watermark/value/required" {
		t.Fatalf("obligation value FQN mismatch: %q", ov.GetFqn())
	}
	if len(ov.GetTriggers()) != 2 {
		t.Fatalf("want 2 triggers, got %d", len(ov.GetTriggers()))
	}
	t0 := ov.GetTriggers()[0]
	if t0.GetAction().GetName() != "read" {
		t.Fatalf("trigger 0 action mismatch: %q", t0.GetAction().GetName())
	}
	if t0.GetAttributeValue().GetFqn() != "https://example.com/attr/classification/value/topsecret" {
		t.Fatalf("trigger 0 attribute_value mismatch: %q", t0.GetAttributeValue().GetFqn())
	}
	if len(t0.GetContext()) != 0 {
		t.Fatalf("trigger 0 unexpected context: %+v", t0.GetContext())
	}
	t1 := ov.GetTriggers()[1]
	if len(t1.GetContext()) != 1 {
		t.Fatalf("trigger 1 want 1 context, got %d", len(t1.GetContext()))
	}
	if t1.GetContext()[0].GetPep().GetClientId() != "pep-alpha" {
		t.Fatalf("trigger 1 PEP client_id mismatch: %q", t1.GetContext()[0].GetPep().GetClientId())
	}
}

func TestStore_RejectsUnknownAttributeReferences(t *testing.T) {
	cases := map[string]string{
		"registered resource AAV": `
namespaces: [{name: example.com}]
attributes:
  - {namespace: example.com, name: a, rule: anyOf, values: [{value: v1}]}
registered_resources:
  - {namespace: example.com, name: r, values: [{value: x, action_attribute_values: [{action: read, attribute_value_fqn: https://example.com/attr/a/value/nope}]}]}
`,
		"obligation trigger": `
namespaces: [{name: example.com}]
attributes:
  - {namespace: example.com, name: a, rule: anyOf, values: [{value: v1}]}
obligations:
  - {namespace: example.com, name: o, values: [{value: x, triggers: [{action: read, attribute_value_fqn: https://example.com/attr/a/value/nope}]}]}
`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStoreFromFile(path); err == nil {
				t.Fatal("expected error for unknown attribute value reference, got nil")
			}
		})
	}
}
