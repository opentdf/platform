package filestore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Store is a read-only, in-memory snapshot of policy objects loaded from a
// Schema. It is safe for concurrent reads; the data is built once and never
// mutated after construction.
type Store struct {
	namespaces          []*policy.Namespace
	namespacesByName    map[string]*policy.Namespace
	attributes          []*policy.Attribute
	attributesByFQN     map[string]*policy.Attribute
	valuesByFQN         map[string]*policy.Value
	subjectMappings     []*policy.SubjectMapping
	resourceMappings    []*policy.ResourceMapping
	keyAccessServers    []*policy.KeyAccessServer
	kasByID             map[string]*policy.KeyAccessServer
	kasByURI            map[string]*policy.KeyAccessServer
	registeredResources []*policy.RegisteredResource
	obligations         []*policy.Obligation
}

// NewStore builds an in-memory store from the supplied schema. Validation is
// performed eagerly so configuration errors surface at startup, not on the
// first request.
func NewStore(s *Schema) (*Store, error) {
	if s == nil {
		return nil, errors.New("filestore: nil schema")
	}
	b := &builder{
		schema:           s,
		namespacesByName: map[string]*policy.Namespace{},
		attributesByFQN:  map[string]*policy.Attribute{},
		valuesByFQN:      map[string]*policy.Value{},
		kasByID:          map[string]*policy.KeyAccessServer{},
		kasByURI:         map[string]*policy.KeyAccessServer{},
		scsByID:          map[string]*policy.SubjectConditionSet{},
	}
	return b.build()
}

// NewStoreFromFile is a convenience for the common case of loading the schema
// from disk and constructing a Store in a single call.
func NewStoreFromFile(path string) (*Store, error) {
	schema, err := LoadSchema(path)
	if err != nil {
		return nil, err
	}
	return NewStore(schema)
}

// IsEnabled reports whether this store can serve entitlement policy data. A
// nil receiver returns false so callers may safely use the zero value.
func (s *Store) IsEnabled() bool { return s != nil }

// IsReady is true whenever the store is enabled — data is loaded eagerly at
// construction so there is no asynchronous warm-up phase.
func (s *Store) IsReady(_ context.Context) bool { return s.IsEnabled() }

// All accessors return freshly-cloned proto objects: callers (notably the v1
// entitlement and v2 PDP code paths) mutate the returned values to attach
// subject mappings, which would otherwise close reference cycles into the
// store's shared state.

// cloneAs returns a typed clone of the given proto message. proto.Clone is
// documented to preserve the runtime type, so the assertion is infallible —
// but linters require the two-return form, so we go through this helper to
// keep call sites readable.
func cloneAs[T proto.Message](src T) T {
	cloned, _ := proto.Clone(src).(T)
	return cloned
}

func (s *Store) ListAllAttributes(_ context.Context) ([]*policy.Attribute, error) {
	out := make([]*policy.Attribute, len(s.attributes))
	for i, a := range s.attributes {
		out[i] = cloneAs(a)
	}
	return out, nil
}

func (s *Store) ListAllSubjectMappings(_ context.Context) ([]*policy.SubjectMapping, error) {
	out := make([]*policy.SubjectMapping, len(s.subjectMappings))
	for i, sm := range s.subjectMappings {
		out[i] = cloneAs(sm)
	}
	return out, nil
}

func (s *Store) ListAllRegisteredResources(_ context.Context) ([]*policy.RegisteredResource, error) {
	out := make([]*policy.RegisteredResource, len(s.registeredResources))
	for i, r := range s.registeredResources {
		out[i] = cloneAs(r)
	}
	return out, nil
}

func (s *Store) ListAllObligations(_ context.Context) ([]*policy.Obligation, error) {
	out := make([]*policy.Obligation, len(s.obligations))
	for i, o := range s.obligations {
		out[i] = cloneAs(o)
	}
	return out, nil
}

// ListActiveAttributes returns only attributes whose Active wrapper is true or
// unset. The authorization endpoints filter on active state when querying
// upstream; we honour the same default here.
func (s *Store) ListActiveAttributes(_ context.Context) ([]*policy.Attribute, error) {
	out := make([]*policy.Attribute, 0, len(s.attributes))
	for _, a := range s.attributes {
		if a.GetActive() == nil || a.GetActive().GetValue() {
			out = append(out, cloneAs(a))
		}
	}
	return out, nil
}

// GetAttributeValuesByFqns returns the attribute-and-value pairs for each
// requested FQN. Missing entries are omitted, mirroring the policy service.
// Values returned here intentionally carry no Attribute back-reference; use
// AttributeForValueFQN to resolve the definition.
func (s *Store) GetAttributeValuesByFqns(_ context.Context, fqns []string) (map[string]*policy.Value, error) {
	out := make(map[string]*policy.Value, len(fqns))
	for _, raw := range fqns {
		fqn := strings.ToLower(raw)
		if v, ok := s.valuesByFQN[fqn]; ok {
			out[fqn] = cloneAs(v)
		}
	}
	return out, nil
}

// AttributeForValueFQN returns the attribute definition that owns the given
// value FQN, or nil if the value is unknown.
func (s *Store) AttributeForValueFQN(valueFQN string) *policy.Attribute {
	normalized := strings.ToLower(valueFQN)
	if _, ok := s.valuesByFQN[normalized]; !ok {
		return nil
	}
	// strip "/value/<value>" to recover the attribute FQN
	idx := strings.LastIndex(normalized, "/value/")
	if idx < 0 {
		return nil
	}
	a, ok := s.attributesByFQN[normalized[:idx]]
	if !ok {
		return nil
	}
	return cloneAs(a)
}

// MatchSubjectMappings replicates the policy service's "liberal" matcher: any
// subject mapping whose condition set references one of the requested external
// selector values is returned (as a fresh clone).
func (s *Store) MatchSubjectMappings(_ context.Context, properties []*policy.SubjectProperty) ([]*policy.SubjectMapping, error) {
	wanted := make(map[string]struct{}, len(properties))
	for _, p := range properties {
		if sel := p.GetExternalSelectorValue(); sel != "" {
			wanted[sel] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	out := make([]*policy.SubjectMapping, 0)
	for _, sm := range s.subjectMappings {
		if subjectMappingMatches(sm, wanted) {
			out = append(out, cloneAs(sm))
		}
	}
	return out, nil
}

func subjectMappingMatches(sm *policy.SubjectMapping, wanted map[string]struct{}) bool {
	for _, set := range sm.GetSubjectConditionSet().GetSubjectSets() {
		for _, grp := range set.GetConditionGroups() {
			for _, cond := range grp.GetConditions() {
				if _, ok := wanted[cond.GetSubjectExternalSelectorValue()]; ok {
					return true
				}
			}
		}
	}
	return false
}

type builder struct {
	schema           *Schema
	namespaces       []*policy.Namespace
	namespacesByName map[string]*policy.Namespace
	attributes       []*policy.Attribute
	attributesByFQN  map[string]*policy.Attribute
	valuesByFQN      map[string]*policy.Value
	subjectMappings  []*policy.SubjectMapping
	resourceMappings []*policy.ResourceMapping
	kas              []*policy.KeyAccessServer
	kasByID          map[string]*policy.KeyAccessServer
	kasByURI         map[string]*policy.KeyAccessServer
	scsByID          map[string]*policy.SubjectConditionSet
	registered       []*policy.RegisteredResource
	obligations      []*policy.Obligation
}

func (b *builder) build() (*Store, error) {
	b.buildKAS()
	b.buildNamespaces()
	if err := b.buildAttributes(); err != nil {
		return nil, err
	}
	if err := b.buildSubjectConditionSets(); err != nil {
		return nil, err
	}
	if err := b.buildSubjectMappings(); err != nil {
		return nil, err
	}
	b.buildResourceMappings()
	if err := b.buildRegisteredResources(); err != nil {
		return nil, err
	}
	if err := b.buildObligations(); err != nil {
		return nil, err
	}

	return &Store{
		namespaces:          b.namespaces,
		namespacesByName:    b.namespacesByName,
		attributes:          b.attributes,
		attributesByFQN:     b.attributesByFQN,
		valuesByFQN:         b.valuesByFQN,
		subjectMappings:     b.subjectMappings,
		resourceMappings:    b.resourceMappings,
		keyAccessServers:    b.kas,
		kasByID:             b.kasByID,
		kasByURI:            b.kasByURI,
		registeredResources: b.registered,
		obligations:         b.obligations,
	}, nil
}

func (b *builder) buildKAS() {
	for i := range b.schema.KeyAccessServers {
		def := b.schema.KeyAccessServers[i]
		kas := &policy.KeyAccessServer{
			Id:   nonEmpty(def.ID, def.URI),
			Uri:  def.URI,
			Name: def.Name,
		}
		b.kas = append(b.kas, kas)
		if kas.GetId() != "" {
			b.kasByID[kas.GetId()] = kas
		}
		if kas.GetUri() != "" {
			b.kasByURI[kas.GetUri()] = kas
		}
	}
}

func (b *builder) buildNamespaces() {
	for i := range b.schema.Namespaces {
		def := b.schema.Namespaces[i]
		fqn := def.FQN
		if fqn == "" {
			fqn = "https://" + def.Name
		}
		ns := &policy.Namespace{
			Id:     nonEmpty(def.ID, fqn),
			Name:   def.Name,
			Fqn:    fqn,
			Active: wrapperspb.Bool(true),
		}
		b.namespaces = append(b.namespaces, ns)
		if def.Name != "" {
			b.namespacesByName[strings.ToLower(def.Name)] = ns
		}
	}
}

func (b *builder) buildAttributes() error {
	for i := range b.schema.Attributes {
		def := b.schema.Attributes[i]
		ns, ok := b.namespacesByName[strings.ToLower(def.Namespace)]
		if !ok {
			return fmt.Errorf("filestore: attribute %q references unknown namespace %q", def.Name, def.Namespace)
		}
		rule, err := parseAttributeRule(def.Rule)
		if err != nil {
			return fmt.Errorf("filestore: attribute %q/%q: %w", def.Namespace, def.Name, err)
		}
		attrFQN := strings.ToLower(ns.GetFqn() + "/attr/" + def.Name)
		attr := &policy.Attribute{
			Id:        nonEmpty(def.ID, attrFQN),
			Namespace: ns,
			Name:      def.Name,
			Rule:      rule,
			Fqn:       attrFQN,
			Active:    wrapperspb.Bool(true),
			Grants:    b.resolveKAS(def.Grants),
		}
		values := make([]*policy.Value, 0, len(def.Values))
		for _, v := range def.Values {
			vFQN := strings.ToLower(attrFQN + "/value/" + v.Value)
			value := &policy.Value{
				Id:     nonEmpty(v.ID, vFQN),
				Value:  v.Value,
				Fqn:    vFQN,
				Active: wrapperspb.Bool(true),
				Grants: b.resolveKAS(v.Grants),
			}
			values = append(values, value)
			b.valuesByFQN[vFQN] = value
		}
		attr.Values = values
		// Intentionally do not back-reference Attribute on each Value: it
		// produces a cycle (Attribute → Values → Value → Attribute) that
		// breaks protojson marshalers (e.g. v1's OpaInput). Consumers that
		// need the definition use the top-level Attribute field on the
		// wrapping AttributeAndValue response instead.
		b.attributes = append(b.attributes, attr)
		b.attributesByFQN[attrFQN] = attr
	}
	return nil
}

func (b *builder) buildSubjectConditionSets() error {
	for i := range b.schema.SubjectConditionSets {
		def := b.schema.SubjectConditionSets[i]
		if def.ID == "" {
			return fmt.Errorf("filestore: subject_condition_set at index %d missing id", i)
		}
		scs, err := convertSCS(def.ID, def.SubjectSets)
		if err != nil {
			return fmt.Errorf("filestore: subject_condition_set %q: %w", def.ID, err)
		}
		b.scsByID[def.ID] = scs
	}
	return nil
}

func (b *builder) buildSubjectMappings() error {
	for i := range b.schema.SubjectMappings {
		def := b.schema.SubjectMappings[i]
		valFQN := strings.ToLower(def.AttributeValueFQN)
		value, ok := b.valuesByFQN[valFQN]
		if !ok {
			return fmt.Errorf("filestore: subject_mapping at index %d references unknown attribute_value_fqn %q", i, def.AttributeValueFQN)
		}
		var scs *policy.SubjectConditionSet
		switch {
		case def.InlineConditionSet != nil:
			id := def.SubjectConditionSet
			if id == "" {
				id = fmt.Sprintf("sm-%d-scs", i)
			}
			built, err := convertSCS(id, def.InlineConditionSet.SubjectSets)
			if err != nil {
				return fmt.Errorf("filestore: subject_mapping at index %d: %w", i, err)
			}
			scs = built
		case def.SubjectConditionSet != "":
			ref, refOK := b.scsByID[def.SubjectConditionSet]
			if !refOK {
				return fmt.Errorf("filestore: subject_mapping at index %d references unknown subject_condition_set %q", i, def.SubjectConditionSet)
			}
			scs = ref
		default:
			return fmt.Errorf("filestore: subject_mapping at index %d must reference a subject_condition_set or define one inline", i)
		}
		actions, err := convertActions(def.Actions)
		if err != nil {
			return fmt.Errorf("filestore: subject_mapping at index %d: %w", i, err)
		}
		sm := &policy.SubjectMapping{
			Id:                  nonEmpty(def.ID, fmt.Sprintf("sm-%d", i)),
			AttributeValue:      value,
			SubjectConditionSet: scs,
			Actions:             actions,
		}
		b.subjectMappings = append(b.subjectMappings, sm)
		// Intentionally do not back-reference SubjectMappings on Value: the
		// v1 entitlements path populates the field locally from a lookup,
		// and the v2 PDP builds its own attribute index. Setting it here
		// would close a cycle (Value → SubjectMappings → SubjectMapping →
		// AttributeValue → Value) that breaks protojson serializers.
	}
	return nil
}

func (b *builder) buildResourceMappings() {
	for i := range b.schema.ResourceMappings {
		def := b.schema.ResourceMappings[i]
		value, ok := b.valuesByFQN[strings.ToLower(def.AttributeValueFQN)]
		if !ok {
			// Unknown value mappings are ignored, matching DB behaviour for stale rows.
			continue
		}
		rm := &policy.ResourceMapping{
			Id:             nonEmpty(def.ID, fmt.Sprintf("rm-%d", i)),
			AttributeValue: value,
			Terms:          def.Terms,
		}
		b.resourceMappings = append(b.resourceMappings, rm)
	}
}

func (b *builder) buildRegisteredResources() error {
	for i := range b.schema.RegisteredResources {
		def := b.schema.RegisteredResources[i]
		if def.Name == "" {
			return fmt.Errorf("filestore: registered_resource at index %d missing name", i)
		}
		var ns *policy.Namespace
		if def.Namespace != "" {
			ns = b.namespacesByName[strings.ToLower(def.Namespace)]
			if ns == nil {
				return fmt.Errorf("filestore: registered_resource %q references unknown namespace %q", def.Name, def.Namespace)
			}
		}
		rr := &policy.RegisteredResource{
			Id:        nonEmpty(def.ID, def.Name),
			Name:      def.Name,
			Namespace: ns,
		}
		for vIdx, v := range def.Values {
			if v.Value == "" {
				return fmt.Errorf("filestore: registered_resource %q value at index %d missing value", def.Name, vIdx)
			}
			fqn := v.FQN
			if fqn == "" {
				fqn = registeredResourceValueFQN(ns, def.Name, v.Value)
			}
			rrv := &policy.RegisteredResourceValue{
				Id:    nonEmpty(v.ID, fqn),
				Value: v.Value,
				Fqn:   fqn,
			}
			for aIdx, aav := range v.ActionAttributeValues {
				if aav.Action == "" {
					return fmt.Errorf("filestore: registered_resource %q value %q action_attribute_value at index %d missing action", def.Name, v.Value, aIdx)
				}
				attrVal := b.valuesByFQN[strings.ToLower(aav.AttributeValueFQN)]
				if attrVal == nil {
					return fmt.Errorf("filestore: registered_resource %q value %q action_attribute_value at index %d references unknown attribute_value_fqn %q",
						def.Name, v.Value, aIdx, aav.AttributeValueFQN)
				}
				rrv.ActionAttributeValues = append(rrv.ActionAttributeValues, &policy.RegisteredResourceValue_ActionAttributeValue{
					Id:             nonEmpty(aav.ID, fmt.Sprintf("%s-aav-%d", rrv.GetId(), aIdx)),
					Action:         &policy.Action{Name: aav.Action},
					AttributeValue: attrVal,
				})
			}
			rr.Values = append(rr.Values, rrv)
		}
		b.registered = append(b.registered, rr)
	}
	return nil
}

func (b *builder) buildObligations() error {
	for i := range b.schema.Obligations {
		def := b.schema.Obligations[i]
		if def.Name == "" {
			return fmt.Errorf("filestore: obligation at index %d missing name", i)
		}
		if def.Namespace == "" {
			return fmt.Errorf("filestore: obligation %q missing namespace", def.Name)
		}
		ns := b.namespacesByName[strings.ToLower(def.Namespace)]
		if ns == nil {
			return fmt.Errorf("filestore: obligation %q references unknown namespace %q", def.Name, def.Namespace)
		}
		oblFQN := strings.ToLower(ns.GetFqn() + "/obl/" + def.Name)
		ob := &policy.Obligation{
			Id:        nonEmpty(def.ID, oblFQN),
			Name:      def.Name,
			Namespace: ns,
		}
		for vIdx, v := range def.Values {
			if v.Value == "" {
				return fmt.Errorf("filestore: obligation %q value at index %d missing value", def.Name, vIdx)
			}
			valFQN := v.FQN
			if valFQN == "" {
				valFQN = strings.ToLower(oblFQN + "/value/" + v.Value)
			}
			ov := &policy.ObligationValue{
				Id:    nonEmpty(v.ID, valFQN),
				Value: v.Value,
				Fqn:   valFQN,
			}
			for tIdx, t := range v.Triggers {
				if t.AttributeValueFQN == "" {
					return fmt.Errorf("filestore: obligation %q value %q trigger at index %d missing attribute_value_fqn",
						def.Name, v.Value, tIdx)
				}
				if t.Action == "" {
					return fmt.Errorf("filestore: obligation %q value %q trigger at index %d missing action",
						def.Name, v.Value, tIdx)
				}
				attrVal := b.valuesByFQN[strings.ToLower(t.AttributeValueFQN)]
				if attrVal == nil {
					return fmt.Errorf("filestore: obligation %q value %q trigger at index %d references unknown attribute_value_fqn %q",
						def.Name, v.Value, tIdx, t.AttributeValueFQN)
				}
				// Intentionally do not set ObligationValue back-reference on
				// the trigger: it would close a cycle (ObligationValue →
				// Triggers → ObligationTrigger → ObligationValue) that breaks
				// proto.Clone. The obligations PDP reads obligationValue.GetFqn()
				// from the parent loop variable, not via this back-pointer.
				trigger := &policy.ObligationTrigger{
					Id:             nonEmpty(t.ID, fmt.Sprintf("%s-trigger-%d", ov.GetId(), tIdx)),
					Action:         &policy.Action{Name: t.Action},
					AttributeValue: attrVal,
					Namespace:      ns,
				}
				for _, c := range t.Context {
					if c.PEPClientID == "" {
						return fmt.Errorf("filestore: obligation %q value %q trigger at index %d has empty pep_client_id context",
							def.Name, v.Value, tIdx)
					}
					trigger.Context = append(trigger.Context, &policy.RequestContext{
						Pep: &policy.PolicyEnforcementPoint{ClientId: c.PEPClientID},
					})
				}
				ov.Triggers = append(ov.Triggers, trigger)
			}
			ob.Values = append(ob.Values, ov)
		}
		b.obligations = append(b.obligations, ob)
	}
	return nil
}

// registeredResourceValueFQN builds the FQN format expected by the v2 PDP.
// When namespace is empty the value uses the legacy form https://reg_res/...
func registeredResourceValueFQN(ns *policy.Namespace, resourceName, value string) string {
	if ns == nil || ns.GetName() == "" {
		return strings.ToLower("https://reg_res/" + resourceName + "/value/" + value)
	}
	return strings.ToLower("https://" + ns.GetName() + "/reg_res/" + resourceName + "/value/" + value)
}

func (b *builder) resolveKAS(refs []KasReferenceD) []*policy.KeyAccessServer {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*policy.KeyAccessServer, 0, len(refs))
	for _, r := range refs {
		switch {
		case r.ID != "" && b.kasByID[r.ID] != nil:
			out = append(out, b.kasByID[r.ID])
		case r.URI != "" && b.kasByURI[r.URI] != nil:
			out = append(out, b.kasByURI[r.URI])
		case r.URI != "":
			// Inline KAS reference that wasn't declared globally.
			kas := &policy.KeyAccessServer{Id: nonEmpty(r.ID, r.URI), Uri: r.URI}
			b.kasByURI[r.URI] = kas
			out = append(out, kas)
		}
	}
	return out
}

func convertSCS(id string, sets []SubjectSetDef) (*policy.SubjectConditionSet, error) {
	scs := &policy.SubjectConditionSet{Id: id}
	for _, set := range sets {
		ss := &policy.SubjectSet{}
		for _, grp := range set.ConditionGroups {
			op, err := parseBooleanOperator(grp.BooleanOperator)
			if err != nil {
				return nil, err
			}
			cg := &policy.ConditionGroup{BooleanOperator: op}
			for _, cond := range grp.Conditions {
				operator, err := parseSubjectOperator(cond.Operator)
				if err != nil {
					return nil, err
				}
				cg.Conditions = append(cg.Conditions, &policy.Condition{
					SubjectExternalSelectorValue: cond.SubjectExternalSelectorValue,
					Operator:                     operator,
					SubjectExternalValues:        cond.SubjectExternalValues,
				})
			}
			ss.ConditionGroups = append(ss.ConditionGroups, cg)
		}
		scs.SubjectSets = append(scs.SubjectSets, ss)
	}
	return scs, nil
}

func convertActions(refs []ActionRef) ([]*policy.Action, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	out := make([]*policy.Action, 0, len(refs))
	for _, r := range refs {
		a := &policy.Action{Name: r.Name}
		if r.Standard != "" {
			std, err := parseStandardAction(r.Standard)
			if err != nil {
				return nil, err
			}
			// policy.Action.Value is deprecated; the rest of the codebase still uses
			// it pending the action-name migration (DECRYPT→"read", TRANSMIT→"create").
			a.Value = &policy.Action_Standard{Standard: std} //nolint:staticcheck // deprecated proto field still used across codebase
		}
		out = append(out, a)
	}
	return out, nil
}

func parseAttributeRule(s string) (policy.AttributeRuleTypeEnum, error) {
	switch strings.ToLower(s) {
	case "", "anyof", "any_of":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, nil
	case "allof", "all_of":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, nil
	case "hierarchy":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, nil
	default:
		return 0, fmt.Errorf("unknown attribute rule %q (expected allOf|anyOf|hierarchy)", s)
	}
}

func parseBooleanOperator(s string) (policy.ConditionBooleanTypeEnum, error) {
	switch strings.ToUpper(s) {
	case "", "AND":
		return policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND, nil
	case "OR":
		return policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR, nil
	default:
		return 0, fmt.Errorf("unknown boolean_operator %q (expected AND|OR)", s)
	}
}

func parseSubjectOperator(s string) (policy.SubjectMappingOperatorEnum, error) {
	switch strings.ToUpper(s) {
	case "", "IN":
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, nil
	case "NOT_IN", "NOTIN":
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN, nil
	case "IN_CONTAINS", "INCONTAINS":
		return policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS, nil
	default:
		return 0, fmt.Errorf("unknown subject mapping operator %q", s)
	}
}

func parseStandardAction(s string) (policy.Action_StandardAction, error) {
	switch strings.ToUpper(s) {
	case "TRANSMIT", "STANDARD_ACTION_TRANSMIT":
		return policy.Action_STANDARD_ACTION_TRANSMIT, nil
	case "DECRYPT", "STANDARD_ACTION_DECRYPT":
		return policy.Action_STANDARD_ACTION_DECRYPT, nil
	default:
		return 0, fmt.Errorf("unknown standard action %q", s)
	}
}

func nonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
