// Package dynamicentitlement is a SPIKE / proof-of-concept for entitling dynamic
// attribute values at the AttributeDefinition level, exploring DSPX-2754.
//
// It is NOT wired into any live decision path. It exists to evaluate, with working
// code and tests, the options the architecture team deferred to an implementation
// spike in the dynamic-attribute-value ADR (virtru-corp/adr#266):
//
//   - reuse the existing SubjectMapping / SubjectConditionSet primitive,
//   - introduce a new primitive (DefinitionValueEntitlementMapping),
//   - introduce a new attribute rule, or
//   - introduce a new comparison operator.
//
// # The problem
//
// Today, entitling a highly dynamic / high-cardinality value (medical record numbers,
// account IDs, emails) means duplicating every value as an AttributeValue plus a
// per-value SubjectMapping + SubjectConditionSet, kept constantly in sync with an
// external system of record. The ADR proposes raising the condition-set authority up
// to the AttributeDefinition so one mapping (selector + operator + actions) resolves
// entitlement to concrete value FQNs dynamically.
//
// # The shared mechanic
//
// Existing condition evaluation compares an entity's selector result against a STATIC
// list authored into policy (policy.Condition.subject_external_values; see
// subjectmappingbuiltin.EvaluateCondition). The dynamic case INVERTS this: the
// right-hand operand is the resource's value segment (e.g. "mrn-123" parsed from
// .../value/mrn-123), known only at decision time, tested for membership in the
// entity's selector-resolved set (e.g. .patientAssignments -> ["mrn-123","mrn-789"]).
//
// All four options share that one comparison (see core.go). They differ only in their
// container, schema, and admin UX. This package implements the comparison once and
// wraps it three ways (reuse_subjectmapping.go, new_primitive.go, attribute_rule.go),
// driven by a common entitlement/decision driver (entitle.go), so the trade-offs can
// be compared on real behavior rather than prose.
//
// Findings are summarized in service/policy/adr/0005-dynamic-attribute-value-entitlements-spike.md.
//
// # Out of scope
//
// No proto, codegen, database, sqlc, service-handler, or PDP changes — the ADR states
// primitive names and schema are still subject to change, so persistence/wire plumbing
// would be premature churn. POC-only Go types stand in for would-be proto additions.
package dynamicentitlement
