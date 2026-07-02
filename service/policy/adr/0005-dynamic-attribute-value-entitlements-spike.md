# Dynamic Attribute Value Entitlement

Entitling highly dynamic, high-cardinality attribute values (medical record numbers, account IDs,
email-like identifiers) is impractical today: each value must be duplicated as an `AttributeValue` and
paired with its own `SubjectMapping` + `SubjectConditionSet`, then kept constantly in sync with an
external system of record. An upstream design ADR
chose a definition-level dynamic entitlement model (its Option 3) but **explicitly deferred to an
implementation spike** the question of *how* to model it. This document records what that spike found.

The original spike prototyped all three options as a throwaway package to make them comparable on real
behavior. The recommendation below (a new primitive carrying a new operator) is now implemented as
production code: the `DynamicValueMapping` primitive
([`service/policy/objects.proto`](../objects.proto)), its dedicated
[`DynamicValueMappingService`](../dynamicvaluemapping), DB layer, and the decision-time evaluator
([`service/internal/subjectmappingbuiltin/dynamic_value_mapping_builtin.go`](../../internal/subjectmappingbuiltin/dynamic_value_mapping_builtin.go))
wired into the PDP. The findings below record why that shape was chosen over the alternatives.

> [!NOTE]
> The upstream ADR named this
> primitive `DefinitionValueEntitlementMapping` but explicitly noted that primitive names are subject to
> change during implementation. It is implemented here as `DynamicValueMapping`, which is shorter, omits
> the redundant "Entitlement" (consistent with `SubjectMapping`/`ResourceMapping`), and avoids overloading
> the authorization-runtime term "entitlement".

## Context

How should condition-set authority be moved up from the `AttributeValue` to the `AttributeDefinition`?
Four shapes were on the table (from the ADR discussion threads): reuse Subject Mappings, add a new
primitive, add a new attribute rule, or add a new operator.

## Recommendation: a new primitive (`DynamicValueMapping`) carrying a new operator

The spike recommends a **new first-class primitive** scoped to an `AttributeDefinition`, holding a
`selector`, a **new dynamic operator**, and `actions`. The four "options" are not mutually exclusive: the
new operator is the shared mechanic *every* shape needs, and the new primitive is the cleanest container
for it. Reuse-of-subject-mappings and a new-attribute-rule were both prototyped and found to carry
avoidable downsides (below).

### Shared Mechanic: comparing against the resource value

Existing condition evaluation compares an entity's selector result against a **static list authored into
policy** (`policy.Condition.subject_external_values`; see
[`subjectmappingbuiltin.EvaluateCondition`](../../internal/subjectmappingbuiltin/subject_mapping_builtin.go)).
The dynamic case supplies a different right-hand operand: the **resource's value segment**
(e.g. `mrn-123`, parsed from `…/value/mrn-123`), known only at decision time, tested for membership in the
entity's selector-resolved set (e.g. `.patientAssignments` → `["mrn-123","mrn-789"]`).

No new operator enum is required for this. `DynamicValueResolver` reuses `SubjectMappingOperatorEnum`:
`IN` matches when the resource segment equals any resolved entity value, and `IN_CONTAINS` matches on
substring containment. The match is inherently existential over the resolved values, so `NOT_IN` is
rejected (a definition-wide "not entitled" has no meaning at decision time). Reusing the existing
operator keeps the resolver and subject-mapping vocabularies aligned; see
[`evaluateValueResolver`](../../internal/subjectmappingbuiltin/dynamic_value_mapping_builtin.go).

> [!NOTE]
> The original spike prototyped a dedicated `RESOURCE_VALUE_IN` operator to make the direction
> explicit. Implementation reused `SubjectMappingOperatorEnum` instead: the resolver already fixes the
> comparison direction (resource segment against the resolved set), so a separate enum added surface
> without changing behavior.

## Options

| Dimension | A. Reuse Subject Mappings | B. New Primitive (recommended) | C. New Attribute Rule |
| --- | --- | --- | --- |
| Expresses "dynamic" in schema | ✗ must overload `subject_external_values` with a sentinel | ✓ typed fields, intent explicit | ◑ rule value implies it |
| Operator field honesty | ✗ static `SubjectMappingOperatorEnum` reused, dynamic meaning implicit | ✓ `SubjectMappingOperatorEnum` in a resolver whose direction is explicit (`NOT_IN` rejected) | ✓ |
| Combination rule (ANY_OF/ALL_OF) still available | ✓ orthogonal | ✓ orthogonal | ✗ rule slot consumed (see below) |
| Reuses existing evaluator code | ✓ partial (static leaves) | ✗ (new, small) | ✗ |
| Mixed static + dynamic conditions | ✓ supported | ✓ optional `SubjectConditionSet` pre-gate | ✗ |
| Admin/UX clarity | ✗ "why is this subject mapping on a definition?" | ✓ distinct object, distinct mental model | ◑ overloads "rule" concept |
| Migration drift from today | low (same tables) | medium (new table/proto) | medium |

### A. Reuse Subject Mappings (Prototyped, Not Recommended)

The existing `SubjectConditionSet` was re-scoped from an `AttributeValue` to an `AttributeDefinition`
(`DefinitionScopedSubjectMapping`). It reuses the AND/OR condition-group plumbing and the static leaf
evaluator, and it uniquely supports **mixed static + dynamic conditions** (e.g. "department is cardiology
AND the resource MRN is in your assignments"; see `TestReuseStaticAndDynamicConditions`).

But the `SubjectConditionSet` schema has no way to mark a condition as dynamic, so the prototype overloads
`subject_external_values` with a `${resource.value}` sentinel. This is fragile: it is invisible to existing
tooling, easy to mistype, and reuses a field that everywhere else holds a static list. It also forces a
near-duplicate of the group-walk, because the production walk is hard-wired to the static leaf evaluator.
Reuse keeps table and migration drift low but reduces clarity. This answers @strantalis's and @biscoe916's
"why not just extend subject mappings?": it can be done, but the result reads less clearly than a
purpose-built object.

### C. New Attribute Rule (Prototyped, Not Recommended)

Modeling dynamic as a new `AttributeRuleTypeEnum` value (`RuleDynamic`) conflates two separate ideas. The
rule slot already encodes how *multiple values on one definition combine* (`ANY_OF` / `ALL_OF` /
`HIERARCHY`). Using that slot to describe how values are *entitled* means a dynamic definition can no
longer state its combination semantics. In the prototype, `RuleDynamic` defaults to `ANY_OF`, which hides
that choice from the author. How values are entitled and how they combine are separate concerns and should
not share one field.

## Edge Cases (all exercised by tests)

- **Character Set / FQN Ambiguity** (@jentfoo): value segments must never contain FQN-structural or
  encoding characters (`/`, `.`, `%`, NUL) or non-ASCII. The spike enforces this floor
  (`validateValueSegment`) independently of any future loosening of the value grammar. As a consequence, the
  **current** value grammar (`lib/identifier`, strictly `[a-zA-Z0-9_-]`) already cannot represent
  email-like identifiers (`user@acme.co` fails to parse). If the owner/email use case is in scope, the
  value grammar must be deliberately widened, but only to a set that excludes the ambiguous characters
  above.
- **Canonicalization** (@biscoe916): external systems disagree with policy on case and whitespace, so
  `MRN-123` from the IdP would not match `mrn-123` in the FQN. The spike explored a pluggable
  `Canonicalizer` (lowercase + trim). The shipped resolver does **not** canonicalize: matching is exact
  and case-sensitive (`IN` compares equality, `IN_CONTAINS` substring), keeping behavior predictable and
  the operator vocabulary shared with static subject mappings. Where case/whitespace normalization should
  live, and whether it is configurable per definition, is left as a follow-up rather than baked into the
  first release.
- **Cross-Definition / Namespace Collisions** (@jakedoublev): because entitlement is keyed to the value's
  *parent definition FQN*, the same pass-through segment under a different definition is **not** granted
  (`TestCrossDefinitionNoLeak`). This is the key advantage of entitling concrete value FQNs over entitling
  bare pass-through values.
- **Multi-Value Resources** (ADR decision-flow step 6): a single resource carrying several values under
  one definition evaluates the definition rule normally. `TestDecideMultiValue` covers `ANY_OF` (one match
  suffices) and `ALL_OF` (every value must match).
- **API Enforcement**: a definition must not carry both a value-level static subject mapping and a dynamic
  mapping (`ValidateNoCoexistence`), and `HIERARCHY` definitions are rejected for dynamic entitlement since
  they require statically ordered values (`ValidateRule`). The constraint is on value-level *subject
  mappings*, not on the existence of attribute *values*: a definition may still have concrete values (for
  obligation triggers, FQN resolution, etc.) alongside a dynamic mapping. What is disallowed is pairing
  those values with their own subject mappings on a definition that is also entitled dynamically.
- **Direct-Entitlements Overlap / Migration** (@biscoe916 Q1): a direct entitlement is effectively a
  `(value FQN, actions)` pair sourced from ERS at decision time. `TestDirectEntitlementOverlap` shows the
  dynamic mapping reproduces the identical grant from a single policy artifact, supporting the
  "cover the common case in policy, keep direct entitlements/EPOP for true remote entitlement" path.

## Open Questions

1. **Selector Syntax**: the existing flattener addresses array elements as `.patientAssignments[]`, not
   the `.patientAssignments` shown in the ADR. The selector grammar surfaced to admins should be specified
   and documented.
2. **ERS Trust** (@jentfoo, @jrschumacher): like all entitlement, this trusts the ERS response. The
   dynamic model does not worsen that posture but also does not improve it. Provenance/MITM mitigations
   remain future work.
3. **Persistence**: where the new primitive's selector values live for any match-acceleration analogous to
   the cached `subject_condition_set.selector_values` column.
4. **Canonicalization Authority**: per-definition configuration vs a single global normalization.
5. **Value Grammar**: whether/how far to widen the allowed value character set for the email/owner use case.

## Out Of Scope

The broader options (do nothing, productize direct entitlements, plugin PDP) were already decided in
the upstream design ADR. This spike only covers how to model the chosen definition-level approach.
