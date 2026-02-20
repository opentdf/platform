---
status: proposed
date: 2025-01-13
tags:
  - namespaces
  - federation
  - registered-resources
  - subject-mappings
  - actions
driver: ['@jrschumacher', '@biscoe916']
deciders: ['@jrschumacher', '@biscoe916', '@jakedoublev']
consulted: ['@strantalis', '@ttschampel']
---

# Add Namespace Scoping to All Policy Constructs

## Context and Problem Statement

Currently, namespaces in OpenTDF primarily partition **Attribute Definitions** (and by extension, Attribute Values). However, several policy constructs remain globally scoped:

- **Registered Resources**
- **Registered Resource Values**
- **Subject Mappings**
- **Subject Condition Sets**
- **Actions**

This creates challenges for federation scenarios where multiple attribute authorities need to manage their own policy constructs independently. Without namespace scoping, name collisions can occur, organizational boundaries are unclear, and federated deployments cannot cleanly separate concerns.

## Decision Drivers

* **Federation Support**: Enable multiple attribute authorities to operate independently with their own policy constructs
* **Organizational Grouping**: Allow logical separation of policy resources by domain/organization
* **Naming Collision Prevention**: Permit the same resource names in different namespaces (e.g., two organizations can both have a "documents" registered resource)
* **Consistency**: Align all policy constructs with the existing namespace pattern used by Attribute Definitions
* **Query Scoping**: Enable namespace-filtered queries for better performance and clearer authorization boundaries

## Considered Options

1. **Add namespace_id column directly to existing tables** (with migration)
2. **Create junction tables for namespace associations** (existing pattern from KAS grants)
3. **Hybrid approach**: Direct columns for primary ownership, junction tables where many-to-many relationships are needed
4. **Status quo**: Keep constructs globally scoped

## Decision Outcome

Chosen option: **Option 1 - Add namespace_id column directly to existing tables**, because:

- Registered Resources, Subject Mappings, Subject Condition Sets, and Actions have a clear single-namespace ownership model
- Uniqueness constraints need to be scoped to namespace (e.g., `UNIQUE(namespace_id, name)`)
- Simpler query patterns than junction tables for 1:N relationships
- Aligns with how Attribute Definitions already relate to namespaces

### Consequences

* **Good**, because it enables clean federation with independent namespace management
* **Good**, because uniqueness constraints become namespace-scoped, preventing cross-organization collisions
* **Good**, because API contracts become explicit about namespace context
* **Good**, because query performance can be optimized with namespace-based partitioning
* **Bad**, because it requires data migration for existing deployments
* **Bad**, because it introduces breaking API changes (namespace becomes required)
* **Neutral**, because cross-namespace references remain valid (a Subject Mapping in namespace A can reference an Attribute Value in namespace B for federation use cases)

## Detailed Design

### Schema Changes

#### Registered Resources

```sql
-- Add namespace_id to registered_resources
ALTER TABLE registered_resources
  ADD COLUMN namespace_id UUID NOT NULL
  REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Update uniqueness constraint: name unique within namespace
ALTER TABLE registered_resources
  DROP CONSTRAINT registered_resources_name_key;
ALTER TABLE registered_resources
  ADD CONSTRAINT registered_resources_namespace_name_unique
  UNIQUE(namespace_id, name);

-- Add index for namespace-scoped queries
CREATE INDEX idx_registered_resources_namespace
  ON registered_resources(namespace_id);
```

#### Subject Condition Sets

```sql
-- Add namespace_id to subject_condition_set
ALTER TABLE subject_condition_set
  ADD COLUMN namespace_id UUID NOT NULL
  REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Add index for namespace-scoped queries
CREATE INDEX idx_subject_condition_set_namespace
  ON subject_condition_set(namespace_id);
```

#### Subject Mappings

```sql
-- Add namespace_id to subject_mappings
ALTER TABLE subject_mappings
  ADD COLUMN namespace_id UUID NOT NULL
  REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Add index for namespace-scoped queries
CREATE INDEX idx_subject_mappings_namespace
  ON subject_mappings(namespace_id);
```

#### Actions

```sql
-- Add namespace_id to actions
-- Standard actions (is_standard=TRUE) remain global with NULL namespace_id
-- Custom actions require namespace assignment
ALTER TABLE actions
  ADD COLUMN namespace_id UUID -- NULL is permitted to support standard actions
  REFERENCES attribute_namespaces(id) ON DELETE CASCADE;

-- Update uniqueness constraint: name unique within namespace for custom actions
-- Standard actions maintain global uniqueness via is_standard constraint
ALTER TABLE actions
  DROP CONSTRAINT actions_name_key;
ALTER TABLE actions
  ADD CONSTRAINT actions_namespace_name_unique
  UNIQUE(namespace_id, name);

-- Add index for namespace-scoped queries
CREATE INDEX idx_actions_namespace
  ON actions(namespace_id);
```

**Standard Actions Decision:** Standard actions (`is_standard=TRUE`) remain globally scoped with `namespace_id = NULL`. This preserves backward compatibility and recognizes that CRUD operations are universal concepts not owned by any specific namespace. Custom actions require namespace assignment.

### Proto/API Changes

All affected services will require `namespace_id` in their request messages:

```protobuf
// Example: CreateRegisteredResourceRequest
message CreateRegisteredResourceRequest {
  string namespace_id = 1;  // NEW: Required
  string name = 2;
  // ... existing fields
}

// Example: ListRegisteredResourcesRequest
message ListRegisteredResourcesRequest {
  string namespace_id = 1;  // NEW: Required for scoped queries
  // ... pagination fields
}
```

### Cross-Namespace Reference Behavior

**Subject Mappings can reference Attribute Values from any namespace.** This is intentional for federation:

- A Subject Mapping in `https://org-a.com` can grant entitlements to Attribute Values in `https://org-b.com`
- This enables federated attribute authorities to define subject-to-entitlement mappings across organizational boundaries
- The namespace on the Subject Mapping indicates **ownership/management**, not access restriction

**Registered Resources follow the same pattern:**

- A Registered Resource Value in namespace A can be associated with Attribute Values from namespace B via `action_attribute_values`
- The namespace indicates where the resource definition is managed

### GetDecisions / Visibility Trimming Impact

The `GetDecisions` RPC uses Subject Mappings to determine entitlements. With namespace scoping:

1. Subject Mappings must be queried across relevant namespaces (or all accessible namespaces)
2. The caller may need to specify which namespaces to consider
3. Federation scenarios where mappings cross namespace boundaries remain fully supported

**Proposed behavior:**
- `GetDecisions` accepts an optional `namespace_ids` filter
- If not specified, all namespaces the caller has access to are considered
- Cross-namespace Subject Mappings are evaluated regardless of which namespace they reside in

**Operational Complexity:**
The primary complexity is in query construction, not fundamental design:
- Subject Mappings have an **ownership namespace** (where they're managed/administered)
- Subject Mappings can **reference** Attribute Values in **any namespace** (cross-namespace by design)
- Query logic: "Find all Subject Mappings (across accessible namespaces) that grant entitlements to the requested Attribute Values (which may span multiple namespaces)"

This cross-namespace reference model is intentional and required for federation use cases. The implementation requires careful JOIN construction but does not change the semantic model.

⚠️ **See [Risks and Required Decisions](#risks-and-required-decisions)** for the decision on which namespaces GetDecisions should query.

## Migration Strategy

Following established patterns from [20240813000001_add_namespace_kas_grants.sql](../db/migrations/20240813000001_add_namespace_kas_grants.sql):

### Phase 1: Schema Addition (Non-Breaking)

1. Add `namespace_id` column as **nullable** to all affected tables
2. System continues operating normally—existing code paths unaffected
3. New API endpoints accept optional `namespace_id` (backward compatible)

### Phase 2: Data Migration (Interactive or Automatic)

The migration behavior depends on the existing namespace count:

**Single Namespace Scenario:**
- If exactly one namespace exists in `attribute_namespaces`, automatically assign all existing records to that namespace
- No admin intervention required
- Migration can proceed unattended

**Multiple Namespace Scenario:**
- Migration requires interactive admin intervention
- Provide CLI tooling or admin UI to:
  - List unmigrated records per table
  - Assign records to appropriate namespaces
  - Validate assignments before committing
- System remains operational in "mixed mode" until migration complete

**Migration Tooling:**
```bash
# Example CLI commands (to be implemented)
opentdf-admin migrate namespace-scope --status           # Show migration progress
opentdf-admin migrate namespace-scope --list-pending     # List unmigrated records
opentdf-admin migrate namespace-scope --assign <table> --namespace <ns-id>  # Bulk assign
opentdf-admin migrate namespace-scope --interactive      # Interactive assignment UI
```

### Phase 3: Constraint Enforcement

1. Verify all records (except standard actions) have `namespace_id` assigned
2. Add `NOT NULL` constraint to non-action tables
3. Update uniqueness constraints to be namespace-scoped
4. Add indexes for query optimization

### Phase 4: API Enforcement

1. Deprecate non-namespaced API endpoints with warning responses
2. Require `namespace_id` in all create/update operations
3. List operations default to namespace-scoped (require explicit namespace)
4. Provide deprecation period before removing old endpoints

## Work Decomposition and Level of Effort

### Database Migrations

| Task | Description | LOE |
|------|-------------|-----|
| M1 | Add nullable `namespace_id` to `registered_resources` | S |
| M2 | Add nullable `namespace_id` to `subject_condition_set` | S |
| M3 | Add nullable `namespace_id` to `subject_mappings` | S |
| M4 | Add nullable `namespace_id` to `actions` | S |
| M5 | Data migration script for existing records | M |
| M6 | Add NOT NULL constraints after migration | S |
| M7 | Update uniqueness constraints (namespace-scoped) | S |
| M8 | Add namespace indexes | S |
| M9 | Migration CLI tooling (status, list-pending, assign, interactive) | L |
| M10 | Single-namespace auto-migration logic | S |
| M11 | Migration documentation (.md files) | M |

**Subtotal: ~4-5 days**

### Proto/API Changes

| Task | Description | LOE |
|------|-------------|-----|
| P1 | Update `registered_resources.proto` - add namespace_id fields | S |
| P2 | Update `subject_mapping.proto` - add namespace_id fields | S |
| P3 | Update `actions.proto` (if separate) or relevant proto | S |
| P4 | Regenerate proto/gRPC code | S |
| P5 | Update OpenAPI specs | S |

**Subtotal: ~1 day**

### Service Layer (Go)

| Task | Description | LOE |
|------|-------------|-----|
| S1 | Update Registered Resources CRUD - require namespace_id | M |
| S2 | Update Subject Mappings CRUD - require namespace_id | M |
| S3 | Update Subject Condition Sets CRUD - require namespace_id | M |
| S4 | Update Actions CRUD - require namespace_id | M |
| S5 | Update `GetDecisions` to handle namespace filtering | L |
| S6 | Update `MatchSubjectMappings` for namespace awareness | M |
| S7 | Update validation logic for namespace-scoped uniqueness | M |
| S8 | Error handling for namespace-related errors | S |

**Subtotal: ~4-5 days**

### Database Layer (sqlc/queries)

| Task | Description | LOE |
|------|-------------|-----|
| D1 | Update registered resources queries | M |
| D2 | Update subject mapping queries | M |
| D3 | Update subject condition set queries | M |
| D4 | Update action queries | M |
| D5 | Update FQN generation for Registered Resources (namespace prefix) | M |

**Subtotal: ~2-3 days**

### Testing

| Task | Description | LOE |
|------|-------------|-----|
| T1 | Unit tests for namespace validation | M |
| T2 | Integration tests for namespace-scoped CRUD | L |
| T3 | Integration tests for cross-namespace references | M |
| T4 | Migration tests (upgrade path) | M |
| T5 | GetDecisions tests with namespace filtering | M |
| T6 | Performance tests for namespace-indexed queries | S |

**Subtotal: ~3-4 days**

### Documentation

| Task | Description | LOE |
|------|-------------|-----|
| Doc1 | Update API documentation | M |
| Doc2 | Migration guide for existing deployments | M |
| Doc3 | Federation documentation updates | M |
| Doc4 | Update examples and quickstarts | S |

**Subtotal: ~2 days**

### CLI Updates

| Task | Description | LOE |
|------|-------------|-----|
| CLI1 | Update policy CLI commands to accept/require namespace | M |
| CLI2 | Add namespace context/default support for CLI workflows | M |
| CLI3 | Update CLI help text and examples | S |

**Subtotal: ~1-2 days**

### SDK Updates

| Task | Description | LOE |
|------|-------------|-----|
| SDK1 | Update Go SDK (proto bump + signature updates) | S |
| SDK2 | Update JS SDK (proto bump + signature updates) | S |
| SDK3 | Update Java SDK (proto bump + signature updates) | S |

**Subtotal: ~1-2 days total**

---

**Total Estimated LOE: ~18-24 days** (including SDKs and CLI)

**LOE Key:**
- **S (Small)**: < 0.5 day
- **M (Medium)**: 0.5 - 1 day
- **L (Large)**: 1 - 2 days
- **XL (Extra Large)**: 2+ days

## Risks and Required Decisions

### GetDecisions Cross-Namespace Query Behavior

**Risk Level: HIGH** — Must be resolved before implementation.

**Problem Statement:**
With namespace scoping, Subject Mappings have an ownership namespace but can reference Attribute Values in any namespace. `GetDecisions` must determine which Subject Mappings to evaluate when resolving entitlements.

**Example Scenario:**
- Namespace A (`https://org-a.com`) has a Subject Mapping: "Users with role=admin get `https://org-b.com/attr/classification/value/secret`"
- Namespace B (`https://org-b.com`) owns the Attribute Value being granted
- When `GetDecisions` is called for a user with role=admin, should it find the Subject Mapping in Namespace A?

**Decision Required — Choose One:**

| Option | Behavior | Pros | Cons |
|--------|----------|------|------|
| **A: Query All Accessible** | GetDecisions queries Subject Mappings across all namespaces the caller has read access to | Preserves current behavior; federation works seamlessly | Performance concern at scale; implicit trust model |
| **B: Explicit Namespace List** | Caller must specify which namespaces to include in GetDecisions | Explicit control; predictable behavior | Breaking change; caller must know namespace topology |
| **C: Attribute Value Namespace** | Query Subject Mappings in namespaces that own the requested Attribute Values | Intuitive ownership model | Breaks federation—cross-namespace grants wouldn't work |
| **D: Federated Trust Registry** | Namespaces explicitly declare which other namespaces can grant their Attribute Values | Most secure; explicit trust | Additional complexity; new trust management API |

**Recommendation:** Option A for backward compatibility, with Option B as an optional filter for callers who want explicit control.

**Status:** OPEN — Requires team discussion before implementation.

**Impact if Unresolved:**
- Undefined behavior for federated deployments
- Potential security implications (unintended entitlement grants)
- Performance unpredictability

---

### Proto Versioning — RESOLVED

**Decision:** No proto version bump (Option A).

**Rationale:**
- Proto3 has no `required` fields—all fields are implicitly optional at the wire level
- Validation is enforced in service layer regardless of proto version
- Wire format is unchanged; adding optional `namespace_id` field is backward compatible
- Service-layer validation handles the contextual requirements (migration state, standard actions)

**Documentation Requirement:** Release notes and migration guide must clearly communicate the semantic change in API behavior.

---

## Resolved Questions

1. **Standard Actions**: Standard actions (`is_standard=TRUE`) remain global with `namespace_id = NULL`. Custom actions require namespace assignment. This preserves backward compatibility and recognizes CRUD as universal operations.

2. **Migration Strategy**: Interactive migration when multiple namespaces exist; automatic assignment when only one namespace exists. System operates in "mixed mode" during migration with CLI/admin tooling provided.

3. **Cross-Namespace Admin Queries**: Out of scope for this ADR. Fine-grained access control for cross-namespace operations will be addressed separately via ongoing Casbin authorizer enhancements.

4. **FQN Generation**:
   - **Registered Resources**: Prefix with namespace → `https://namespace.com/rr/resource-name`
   - **Subject Mappings**: No FQN required—these are internal constructs not referenced externally
   - **Subject Condition Sets**: No FQN required—referenced only by Subject Mappings via foreign key
   - **Actions**: No FQN required—referenced by name within namespace context

   Only externally-referenced constructs require FQNs: Attributes, Obligations (future), and Registered Resources.

## Validation

Implementation will be validated through:

1. **Schema Validation**: Database constraints enforce namespace requirements
2. **API Contract Tests**: Proto validation ensures namespace_id is provided
3. **Integration Tests**: Cross-namespace reference scenarios tested
4. **Migration Tests**: Upgrade path from non-namespaced to namespaced verified
5. **Performance Tests**: Namespace-indexed queries meet latency requirements

## More Information

### Related ADRs and Migrations

- [0004-standard-action-storage-handling.md](./0004-standard-action-storage-handling.md) - Actions storage design
- [20240813000001_add_namespace_kas_grants.sql](../db/migrations/20240813000001_add_namespace_kas_grants.sql) - Precedent for namespace associations
- [20240806142109_add_resource_mapping_groups.sql](../db/migrations/20240806142109_add_resource_mapping_groups.sql) - Resource Mapping Groups (already namespaced)
- [20251002000000_add_namespace_certificates.sql](../db/migrations/20251002000000_add_namespace_certificates.sql) - Recent namespace junction table pattern

### Federation Use Cases

This change directly supports:

1. **Multi-Authority Federation**: Multiple organizations managing their own policy constructs
2. **Attribute Authority Delegation**: One authority can reference another's attribute values
3. **Organizational Boundaries**: Clear separation of policy management responsibilities
4. **Namespace-Scoped Administration**: Admins can manage their namespace without affecting others
