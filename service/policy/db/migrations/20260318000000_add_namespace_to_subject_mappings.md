# Add Namespace to Subject Mappings and Subject Condition Sets

This migration adds optional namespace scoping to `subject_mappings` and `subject_condition_set`.

## Why

Subject mappings and subject condition sets were previously global — there was no way to scope them
to a specific namespace. This change allows them to be associated with a namespace, enabling
namespace-scoped list filtering.

The columns are nullable to preserve backwards compatibility with existing records that have no
namespace association.

## Changes

1. `subject_condition_set` — add nullable `namespace_id` column:
   - Foreign key to `attribute_namespaces(id)` with `ON DELETE CASCADE`
   - Index `idx_subject_condition_set_namespace_id` for efficient namespace-filtered queries

2. `subject_mappings` — add nullable `namespace_id` column:
   - Foreign key to `attribute_namespaces(id)` with `ON DELETE CASCADE`
   - Index `idx_subject_mappings_namespace_id` for efficient namespace-filtered queries

## Resulting Behavior

- Existing records with `namespace_id = NULL` are unscoped and returned in all list queries where no namespace filter is given.
- New records can optionally be associated with a namespace at creation time (by ID or FQN).
- List queries accept an optional namespace filter; when provided, only records matching that
  namespace are returned.
- Deleting a namespace cascades to remove all associated subject mappings and subject condition sets.
