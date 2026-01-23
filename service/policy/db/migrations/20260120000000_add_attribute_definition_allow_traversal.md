# Add Allow Traversal to Attribute Definitions

This migration adds a boolean flag to attribute definitions so policy logic can explicitly allow or deny attribute traversal.

## Schema Changes

- **Table**: `attribute_definitions`
- **Column added**: `allow_traversal BOOLEAN NOT NULL DEFAULT FALSE` (comment: "Whether or not to allow platform to return the definition key when encrypting, if the value specified is missing.")

## Behavior

- Existing rows default to `allow_traversal = FALSE`.
- New rows must provide a value or accept the default `FALSE`.

## Rollback

- Drops the `allow_traversal` column from `attribute_definitions`.
