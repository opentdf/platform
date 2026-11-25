# Index obligation triggers by attribute value

### Changes

- Index on `obligation_triggers(attribute_value_id)`
- No schema changes

### Why

Authorization decisions load only the obligation triggers for the attribute values they decide,
through `ListObligationTriggers` filtered by `attribute_value_fqns`. That join reaches
`obligation_triggers` by `attribute_value_id`, which the existing unique indexes (leading with
`obligation_value_id`) don't cover. The index also speeds up cascading deletes from
`attribute_values`.
