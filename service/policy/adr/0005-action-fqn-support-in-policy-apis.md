# Policy APIs will support action FQNs for downstream references

As policy objects become namespace-aware, referring to actions by `name` alone is ambiguous across namespaces.

This is especially important for downstream APIs that attach actions to other policy objects, including:

1. Obligation Triggers
2. Subject Mappings
3. Registered Resource Values

## Chosen Option: Add action FQN support in request payloads

1. Downstream policy APIs will support identifying actions by FQN (for example, `https://example.com/act/read`) in addition to existing identifiers.
2. Action FQN support lets clients reference namespaced actions directly without first resolving and passing action IDs.
3. We keep ID-based support for cases where clients already have IDs.
4. Service-level validation will ensure references are namespace-consistent where required by namespaced policy behavior.

## Why this option

1. Action IDs are precise but require extra lookup calls for many clients.
2. Action names are human-friendly but become ambiguous once actions are namespaced.
3. Action FQNs are both human-readable and namespace-specific, making them a practical default for cross-object references.
4. This follows the same direction already used by other namespaced policy objects (for example, registered resources), where FQNs are first-class identifiers and are supported by shared identifier helpers.

## Options considered

### Require action ID only
1. Unambiguous but adds client round trips and operational overhead.
2. Poor ergonomics for configuration-heavy workflows.

### Keep action name only
1. Simple input shape but ambiguous in namespaced systems.
2. Requires implicit resolution rules that are hard to reason about.

### Support action FQN (chosen)
1. Namespace-explicit, readable, and easy to construct.
2. Avoids mandatory ID lookup while preserving precise identity semantics.
