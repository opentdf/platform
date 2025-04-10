# Standard Actions will be storage-driven and exported SDK constants

Admin CRUD and PEP usage of actions (standard and custom) is getting complex.

Protos for Standard Actions are good because PEPs have the acceptable values importable at build/compile time, but interoperability
with Custom Actions (which must be fetched / configured) is challenging.

## Chosen Option: Standard Actions will be storage-driven and exported SDK constants

1. We will store CRUD action names with `is_standard = TRUE` in policy db table.
2. We will expose `ActionCreate`, `ActionRead`, etc., via SDK constants to make standard actions importable.
3. Custom actions in PEPs will be retrievable or configurable as needed (as action name strings or policy object action IDs).
4. We will avoid significant complexity from normalizing proto enums to stored table rows, and vice versa.
5. Subject Mappings CRUD, Obligations CRUD, and `GetDecisions` will support actions by `name` or `id` and
validate that the action exists in the policy database.
6. We will deprecate the existing standard action enums and suggest use of SDK constants.

## Options

### Enhance existing StandardAction proto enum and normalize when stored in actions table
1. Standard Actions are proto-defined and normalized into the db (STANDARD_ACTION_ENUM_CREATE => 'create') with is_standard = TRUE.
2. Admins can write metadata labels for standard actions, but they're otherwise immutable.
3. This becomes quite complex in Subject Mappings CRUD, Obligations CRUD, and `GetDecisions` with need to support:
    1. custom action by ID
    2. custom action by stored, normalized name
    3. standard action by stored ID (to be normalized to proto in API layer)
    4. standard action by stored, normalized name (to be normalized to proto in API layer)
    5. proto enum for standard action (to be normalized to a stored name in DB layer)

### Enhance existing StandardAction proto enum but do not store in actions table
1. Standard Actions are proto-only.
2. Custom Actions are stored in db table.
3. Subject Mappings column for standard_actions (marshaled protos), and relation table for custom actions (by ID).
4. Simpler Subject Mappings CRUD, Obligations CRUD, and `GetDecisions`:
    1. custom action by ID
    2. custom action by stored, normalized name
    3. proto enum for standard action

### Standard Actions will be storage-driven and exported SDK constants
1. Standard Actions become read-only "create, read, update, delete" rows in db table (with column is_standard = TRUE).
2. Custom Actions are fully writable with unique names and column is_standard = FALSE.
3. Old proto enums are deprecated.
4. Simpler Subject Mappings CRUD, Obligations CRUD, and `GetDecisions`:
    1. action by ID
    2. action by name
    3. SDKs can still export constants like ActionCreate, ActionRead, etc.

