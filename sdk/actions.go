package sdk

// PolicyActionNameCreate is the standard "create" action in the Policy Service.
const PolicyActionNameCreate = "create"

// PolicyActionNameRead is the standard "read" action in the Policy Service.
const PolicyActionNameRead = "read"

// PolicyActionNameUpdate is the standard "update" action in the Policy Service.
const PolicyActionNameUpdate = "update"

// PolicyActionNameDelete is the standard "delete" action in the Policy Service.
const PolicyActionNameDelete = "delete"

// DecisionActionNameCreate is the "create" action for the Authorization Decisions API.
const DecisionActionNameCreate = PolicyActionNameCreate

// DecisionActionNameRead is the "read" action for the Authorization Decisions API.
const DecisionActionNameRead = PolicyActionNameRead

// DecisionActionNameUpdate is the "update" action for the Authorization Decisions API.
const DecisionActionNameUpdate = PolicyActionNameUpdate

// DecisionActionNameDelete is the "delete" action for the Authorization Decisions API.
const DecisionActionNameDelete = PolicyActionNameDelete

// CONTRIBUTING: The PolicyActionName* values are duplicated from
// service/policy/db/actions.go (ActionCreate/Read/Update/Delete).
// Changes to either set MUST be mirrored in the other.
