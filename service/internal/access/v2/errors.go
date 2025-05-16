package access

import "errors"

var (
	ErrMissingRequiredSDK                          = errors.New("access: missing required SDK")
	ErrMissingRequiredLogger                       = errors.New("access: missing required logger")
	ErrMissingEntityResolutionServiceSDKConnection = errors.New("access: missing required entity resolution SDK connection, cannot be nil")
	ErrMissingRequiredPolicy                       = errors.New("access: both attribute definitions and subject mappings must be provided or neither")
	ErrInvalidEntityType                           = errors.New("access: invalid entity type")
	ErrInvalidAttributeDefinition                  = errors.New("access: invalid attribute definition")
	ErrInvalidSubjectMapping                       = errors.New("access: invalid subject mapping")
	ErrInvalidEntitledFQNsToActions                = errors.New("access: invalid entitled FQNs to actions")
	ErrInvalidResource                             = errors.New("access: invalid resource")
	ErrInvalidEntityChain                          = errors.New("access: invalid entity chain")
	ErrInvalidAction                               = errors.New("access: invalid action")
	ErrFQNNotFound                                 = errors.New("access: attribute value FQN not found in memory")
	ErrDefinitionNotFound                          = errors.New("access: definition not found for FQN")
	ErrFailedEvaluation                            = errors.New("access: failed to evaluate definition")
	ErrMissingRequiredSpecifiedRule                = errors.New("access: AttributeDefinition rule cannot be unspecified")
	ErrUnrecognizedRule                            = errors.New("access: unrecognized AttributeDefinition rule")
)
