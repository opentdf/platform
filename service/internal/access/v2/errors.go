package access

import "errors"

var (
	ErrMissingRequiredSDK                          = errors.New("access: missing required SDK")
	ErrMissingRequiredLogger                       = errors.New("access: missing required logger")
	ErrMissingEntityResolutionServiceSDKConnection = errors.New("access: missing required entity resolution SDK connection, cannot be nil")
	ErrMissingRequiredPolicy                       = errors.New("access: both attribute definitions and subject mappings must be provided or neither")
	ErrInvalidAttributeDefinition                  = errors.New("access: invalid attribute definition")
	ErrInvalidSubjectMapping                       = errors.New("access: invalid subject mapping")
	ErrInvalidResourceType                         = errors.New("access: invalid resource type")
	ErrInvalidEntityChain                          = errors.New("access: invalid entity chain")
	ErrInvalidAction                               = errors.New("access: invalid action")
	ErrInvalidParameterMismatch                    = errors.New("access: invalid parameter mismatch")
)
