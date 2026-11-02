package profilestore

import "errors"

var (
	ErrProfileNameConflict        = errors.New("error: profile name already exists in storage")
	ErrMissingCurrentProfile      = errors.New("error: current profile not set")
	ErrMissingDefaultProfile      = errors.New("error: default profile not set")
	ErrMissingProfileName         = errors.New("error: profile name not found")
	ErrInvalidStoreDriver         = errors.New("error: invalid store driver")
	ErrDeletingProfile            = errors.New("error: deleting profile with name")
	ErrCannotDeleteDefaultProfile = errors.New("error: cannot delete default profile")
)
