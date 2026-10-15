package store

import (
	"errors"
	"io/fs"
)

// ExistsForCreate checks presence without treating a lookup failure as absence.
// Native drivers can check presence without reading/decrypting the payload.
// Custom drivers without that capability must return nil, nil (the memory
// driver's absence convention) or fs.ErrNotExist from Get for a missing record.
// A successful non-nil payload, even empty/invalid JSON, is an existing record.
// This is a preflight check, not an atomic create-if-absent operation.
func ExistsForCreate(s Interface) (bool, error) {
	if checker, ok := s.(interface{ ExistsWithError() (bool, error) }); ok {
		return checker.ExistsWithError()
	}
	data, err := s.Get()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return data != nil, nil
}
