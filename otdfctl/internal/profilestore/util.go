package profilestore

import (
	"errors"
	"fmt"
	"regexp"
)

var profileNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-_]?[a-z0-9])*$`)

func validateProfileName(n string) error {
	// check profile name is valid [a-zA-Z0-9_-]
	if n == "" {
		return fmt.Errorf("%w, profile name: ''", ErrMissingProfileName)
	}
	// check profile name is valid [a-zA-Z0-9_-]
	if !profileNameRegex.MatchString(n) {
		return errors.New("profile name must be alphanumeric with dashes or underscores (e.g. my-profile-name)")
	}
	return nil
}
