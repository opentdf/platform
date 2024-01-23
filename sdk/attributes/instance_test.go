package attributes

import (
	"errors"
	"testing"
)

func TestAttributeInstanceFromURL(t *testing.T) {
	tests := map[string]struct {
		a string
		i *AttributeInstance
		e InvalidAttributeError
	}{
		"small": {
			a: "http://a.co/attr/a/value/b",
			i: &AttributeInstance{"http://a.co", "a", "b"},
		},
		"noval": {
			a: "http://a.co/attr/a/value/a",
			e: InvalidAttributeError("http://a.co/attr/a/value/"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual, err := AttributeInstanceFromURL(test.a)

			if test.i != nil {
				if err == nil && *actual != *test.i {
					t.Errorf("mismatch: expected %v, got %v", *test.i, *actual)
				} else if err != nil {
					t.Errorf("parse failure: %v => %v", test.a, err)
				}
			} else if test.e != "" {
				var parseError InvalidAttributeError
				if errors.As(err, &parseError) {
					if parseError != test.e {
						t.Errorf("parse failure: invalid err: %v => %v, should be %v", test.a, err, test.e)
					}
				} else {
					t.Errorf("parse failure: invalid err: %v => %v", test.a, err)
				}
				t.Errorf("mismatch: expected %v, got %v", *test.i, *actual)
			}
		})
	}

}
