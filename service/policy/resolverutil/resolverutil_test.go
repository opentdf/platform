package resolverutil

import "testing"

func TestNamespaceNameFromFQN(t *testing.T) {
	cases := map[string]string{
		"https://virtru.com":                                  "virtru.com",
		"https://virtru.com/":                                 "virtru.com",
		"https://virtru.com/obl/handling":                     "virtru.com",
		"https://virtru.com/attr/classification/value/secret": "virtru.com",
		"http://acme.test/resm/group":                         "acme.test",
		"virtru.com":                                          "virtru.com",
		"":                                                    "",
	}
	for in, want := range cases {
		if got := NamespaceNameFromFQN(in); got != want {
			t.Errorf("NamespaceNameFromFQN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSingleAddsNamespaceDimension(t *testing.T) {
	rc := Single("virtru.com")
	if len(rc.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rc.Resources))
	}
	if got := (*rc.Resources[0])["namespace"]; got != "virtru.com" {
		t.Errorf("namespace dimension = %q, want %q", got, "virtru.com")
	}
}
