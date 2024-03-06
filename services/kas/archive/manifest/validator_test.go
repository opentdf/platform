package manifest

import (
	"io/ioutil"
	"testing"
)

func TestValid(t *testing.T) {
	f, err := ioutil.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	err = Valid(f)
	if err != nil {
		t.Fatal(err)
	}
	err = Valid([]byte("invalid-json"))
	if err == nil {
		t.Fail()
	}
	t.Log(err)
	t.Log("Valid")
}

func TestValidFailure(t *testing.T) {
	var mockJson = []byte(`[
		{"Wrong": "Platypus", "Fields": "Monotremata"},
		{"Wrong": "Quoll",    "Fields": "Dasyuromorphia"}
	]`)

	err := Valid(mockJson)

	if err == nil {
		t.Errorf("Error expected, but got %v", err)
	}
}
