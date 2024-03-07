package archive

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	f, err := os.ReadFile("testdata/envoy.yaml.tdf")
	if err != nil {
		t.Fatal(err)
	}
	err = Valid(bytes.NewReader(f))
	if err != nil {
		t.Fatal(err)
	}
	r := strings.NewReader("hello world")
	err = Valid(r)
	if err == nil {
		t.Fail()
	}
	t.Log(err)
	t.Log("Valid")
}
