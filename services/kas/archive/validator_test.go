package archive

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	f, err := ioutil.ReadFile("testdata/envoy.yaml.tdf")
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
