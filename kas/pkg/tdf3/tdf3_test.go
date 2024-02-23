package tdf3

import (
	"reflect"
	"testing"
)

func TestBlockMethod(t *testing.T) {
	b := Block{
		Block:      nil,
		Algorithm:  "AES",
		Streamable: true,
		IV:         []byte("example-iv"),
	}

	result := b.Method()

	expectedResult := EncryptionMethod{
		Algorithm:  "AES",
		Streamable: true,
		IV:         []byte("example-iv"),
	}

	if !reflect.DeepEqual(result, expectedResult) {
		t.Errorf("Expected result %v, but got %v", expectedResult, result)
	}
}
