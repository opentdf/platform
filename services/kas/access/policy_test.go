package access

import (
	"testing"
)

func TestGetNamespacesFromAttributesSuccess(t *testing.T) {
	testBody := PolicyBody{
		DataAttributes: []Attribute{
			{URI: "https://example.com/attr/Test1/value/A", Name: "TestAttr1"},
			{URI: "https://example2.com/attr/Test2/value/B", Name: "TestAttr2"},
			{URI: "https://example.com/attr/Test3/value/C", Name: "TestAttr3"},
		},
		Dissem: []string{},
	}
	expectedResult := []string{"https://example2.com", "https://example.com"}
	output, err := getNamespacesFromAttributes(testBody)
	if err != nil {
		t.Error(err)
	}
	if !sameStringSlice(output, expectedResult) {
		t.Errorf("Output %q not equal to expected %q", output, expectedResult)
	}
}

func TestGetNamespacesFromAttributesFailure(t *testing.T) {
	testBody := PolicyBody{
		DataAttributes: []Attribute{
			{URI: "", Name: "TestAttr1"},
		},
		Dissem: []string{},
	}
	output, err := getNamespacesFromAttributes(testBody)

	if len(output) != 0 {
		t.Errorf("Output %v not equal to expected %v", len(output), 0)
	}

	if err == nil {
		t.Errorf("Should throw an error, but got %v", err)
	}
}

func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}
