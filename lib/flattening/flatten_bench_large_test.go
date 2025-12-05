package flattening

import (
	"fmt"
	"testing"
)

// Benchmark with larger dataset to show lookup performance
func BenchmarkGetFromFlattened_Large(b *testing.B) {
	// Create a larger flattened structure via Flatten
	largeInput := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		largeInput[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}
	flatInput, err := Flatten(largeInput)
	if err != nil {
		b.Fatal(err)
	}

	// Query for a key in the middle
	queryString := ".key50"
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = GetFromFlattened(flatInput, queryString)
	}
}

// Benchmark multiple lookups on same flattened entity
func BenchmarkGetFromFlattened_MultipleLookups(b *testing.B) {
	largeInput := make(map[string]interface{})
	for i := 0; i < 50; i++ {
		largeInput[fmt.Sprintf("attr%d", i)] = fmt.Sprintf("value%d", i)
	}
	flatInput, err := Flatten(largeInput)
	if err != nil {
		b.Fatal(err)
	}

	queries := []string{".attr0", ".attr10", ".attr25", ".attr40", ".attr49"}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, q := range queries {
			_ = GetFromFlattened(flatInput, q)
		}
	}
}

// Benchmark with nested structure (common in entity representations)
func BenchmarkFlatten_NestedEntity(b *testing.B) {
	nestedInput := map[string]interface{}{
		"user": map[string]interface{}{
			"id":    "user123",
			"name":  "Test User",
			"email": "test@example.com",
			"attributes": map[string]interface{}{
				"department": "Engineering",
				"level":      "Senior",
				"groups":     []interface{}{"group1", "group2", "group3"},
			},
		},
		"roles": []interface{}{
			map[string]interface{}{"name": "admin", "scope": "global"},
			map[string]interface{}{"name": "reader", "scope": "local"},
		},
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := Flatten(nestedInput)
		if err != nil {
			b.Fatal(err)
		}
	}
}


