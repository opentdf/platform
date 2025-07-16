package cmd

import (
	"testing"
)

func TestFindNewId(t *testing.T) {
	// Test with no existing IDs
	existing := existingKeys{make(map[string]bool)}
	id, err := existing.findNewID()
	if err != nil {
		t.Fatalf("findNewID failed with no existing IDs: %v", err)
	}
	if len(id) != idLength {
		t.Errorf("expected id length %d, got %d", idLength, len(id))
	}
	if existing.existingIDs[id] {
		t.Errorf("newly generated id '%s' should not be in the existing map", id)
	}

	// Test with some existing IDs
	existing.existingIDs[id] = true
	newID, err := existing.findNewID()
	if err != nil {
		t.Fatalf("findNewID failed with existing IDs: %v", err)
	}
	if len(newID) != idLength {
		t.Errorf("expected new id length %d, got %d", idLength, len(newID))
	}
	if newID == id {
		t.Errorf("findNewID generated a duplicate ID '%s'", newID)
	}

	// Test for uniqueness over multiple generations
	for i := 0; i < 100; i++ {
		nid, err := existing.findNewID()
		if err != nil {
			t.Fatalf("findNewID failed during multiple generations: %v", err)
		}
		if existing.existingIDs[nid] {
			t.Errorf("generated a duplicate id '%s' that was already in the map", id)
		}
		existing.existingIDs[nid] = true
	}
}
