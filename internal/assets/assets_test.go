package assets

import (
	"slices"
	"testing"
)

func TestList_ContainsNoteTxt(t *testing.T) {
	files, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := "assets/note.txt"
	if !slices.Contains(files, want) {
		t.Fatalf("List() = %v, want it to contain %q", files, want)
	}
}
