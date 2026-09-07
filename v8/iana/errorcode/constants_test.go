package errorcode

import (
	"strings"
	"testing"
)

func TestLookupKnownAndUnknownCodes(t *testing.T) {
	for code, description := range errorcodeLookup {
		got := Lookup(code)
		if !strings.Contains(got, description) {
			t.Fatalf("Lookup(%d) = %q, want description %q", code, got, description)
		}
	}
	if got := Lookup(-999); got != "Unknown ErrorCode -999" {
		t.Fatalf("unknown lookup = %q", got)
	}
}
