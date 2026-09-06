package testdata

import (
	"encoding/hex"
	"testing"
)

func TestMSKILEStructureFixtures(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		size int
	}{
		{"PAC attributes info", MSKILEPACAttributesRequested, 8},
		{"PAC requestor SID", MSKILEPACRequestorSID, 28},
		{"kpasswd policy reply", MSKILEKPasswdPolicyReply, 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatalf("fixture is not valid hex: %v", err)
			}
			if len(b) != tt.size {
				t.Fatalf("fixture size is %d bytes, want %d", len(b), tt.size)
			}
		})
	}
}
