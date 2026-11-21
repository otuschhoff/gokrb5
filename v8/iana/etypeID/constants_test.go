package etypeID

import (
	"strings"
	"testing"
)

func TestETypeMappings(t *testing.T) {
	for id, name := range ETypesByID {
		if got := ETypeToString(id); got != name {
			t.Fatalf("ETypeToString(%d) = %q, want %q", id, got, name)
		}
	}
	if got := ETypeToString(-1); got != "etype -1" {
		t.Fatalf("unknown etype string = %q", got)
	}
	supported := []string{
		"aes128-cts-hmac-sha1-96",
		"aes256-cts",
		"aes128-sha2",
		"aes256-sha2",
		"des3-cbc-sha1-kd",
		"rc4-hmac",
	}
	for _, name := range supported {
		if id := EtypeSupported(name); id == 0 {
			t.Fatalf("supported etype %q returned zero", name)
		}
	}
	for _, name := range []string{"", "unknown", "des-cbc-md5", "camellia128-cts-cmac"} {
		if id := EtypeSupported(name); id != 0 {
			t.Fatalf("unsupported etype %q returned %d", name, id)
		}
	}
	for name := range ETypesByName {
		if strings.TrimSpace(name) == "" {
			t.Fatal("empty etype alias")
		}
	}
}

func TestETypeLookupUsesExportedMaps(t *testing.T) {
	const name = "custom-enctype"
	const customID = -1
	ETypesByName[name] = AES256_CTS_HMAC_SHA1_96
	ETypesByID[customID] = name
	t.Cleanup(func() {
		delete(ETypesByName, name)
		delete(ETypesByID, customID)
	})

	if got := EtypeSupported(name); got != AES256_CTS_HMAC_SHA1_96 {
		t.Errorf("EtypeSupported(%q) = %d, want %d", name, got, AES256_CTS_HMAC_SHA1_96)
	}
	if got := ETypeToString(customID); got != name {
		t.Errorf("ETypeToString(%d) = %q, want %q", customID, got, name)
	}
}
