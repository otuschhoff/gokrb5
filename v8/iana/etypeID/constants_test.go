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
	for _, name := range []string{"aes128-cts-hmac-sha1-96", "aes256-cts", "aes128-sha2", "aes256-sha2", "des3-cbc-sha1-kd", "rc4-hmac"} {
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
