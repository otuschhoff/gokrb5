package config

import (
	"reflect"
	"testing"
)

func TestKKDCPURLsInRealmConfig(t *testing.T) {
	c, err := NewFromString(`[libdefaults]
 dns_lookup_kdc = true

[realms]
 EXAMPLE.ORG = {
  kdc = https://proxy.example.org/KdcProxy
  kpasswd_server = https://proxy.example.org/KdcProxy
 }
`)
	if err != nil {
		t.Fatal(err)
	}
	_, kdcs, err := c.GetKDCs("EXAMPLE.ORG", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := kdcs[1]; got != "https://proxy.example.org/KdcProxy" {
		t.Fatalf("KDC URL = %q", got)
	}
	_, kpasswd, err := c.GetKpasswdServers("EXAMPLE.ORG", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := kpasswd[1]; got != "https://proxy.example.org/KdcProxy" {
		t.Fatalf("kpasswd URL = %q", got)
	}
}

func TestServerOrderingDoesNotMutateConfig(t *testing.T) {
	configured := []string{"https://one.example.org/KdcProxy", "kdc.example.org:88"}
	want := append([]string(nil), configured...)
	for i := 0; i < 20; i++ {
		ordered := randServOrder(configured)
		if len(ordered) != len(configured) {
			t.Fatalf("ordered server count = %d", len(ordered))
		}
	}
	if !reflect.DeepEqual(configured, want) {
		t.Fatalf("server ordering mutated configuration: %v", configured)
	}
}
