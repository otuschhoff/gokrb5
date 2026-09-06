package config

import (
	"errors"
	"net"
	"reflect"

	"testing"

	"github.com/otuschhoff/gokrb5/v8/test"

	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestConfig_GetKDCsUsesConfiguredKDC(t *testing.T) {
	t.Parallel()

	// This test is meant to cover the fix for
	// https://github.com/otuschhoff/gokrb5/issues/332
	krb5ConfWithKDCAndDNSLookupKDC := `
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
`

	c, err := NewFromString(krb5ConfWithKDCAndDNSLookupKDC)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	count, kdcs, err := c.GetKDCs("TEST.GOKRB5", false)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 but received %d", count)
	}
	if kdcs[1] != "kdc2b.test.gokrb5:88" {
		t.Fatalf("expected kdc2b.test.gokrb5:88 but received %s", kdcs[1])
	}
}

func TestGetKDCsUsesADSiteDiscoveryOrder(t *testing.T) {
	original := orderedSRV
	defer func() { orderedSRV = original }()
	var names []string
	orderedSRV = func(service, proto, name string) (int, map[int]*net.SRV, error) {
		names = append(names, service+"/"+proto+"/"+name)
		if name == "dc._msdcs.EXAMPLE.ORG" {
			return 1, map[int]*net.SRV{1: {Target: "dc.example.org.", Port: 88}}, nil
		}
		return 0, nil, errors.New("not found")
	}
	c := New()
	c.LibDefaults.DNSLookupKDC = true
	c.LibDefaults.ADSite = "HQ"
	c.Realms = nil
	count, kdcs, err := c.GetKDCs("EXAMPLE.ORG", true)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, "dc.example.org:88", kdcs[1])
	assert.True(t, reflect.DeepEqual([]string{
		"kerberos/tcp/HQ._sites.dc._msdcs.EXAMPLE.ORG",
		"kerberos/tcp/dc._msdcs.EXAMPLE.ORG",
	}, names), "lookup order = %v", names)
}

func TestGetKpasswdServersFallsBackAfterLookupError(t *testing.T) {
	original := orderedSRV
	defer func() { orderedSRV = original }()
	var services []string
	orderedSRV = func(service, proto, name string) (int, map[int]*net.SRV, error) {
		services = append(services, service)
		if service == "kpasswd" {
			return 0, nil, errors.New("not found")
		}
		return 1, map[int]*net.SRV{1: {Target: "admin.example.org.", Port: 749}}, nil
	}
	c := New()
	c.LibDefaults.DNSLookupKDC = true
	count, servers, err := c.GetKpasswdServers("EXAMPLE.ORG", true)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, "admin.example.org:749", servers[1])
	assert.Equal(t, []string{"kpasswd", "kerberos-adm"}, services)
}

func TestResolveKDC(t *testing.T) {
	test.Privileged(t)

	c, err := NewFromString(testdata.KRB5_CONF)
	if err != nil {
		t.Fatal(err)
	}

	// KDCs when they're not provided and we should be looking them up.
	c.LibDefaults.DNSLookupKDC = true
	c.Realms = make([]Realm, 0)
	count, res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDC via DNS TCP: %v", err)
	}
	assert.Equal(t, 5, count, "Number of SRV records not as expected: %v", res)
	assert.Equal(t, count, len(res), "Map size does not match: %v", res)
	expected := []string{
		"kdc.test.gokrb5:88",
		"kdc1a.test.gokrb5:88",
		"kdc2a.test.gokrb5:88",
		"kdc1b.test.gokrb5:88",
		"kdc2b.test.gokrb5:88",
	}
	for _, s := range expected {
		var found bool
		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}
		assert.True(t, found, "Record %s not found in results", s)
	}
}

func TestResolveKDCNoDNS(t *testing.T) {
	c, err := NewFromString(testdata.KRB5_CONF)
	if err != nil {
		t.Fatal(err)
	}
	c.LibDefaults.DNSLookupKDC = false
	_, res, err := c.GetKDCs(c.LibDefaults.DefaultRealm, true)
	if err != nil {
		t.Errorf("error resolving KDCs from config: %v", err)
	}
	expected := []string{
		"127.0.0.1:88",
		"127.0.0.2:88",
	}
	for _, s := range expected {
		var found bool
		for _, v := range res {
			if s == v {
				found = true
				break
			}
		}
		assert.True(t, found, "Record %s not found in results", s)
	}
}
