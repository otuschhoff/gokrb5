package config

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
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
	t.Parallel()

	names := []string{}
	lookup := func(service, proto, name string) (int, map[int]*net.SRV, error) {
		names = append(names, service+"/"+proto+"/"+name)
		if name == "dc._msdcs.EXAMPLE.ORG" {
			return 2, map[int]*net.SRV{
				1: {Target: "dc.example.org.", Port: 88, Priority: 0, Weight: 0},
				2: {Target: "backup.example.org.", Port: 188, Priority: 1, Weight: 0},
			}, nil
		}
		return 0, nil, errors.New("not found")
	}
	c := New()
	c.LibDefaults.DNSLookupKDC = true
	c.LibDefaults.ADSite = "HQ"
	count, kdcs, err := c.getKDCs("EXAMPLE.ORG", true, lookup)
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, map[int]string{1: "dc.example.org:88", 2: "backup.example.org:188"}, kdcs)
	assert.Equal(t, []string{
		"kerberos/tcp/HQ._sites.dc._msdcs.EXAMPLE.ORG",
		"kerberos/tcp/dc._msdcs.EXAMPLE.ORG",
	}, names)
}

func TestGetKpasswdServersFallsBackAfterLookupError(t *testing.T) {
	t.Parallel()

	queries := []string{}
	lookup := func(service, proto, name string) (int, map[int]*net.SRV, error) {
		queries = append(queries, service+"/"+proto+"/"+name)
		if service == "kpasswd" {
			return 0, nil, errors.New("not found")
		}
		return 1, map[int]*net.SRV{1: {Target: "admin.example.org.", Port: 749, Priority: 0, Weight: 0}}, nil
	}
	c := New()
	c.LibDefaults.DNSLookupKDC = true
	count, servers, err := c.getKpasswdServers("EXAMPLE.ORG", true, lookup)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, "admin.example.org:749", servers[1])
	assert.Equal(t, []string{"kpasswd/tcp/EXAMPLE.ORG", "kerberos-adm/tcp/EXAMPLE.ORG"}, queries)
}

func TestHostDiscoveryRetainsLastLookupError(t *testing.T) {
	t.Parallel()

	firstErr := errors.New("first SRV lookup failed")
	lastErr := errors.New("last SRV lookup failed")
	for _, tt := range []struct {
		name        string
		discover    func(*Config, string, bool, srvLookup) (int, map[int]string, error)
		lookupErrs  []error
		wantQueries []string
	}{
		{
			name:       "kdc after empty realm answer",
			discover:   (*Config).getKDCs,
			lookupErrs: []error{firstErr, lastErr, nil},
			wantQueries: []string{
				"kerberos/udp/HQ._sites.dc._msdcs.EXAMPLE.ORG",
				"kerberos/udp/dc._msdcs.EXAMPLE.ORG",
				"kerberos/udp/EXAMPLE.ORG",
			},
		},
		{
			name:        "password server after lookup failures",
			discover:    (*Config).getKpasswdServers,
			lookupErrs:  []error{firstErr, lastErr},
			wantQueries: []string{"kpasswd/udp/EXAMPLE.ORG", "kerberos-adm/udp/EXAMPLE.ORG"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			queries := make([]string, 0, len(tt.wantQueries))
			lookup := func(service, proto, name string) (int, map[int]*net.SRV, error) {
				i := len(queries)
				if i >= len(tt.lookupErrs) {
					t.Fatal("unexpected extra SRV lookup")
				}
				queries = append(queries, service+"/"+proto+"/"+name)
				return 0, nil, tt.lookupErrs[i]
			}
			cfg := New()
			cfg.LibDefaults.DNSLookupKDC = true
			cfg.LibDefaults.ADSite = "HQ"
			count, hosts, err := tt.discover(cfg, "EXAMPLE.ORG", false, lookup)
			assert.Equal(t, tt.wantQueries, queries)
			assert.Same(t, lastErr, err)
			assert.Zero(t, count)
			assert.Equal(t, map[int]string{}, hosts)
		})
	}
}

func TestHostDiscoveryWithNoSRVRecords(t *testing.T) {
	t.Parallel()

	const realmName = "EXAMPLE.ORG"
	cfg := New()
	cfg.LibDefaults.DefaultRealm = realmName
	cfg.LibDefaults.DNSLookupKDC = true
	var realm Realm
	realm.Realm = realmName
	realm.AdminServer = []string{"admin.example.org:749"}
	cfg.Realms = []Realm{realm}
	lookup := func(_, _, _ string) (int, map[int]*net.SRV, error) {
		return 0, nil, nil
	}

	count, hosts, err := cfg.getKDCs("", false, lookup)
	assert.EqualError(t, err, "no KDC SRV records found for realm "+realmName)
	assert.Zero(t, count)
	assert.Equal(t, map[int]string{}, hosts)

	count, hosts, err = cfg.getKpasswdServers(realmName, false, lookup)
	assert.EqualError(t, err, "no kpasswd or kadmin SRV records found for realm "+realmName)
	assert.Zero(t, count)
	assert.Equal(t, map[int]string{}, hosts)
}

func TestGetKpasswdServersDoesNotOverwriteConfigStorage(t *testing.T) {
	t.Parallel()

	backing := []string{"keep"}
	cfg := New()
	cfg.LibDefaults.DNSLookupKDC = false
	var realm Realm
	realm.Realm = "EXAMPLE.ORG"
	realm.KPasswdServer = backing[:0]
	realm.AdminServer = []string{"admin.example.org:749", "missing-port"}
	cfg.Realms = []Realm{realm}

	count, hosts, err := cfg.GetKpasswdServers("example.org", true)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, map[int]string{1: "admin.example.org:464"}, hosts)
	assert.Equal(t, []string{"keep"}, backing)
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
