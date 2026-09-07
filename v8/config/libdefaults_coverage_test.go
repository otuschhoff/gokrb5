package config

import (
	"strings"
	"testing"
	"time"
)

func TestLibDefaultsAllSupportedDirectives(t *testing.T) {
	configuration, err := NewFromString(`[libdefaults]
allow_weak_crypto = yes
ad_site = Site-A
canonicalize = y
request_pac = no
pkinit_anchors = FILE:/ca.pem
pkinit_identities = FILE:/cert.pem,/key.pem
pkinit_kdc_hostname = kdc.example.org
pkinit_eku_checking = none
pkinit_require_crl_checking = true
pkinit_dh_min_bits = 3072
pkinit_pool = FILE:/pool.pem
ccache_type = 3
clockskew = 6m
 default_client_keytab_name = FILE:/client.keytab
default_ccache_name = FILE:/cache
default_keytab_name = FILE:/server.keytab
default_realm = EXAMPLE.ORG
default_tgs_enctypes = aes128-cts-hmac-sha1-96 des-cbc-md5
default_tkt_enctypes = aes256-cts-hmac-sha1-96
 dns_canonicalize_hostname = no
dns_lookup_kdc = yes
dns_lookup_realm = y
extra_addresses = 192.0.2.1,not-an-ip,2001:db8::1
forwardable = true
ignore_acceptor_hostname = yes
k5login_authoritative = no
k5login_directory = /tmp/login
kdc_default_options = 0x40000000
kdc_timesync = 2
noaddresses = false
permitted_enctypes = aes128-cts-hmac-sha1-96
preferred_preauth_types = 17,16
proxiable = yes
rdns = no
realm_try_domains = -1
renew_lifetime = 1d2h
safe_checksum_type = 12
ticket_lifetime = 10h
udp_preference_limit = 1200
verify_ap_req_nofail = yes
`)
	if err != nil {
		t.Fatal(err)
	}
	defaults := configuration.LibDefaults
	if !defaults.AllowWeakCrypto || defaults.ADSite != "Site-A" || !defaults.Canonicalize || defaults.RequestPAC ||
		len(defaults.PKINITAnchors) != 1 || len(defaults.PKINITIdentities) != 1 || defaults.PKINITKDCHostname != "kdc.example.org" ||
		defaults.PKINITEKUChecking != "none" || !defaults.PKINITRequireCRLCheck || defaults.PKINITDHMinBits != 3072 ||
		defaults.CCacheType != 3 || defaults.Clockskew != 6*time.Minute || len(defaults.ExtraAddresses) != 2 ||
		defaults.KDCTimeSync != 2 || defaults.RealmTryDomains != -1 || defaults.RenewLifetime != 26*time.Hour ||
		defaults.TicketLifetime != 10*time.Hour || defaults.UDPPreferenceLimit != 1200 || !defaults.VerifyAPReqNofail {
		t.Fatalf("parsed libdefaults = %+v", defaults)
	}
}

func TestLibDefaultsRejectInvalidValues(t *testing.T) {
	invalid := []string{
		"line without equals", "allow_weak_crypto = maybe", "canonicalize = maybe", "request_pac = maybe",
		"pkinit_eku_checking = invalid", "pkinit_require_crl_checking = maybe", "pkinit_dh_min_bits = 512",
		"ccache_type = 5", "clockskew = invalid", "dns_canonicalize_hostname = maybe", "dns_lookup_kdc = maybe",
		"dns_lookup_realm = maybe", "forwardable = maybe", "ignore_acceptor_hostname = maybe",
		"k5login_authoritative = maybe", "kdc_default_options = xyz", "kdc_timesync = -1", "noaddresses = maybe",
		"preferred_preauth_types = x", "proxiable = maybe", "rdns = maybe", "realm_try_domains = -2",
		"renew_lifetime = invalid", "safe_checksum_type = -1", "ticket_lifetime = invalid",
		"udp_preference_limit = 32701", "verify_ap_req_nofail = maybe",
	}
	for _, line := range invalid {
		t.Run(strings.Fields(line)[0], func(t *testing.T) {
			if _, err := NewFromString("[libdefaults]\n" + line + "\n"); err == nil {
				t.Fatalf("accepted invalid directive %q", line)
			}
		})
	}
}

func TestBooleanAndDurationVariants(t *testing.T) {
	for value, want := range map[string]bool{"true": true, "false": false, "yes": true, "Y": true, "no": false, "N": false} {
		got, err := parseBoolean(value)
		if err != nil || got != want {
			t.Fatalf("parseBoolean(%q) = %v, %v", value, got, err)
		}
	}
	for value, want := range map[string]time.Duration{"2d": 48 * time.Hour, "2d3m4s": 48*time.Hour + 3*time.Minute + 4*time.Second, "90": 90 * time.Second, "1:02": time.Hour + 2*time.Minute, "1:02:03": time.Hour + 2*time.Minute + 3*time.Second} {
		got, err := parseDuration(value)
		if err != nil || got != want {
			t.Fatalf("parseDuration(%q) = %v, %v", value, got, err)
		}
	}
	for _, value := range []string{"xd", "1dbad", "1:2:3:4", "1:x"} {
		if _, err := parseDuration(value); err == nil {
			t.Fatalf("parseDuration(%q) accepted invalid value", value)
		}
	}
}
