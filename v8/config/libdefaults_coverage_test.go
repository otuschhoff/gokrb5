package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const allSupportedLibDefaults = `[libdefaults]
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
`

func TestLibDefaultsAllSupportedDirectives(t *testing.T) {
	configuration, err := NewFromString(allSupportedLibDefaults)
	require.NoError(t, err)
	require.NotNil(t, configuration)

	defaults := configuration.LibDefaults
	is := assert.New(t)
	is.True(defaults.AllowWeakCrypto, "allow_weak_crypto")
	is.Equal("Site-A", defaults.ADSite, "ad_site")
	is.True(defaults.Canonicalize, "canonicalize")
	is.False(defaults.RequestPAC, "request_pac")
	is.Len(defaults.PKINITAnchors, 1, "pkinit_anchors")
	is.Len(defaults.PKINITIdentities, 1, "pkinit_identities")
	is.Equal("kdc.example.org", defaults.PKINITKDCHostname, "pkinit_kdc_hostname")
	is.Equal("none", defaults.PKINITEKUChecking, "pkinit_eku_checking")
	is.True(defaults.PKINITRequireCRLCheck, "pkinit_require_crl_checking")
	is.Equal(3072, defaults.PKINITDHMinBits, "pkinit_dh_min_bits")
	is.Equal(3, defaults.CCacheType, "ccache_type")
	is.Equal(6*time.Minute, defaults.Clockskew, "clockskew")
	is.Len(defaults.ExtraAddresses, 2, "extra_addresses")
	is.Equal(2, defaults.KDCTimeSync, "kdc_timesync")
	is.Equal(-1, defaults.RealmTryDomains, "realm_try_domains")
	is.Equal(26*time.Hour, defaults.RenewLifetime, "renew_lifetime")
	is.Equal(10*time.Hour, defaults.TicketLifetime, "ticket_lifetime")
	is.Equal(1200, defaults.UDPPreferenceLimit, "udp_preference_limit")
	is.True(defaults.VerifyAPReqNofail, "verify_ap_req_nofail")
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

func TestParseBooleanVariants(t *testing.T) {
	const trueLiteral = "true"
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "true word", input: trueLiteral, want: true},
		{name: "false word", input: "false", want: false},
		{name: "yes word", input: "yes", want: true},
		{name: "uppercase yes initial", input: "Y", want: true},
		{name: "no word", input: "no", want: false},
		{name: "uppercase no initial", input: "N", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBoolean(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseDurationVariants(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{name: "days only", input: "2d", want: 48 * time.Hour},
		{name: "days with suffix", input: "2d3m4s", want: 48*time.Hour + 3*time.Minute + 4*time.Second},
		{name: "seconds without unit", input: "90", want: 90 * time.Second},
		{name: "hours and minutes", input: "1:02", want: time.Hour + 2*time.Minute},
		{name: "hours minutes and seconds", input: "1:02:03", want: time.Hour + 2*time.Minute + 3*time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseDurationRejectsInvalidVariants(t *testing.T) {
	for _, value := range []string{"xd", "1dbad", "1:2:3:4", "1:x"} {
		t.Run(value, func(t *testing.T) {
			_, err := parseDuration(value)
			require.Error(t, err)
		})
	}
}
