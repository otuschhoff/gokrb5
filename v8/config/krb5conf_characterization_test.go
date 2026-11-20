package config

import (
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

func TestLibDefaultsLegacyEnctypePolicy(t *testing.T) {
	t.Parallel()

	const names = "rc4-hmac arcfour-hmac aes128-sha1 arcfour-hmac-md5 des3-cbc-sha1-kd des3-cbc-sha1 rc4-hmac-exp"
	lists := "default_tgs_enctypes=" + names + "\n" +
		"default_tkt_enctypes=" + names + "\npermitted_enctypes=" + names + "\n"
	aesDefaults := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}
	aes128 := etypeID.AES128_CTS_HMAC_SHA1_96
	rc4 := etypeID.RC4_HMAC
	for _, tc := range []struct {
		name string
		body string
		want []int32
	}{
		{name: "defaults", want: aesDefaults},
		{name: "opt-in without lists", body: "allow_weak_crypto=true\n", want: aesDefaults},
		{name: "lists without opt-in", body: lists, want: []int32{aes128}},
		{
			name: "explicit opt-in", body: lists + "allow_weak_crypto=true\n",
			want: []int32{rc4, rc4, aes128, rc4, etypeID.DES3_CBC_SHA1_KD},
		},
		{
			name: "opt-in overridden", body: "allow_weak_crypto=true\n" + lists + "allow_weak_crypto=false\n",
			want: []int32{aes128},
		},
		{
			name: "legacy-only lists have no fallback",
			body: "default_tkt_enctypes=rc4-hmac\ndefault_tgs_enctypes=arcfour-hmac\npermitted_enctypes=des3-cbc-sha1-kd\n",
			want: []int32{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := NewFromString("[libdefaults]\n" + tc.body)
			if err != nil {
				t.Fatal(err)
			}
			d := cfg.LibDefaults
			if !slices.Equal(d.DefaultTktEnctypeIDs, tc.want) ||
				!slices.Equal(d.DefaultTGSEnctypeIDs, tc.want) ||
				!slices.Equal(d.PermittedEnctypeIDs, tc.want) {
				t.Fatalf("AS/TGS/permitted = %v/%v/%v; want %v in each",
					d.DefaultTktEnctypeIDs, d.DefaultTGSEnctypeIDs, d.PermittedEnctypeIDs, tc.want)
			}
		})
	}
}

func TestLibDefaultsLineAndCollectionSemantics(t *testing.T) {
	const (
		aes128 = "aes128-cts-hmac-sha256-128"
		aes256 = "aes256-cts-hmac-sha384-192"
	)
	l := newLibDefaults()
	l.ExtraAddresses = []net.IP{net.ParseIP("192.0.2.9")}
	err := l.parseLines([]string{
		" # ignored", " ; ignored", " \t ", "UnKnOwN = ignored",
		" DEFAULT_REALM = first=discarded ; trailing",
		"default_realm = second#discarded",
		"default_tgs_enctypes = " + aes128,
		"default_tgs_enctypes = " + aes256 + " \t " + aes128,
		"default_tkt_enctypes = " + aes256,
		"default_tkt_enctypes = " + aes128,
		"permitted_enctypes = " + aes256, "permitted_enctypes = ",
		"pkinit_anchors = FILE:first", "pkinit_anchors = FILE:second=discarded",
		"pkinit_identities = first", "pkinit_identities = second",
		"pkinit_pool = first", "pkinit_pool = second", "pkinit_pool = ",
		"preferred_preauth_types = 14,15", "preferred_preauth_types = 17,16,17 ",
		"extra_addresses = 192.0.2.1, 192.0.2.2,invalid,2001:db8::1 ",
		"extra_addresses = 192.0.2.3",
		"kdc_default_options = 0x000x10",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := newLibDefaults()
	want.DefaultRealm = "second"
	want.DefaultTGSEnctypes = []string{aes256, aes128}
	want.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.AES128_CTS_HMAC_SHA256_128}
	want.DefaultTktEnctypes = []string{aes128}
	want.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA256_128}
	want.PermittedEnctypes = []string{}
	want.PermittedEnctypeIDs = nil
	want.PKINITAnchors = []string{"FILE:first", "FILE:second"}
	want.PKINITIdentities = []string{"first", "second"}
	want.PKINITPool = []string{"first", "second", ""}
	want.PreferredPreauthTypes = []int{17, 16, 17}
	want.ExtraAddresses = []net.IP{
		net.ParseIP("192.0.2.9"), net.ParseIP("192.0.2.1"),
		net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.3"),
	}
	want.KDCDefaultOptions.Bytes = []byte{0, 16}
	want.KDCDefaultOptions.BitLength = 16
	if !reflect.DeepEqual(l, want) {
		t.Fatalf("parsed defaults = %+v, want %+v", l, want)
	}
}

func TestLibDefaultsBooleanFailureContextAndMutation(t *testing.T) {
	keys := []string{
		"allow_weak_crypto", "canonicalize", "request_pac", "pkinit_require_crl_checking",
		"dns_canonicalize_hostname", "dns_lookup_kdc", "dns_lookup_realm", "forwardable",
		"ignore_acceptor_hostname", "k5login_authoritative", "noaddresses", "proxiable",
		"rdns", "verify_ap_req_nofail",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			l := newLibDefaults()
			want := newLibDefaults()
			want.DefaultRealm = "before"
			line := strings.ToUpper(key) + " = maybe=ignored"
			err := l.parseLines([]string{"default_realm=before", " \t" + line + " # comment", "default_realm=after"})
			assertLibDefaultsFailure(t, l, want, err,
				"libdefaults section line ("+line+"): invalid boolean value")
		})
	}
}

func TestLibDefaultsValueFailureMutation(t *testing.T) {
	const (
		invalidDHMinimumDetail = ": invalid PKINIT DH minimum"
		invalidDurationDetail  = ": invalid time duration"
	)
	tests := []struct {
		name   string
		line   string
		detail string
	}{
		{"missing_equals", "missing equals", ""},
		{"ccache_negative", "ccache_type=-1", ""},
		{"ccache_bound", "ccache_type=5", ""},
		{"ccache_overflow", "ccache_type=4294967296", ""},
		{"ccache_syntax", "ccache_type=x", ""},
		{"timesync_negative", "kdc_timesync=-1", ""},
		{"timesync_overflow", "kdc_timesync=2147483648", ""},
		{"timesync_syntax", "kdc_timesync=x", ""},
		{"checksum_negative", "safe_checksum_type=-1", ""},
		{"checksum_overflow", "safe_checksum_type=2147483648", ""},
		{"checksum_syntax", "safe_checksum_type=x", ""},
		{"realm_bound", "realm_try_domains=-2", ""},
		{"realm_overflow", "realm_try_domains=2147483648", ""},
		{"realm_syntax", "realm_try_domains=x", ""},
		{"udp_negative", "udp_preference_limit=-1", ""},
		{"udp_bound", "udp_preference_limit=32701", ""},
		{"udp_overflow", "udp_preference_limit=4294967296", ""},
		{"udp_syntax", "udp_preference_limit=x", ""},
		{"dh_bound", "pkinit_dh_min_bits=1023", invalidDHMinimumDetail},
		{"dh_syntax", "pkinit_dh_min_bits=x", invalidDHMinimumDetail},
		{"dh_overflow", "pkinit_dh_min_bits=9999999999999999999999999", invalidDHMinimumDetail},
		{"eku_case", "pkinit_eku_checking=KDC", ": invalid PKINIT EKU checking mode"},
		{"preauth_space", "preferred_preauth_types=17, 16", `: strconv.ParseInt: parsing " 16": invalid syntax`},
		{"preauth_empty", "preferred_preauth_types=", `: strconv.ParseInt: parsing "": invalid syntax`},
		{
			"preauth_overflow",
			"preferred_preauth_types=17,2147483648",
			`: strconv.ParseInt: parsing "2147483648": value out of range`,
		},
		{"options_partial", "kdc_default_options=00ffz0", ": encoding/hex: invalid byte: U+007A 'z'"},
		{"options_odd", "kdc_default_options=0x1", ": encoding/hex: odd length hex string"},
		{"options_upper_prefix", "kdc_default_options=0X10", ": encoding/hex: invalid byte: U+0058 'X'"},
		{"clockskew", "clockskew=invalid", invalidDurationDetail},
		{"renew_lifetime", "renew_lifetime=invalid", invalidDurationDetail},
		{"ticket_lifetime", "ticket_lifetime=invalid", invalidDurationDetail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLibDefaults()
			want := newLibDefaults()
			want.DefaultRealm = "before"
			err := l.parseLines([]string{"default_realm=before", tt.line, "default_realm=after"})
			assertLibDefaultsFailure(t, l, want, err, "libdefaults section line ("+tt.line+")"+tt.detail)
		})
	}
}

func assertLibDefaultsFailure(t *testing.T, got, want LibDefaults, err error, text string) {
	t.Helper()
	wantErr := InvalidErrorf("%s", text)
	if err == nil || err.Error() != wantErr.Error() || reflect.TypeOf(err) != reflect.TypeOf(wantErr) {
		t.Fatalf("error = %T %v, want %T %v", err, err, wantErr, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults after error = %+v, want %+v", got, want)
	}
}

func TestLibDefaultsNumericAndEKUBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
	}{
		{"lower", []string{
			"ccache_type=0",
			"pkinit_dh_min_bits=1024",
			"kdc_timesync=0",
			"safe_checksum_type=0",
			"realm_try_domains=-1",
			"udp_preference_limit=0",
			"pkinit_eku_checking=kdc",
		}},
		{"upper", []string{
			"ccache_type=4",
			"pkinit_dh_min_bits=2147483647",
			"kdc_timesync=2147483647",
			"safe_checksum_type=2147483647",
			"realm_try_domains=2147483647",
			"udp_preference_limit=32700",
			"pkinit_eku_checking=kpServerAuth",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLibDefaults()
			if err := l.parseLines(tt.lines); err != nil {
				t.Fatal(err)
			}
			want := []int{0, 1024, 0, 0, -1, 0}
			eku := "kdc"
			if tt.name == "upper" {
				want = []int{4, 2147483647, 2147483647, 2147483647, 2147483647, 32700}
				eku = "kpServerAuth"
			}
			got := []int{
				l.CCacheType, l.PKINITDHMinBits, l.KDCTimeSync,
				l.SafeChecksumType, l.RealmTryDomains, l.UDPPreferenceLimit,
			}
			if !reflect.DeepEqual(got, want) || l.PKINITEKUChecking != eku {
				t.Fatalf("numeric values = %v, EKU = %q; want %v, %q", got, l.PKINITEKUChecking, want, eku)
			}
		})
	}
}

func TestLibDefaultsEnctypeFinalizationTiming(t *testing.T) {
	const (
		desCBCMD5     = "des-cbc-md5"
		aes128CTSSHA1 = "aes128-cts-hmac-sha1-96"
	)
	for _, weak := range []string{"true", "false"} {
		t.Run(weak, func(t *testing.T) {
			l := newLibDefaults()
			lines := []string{
				"default_tgs_enctypes=des-cbc-md5 aes128-cts-hmac-sha1-96",
				"default_tkt_enctypes=des-cbc-md5 aes128-cts-hmac-sha1-96",
				"permitted_enctypes=des-cbc-md5 aes128-cts-hmac-sha1-96",
				"allow_weak_crypto=true", "allow_weak_crypto=" + weak,
			}
			want := newLibDefaults()
			want.DefaultTGSEnctypes = []string{desCBCMD5, aes128CTSSHA1}
			want.DefaultTktEnctypes = []string{desCBCMD5, aes128CTSSHA1}
			want.PermittedEnctypes = []string{desCBCMD5, aes128CTSSHA1}
			want.AllowWeakCrypto = weak == "true"
			err := l.parseLines(append(lines, "no equals"))
			assertLibDefaultsFailure(t, l, want, err, "libdefaults section line (no equals)")
			if err := l.parseLines(nil); err != nil {
				t.Fatal(err)
			}
			ids := []int32{17}
			if !reflect.DeepEqual(l.DefaultTGSEnctypeIDs, ids) ||
				!reflect.DeepEqual(l.DefaultTktEnctypeIDs, ids) || !reflect.DeepEqual(l.PermittedEnctypeIDs, ids) {
				t.Fatalf(
					"final IDs = %v, %v, %v; want %v",
					l.DefaultTGSEnctypeIDs,
					l.DefaultTktEnctypeIDs,
					l.PermittedEnctypeIDs,
					ids,
				)
			}
			l = newLibDefaults()
			if err := l.parseLines(lines); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(l.DefaultTGSEnctypeIDs, ids) ||
				!reflect.DeepEqual(l.DefaultTktEnctypeIDs, ids) || !reflect.DeepEqual(l.PermittedEnctypeIDs, ids) {
				t.Fatal("successful parse did not use final weak-crypto setting")
			}
		})
	}
}
