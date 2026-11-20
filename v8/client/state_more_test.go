package client

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	clientTestOrgRealm    = "EXAMPLE.ORG"
	clientTestComRealm    = "EXAMPLE.COM"
	clientTestKDCAddress  = "127.0.0.1:88"
	diagnosticCredentials = "Credentials:"
)

func kdcTestRealmConfig(realm string, kdcs []string) config.Realm {
	var entry config.Realm
	entry.Realm = realm
	entry.KDC = kdcs
	return entry
}

func TestSessionStoreHandlesNilEntries(t *testing.T) {
	var nilStore *sessions
	nilStore.destroy()
	nilStore.update(nil)
	if session, ok := nilStore.get(clientTestOrgRealm); ok || session != nil {
		t.Fatalf("nil store get = %v, %v", session, ok)
	}

	var store sessions
	store.Entries = map[string]*session{clientTestOrgRealm: nil}
	if session, ok := store.get(clientTestOrgRealm); ok || session != nil {
		t.Fatalf("nil entry get = %v, %v", session, ok)
	}
	store.destroy()
	if len(store.Entries) != 0 {
		t.Fatalf("destroy left %d entries", len(store.Entries))
	}
	if data, err := store.JSON(); err != nil || data != "null" {
		t.Fatalf("empty JSON = %q, %v", data, err)
	}
}

func TestSessionLifecycleHelpers(t *testing.T) {
	now := time.Now().UTC()
	oldCancel := make(chan bool, 1)
	var old, replacement session
	old.realm, old.authTime, old.endTime, old.cancel = "Example.Org", now.Add(-time.Hour), now.Add(time.Hour), oldCancel
	var store sessions
	store.Entries = map[string]*session{clientTestOrgRealm: &old}
	replacement.realm = "example.org"
	replacement.authTime = now.Add(-time.Minute)
	replacement.startTime = now.Add(-time.Minute)
	replacement.endTime = now.Add(2 * time.Hour)
	replacement.renewTill = now.Add(3 * time.Hour)
	replacement.sessionKey = types.EncryptionKey{KeyType: 17, KeyValue: []byte("0123456789abcdef")}
	store.update(&replacement)
	select {
	case <-oldCancel:
	default:
		t.Fatal("replaced session was not cancelled")
	}
	got, ok := store.get(clientTestOrgRealm)
	if !ok || got != &replacement {
		t.Fatalf("replacement session = %p, %v", got, ok)
	}
	if !replacement.valid() {
		t.Fatal("current session reported invalid")
	}
	assertReplacementSessionDetails(t, &replacement)
	replacement.destroy()
	if replacement.valid() || replacement.endTime.After(time.Now().UTC()) {
		t.Fatal("destroyed session remained valid")
	}
	store.destroy()
	if len(store.Entries) != 0 {
		t.Fatalf("destroy left %d sessions", len(store.Entries))
	}
}

func assertReplacementSessionDetails(t *testing.T, replacement *session) {
	t.Helper()
	realm, _, key := replacement.tgtDetails()
	if realm != "example.org" || !bytes.Equal(key.KeyValue, replacement.sessionKey.KeyValue) {
		t.Fatalf("session details = %q/%x", realm, key.KeyValue)
	}
}

func TestClientSessionAccessAndSessionOnlyLogin(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	client := NewFromPrincipalName(principal, clientTestOrgRealm, cfg)
	now := time.Now().UTC()
	var current session
	current.realm = clientTestOrgRealm
	current.authTime = now.Add(-time.Hour)
	current.endTime = now.Add(time.Hour)
	current.renewTill = now.Add(2 * time.Hour)
	current.sessionKeyExpiration = now.Add(30 * time.Minute)
	current.tgt.Realm = clientTestOrgRealm
	current.sessionKey = types.EncryptionKey{KeyType: 17, KeyValue: []byte("key")}
	client.sessions.update(&current)

	if ok, err := client.IsConfigured(); !ok || err != nil {
		t.Fatalf("session-only client configuration = %v, %v", ok, err)
	}
	if err := client.Login(); err != nil {
		t.Fatalf("session-only login: %v", err)
	}
	if err := client.AffirmLogin(); err != nil {
		t.Fatalf("affirm current login: %v", err)
	}
	if err := client.ensureValidSession("example.org"); err != nil {
		t.Fatal(err)
	}
	assertClientSessionDetails(t, client, &current)
	current.endTime = now.Add(-time.Minute)
	if err := client.Login(); err == nil || !strings.Contains(err.Error(), "no valid existing session") {
		t.Fatalf("expired session login error = %v", err)
	}
}

func assertClientSessionDetails(t *testing.T, client *Client, current *session) {
	t.Helper()
	ticket, key, err := client.sessionTGT(clientTestOrgRealm)
	if err != nil || ticket.Realm != clientTestOrgRealm || string(key.KeyValue) != "key" {
		t.Fatalf("session TGT = %+v, %x, %v", ticket, key.KeyValue, err)
	}
	authTime, endTime, renewTill, keyExpiry, err := client.sessionTimes("example.org")
	if err != nil || !authTime.Equal(current.authTime) || !endTime.Equal(current.endTime) ||
		!renewTill.Equal(current.renewTill) || !keyExpiry.Equal(current.sessionKeyExpiration) {
		t.Fatalf("session times = %v/%v/%v/%v, %v", authTime, endTime, renewTill, keyExpiry, err)
	}
	if _, _, _, _, err := client.sessionTimes("missing"); err == nil {
		t.Fatal("missing session times returned no error")
	}
}

func TestClientConfigurationFailures(t *testing.T) {
	var zeroClient Client
	assertConfigurationFailure(t, &zeroClient, "nil configuration", "configuration")
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = clientTestOrgRealm
	assertConfigurationFailure(t, NewWithPassword("", clientTestOrgRealm, "password", cfg), "empty username", "username")
	cfg.LibDefaults.DefaultRealm = ""
	assertConfigurationFailure(t, NewWithPassword("alice", "", "password", cfg), "empty realm", "defined realm")
	cfg.LibDefaults.DefaultRealm = clientTestOrgRealm
	cfg.Realms = []config.Realm{kdcTestRealmConfig(clientTestOrgRealm, nil)}
	noKDC := NewWithPassword("alice", clientTestOrgRealm, "password", cfg)
	assertConfigurationFailure(t, noKDC, "realm without KDC", "defined KDCs")

	cfg.LibDefaults.DNSLookupKDC = true
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	withoutCredentials := NewFromPrincipalName(principal, clientTestOrgRealm, cfg)
	assertConfigurationFailure(t, withoutCredentials, "missing credentials", "neither a keytab nor a password")
	if err := withoutCredentials.AffirmLogin(); err == nil || !strings.Contains(err.Error(), "could not get valid TGT") {
		t.Fatalf("AffirmLogin error = %v", err)
	}
}

func assertConfigurationFailure(t *testing.T, client *Client, name, want string) {
	t.Helper()
	if ok, err := client.IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s = %v, %v", name, ok, err)
	}
}

func TestClientDiagnosticsPrintAndDestroy(t *testing.T) {
	cfg := config.New()
	client := NewWithPassword("alice", clientTestOrgRealm, "password", cfg)
	var output bytes.Buffer
	if err := client.Diagnostics(&output); err == nil || !strings.Contains(err.Error(), "no KDCs") {
		t.Fatalf("Diagnostics error = %v", err)
	}
	for _, section := range []string{diagnosticCredentials, "TGT Sessions:", "Settings:"} {
		if !strings.Contains(output.String(), section) {
			t.Fatalf("diagnostic output = %q", output.String())
		}
	}

	assertClientDestroyClearsState(t, client, cfg)
}

func assertClientDestroyClearsState(t *testing.T, client *Client, cfg *config.Config) {
	t.Helper()
	now := time.Now().UTC()
	var current session
	current.realm = clientTestOrgRealm
	current.authTime = now.Add(-time.Hour)
	current.endTime = now.Add(time.Hour)
	client.sessions.Entries[clientTestOrgRealm] = &current
	client.setPKINITReplyKey(clientTestOrgRealm, types.EncryptionKey{KeyType: 17, KeyValue: []byte{1, 2, 3}})
	storedKey := client.pkinitKeys[clientTestOrgRealm].KeyValue
	credentialBytes := []byte{4, 5, 6}
	var supplemental pac.SECPKGSupplementalCred
	supplemental.CredentialSize = 3
	supplemental.Credentials = credentialBytes
	client.pkinitCreds = &pac.CredentialData{
		CredentialCount: 1,
		Credentials:     []pac.SECPKGSupplementalCred{supplemental},
	}
	client.fastArmorCl = NewWithPassword("armor", clientTestOrgRealm, "password", cfg)
	client.Destroy()
	hasLoginState := client.Credentials.UserName() != "" || len(client.sessions.Entries) != 0
	hasArmorOrCredentials := client.fastArmorCl != nil || client.pkinitCreds != nil
	if hasLoginState || hasArmorOrCredentials {
		t.Fatal("Destroy did not clear client state")
	}
	if !bytes.Equal(storedKey, []byte{0, 0, 0}) || !bytes.Equal(credentialBytes, []byte{0, 0, 0}) {
		t.Fatalf("sensitive bytes not zeroed: %v/%v", storedKey, credentialBytes)
	}
}

func TestClientPrintWithEmptyState(t *testing.T) {
	var client Client
	var store sessions
	store.Entries = make(map[string]*session)
	client.Credentials = credentials.New("alice", clientTestOrgRealm)
	client.Config = config.New()
	client.settings = NewSettings()
	client.sessions = &store
	client.cache = NewCache()
	client.s4uCache = NewCache()
	var output bytes.Buffer
	client.Print(&output)
	if !strings.Contains(output.String(), "Service ticket cache:") {
		t.Fatalf("Print output = %q", output.String())
	}
}

func TestClientDiagnosticsConfiguredKeytab(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.AES128_CTS_HMAC_SHA1_96)}
	cfg.Realms = []config.Realm{kdcTestRealmConfig(clientTestOrgRealm, []string{clientTestKDCAddress})}
	kt := keytab.New()
	principal := keytab.Principal{
		Realm:      clientTestOrgRealm,
		Components: []string{"alice"},
		NameType:   nametype.KRB_NT_PRINCIPAL,
	}
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	if err := kt.AddKey(principal, 1, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	client := NewWithKeytab("alice", clientTestOrgRealm, kt, cfg)
	var output bytes.Buffer
	if err := client.Diagnostics(&output); err != nil {
		t.Fatalf("configured diagnostics: %v", err)
	}
	if !strings.Contains(output.String(), "UDP KDCs:") || !strings.Contains(output.String(), "TCP KDCs:") {
		t.Fatalf("diagnostic output = %q", output.String())
	}

	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.AES256_CTS_HMAC_SHA1_96)}
	if err := client.Diagnostics(io.Discard); err == nil ||
		!strings.Contains(err.Error(), "default_tkt_enctypes") ||
		!strings.Contains(err.Error(), "preferred_preauth_types") {
		t.Fatalf("mismatched diagnostics = %v", err)
	}
}
