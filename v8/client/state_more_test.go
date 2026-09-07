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
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestSessionLifecycleHelpers(t *testing.T) {
	now := time.Now().UTC()
	oldCancel := make(chan bool, 1)
	old := &session{realm: "Example.Org", authTime: now.Add(-time.Hour), endTime: now.Add(time.Hour), cancel: oldCancel}
	store := &sessions{Entries: map[string]*session{"EXAMPLE.ORG": old}}
	replacement := &session{
		realm: "example.org", authTime: now.Add(-time.Minute), startTime: now.Add(-time.Minute),
		endTime: now.Add(2 * time.Hour), renewTill: now.Add(3 * time.Hour),
		sessionKey: types.EncryptionKey{KeyType: 17, KeyValue: []byte("0123456789abcdef")},
	}
	store.update(replacement)
	select {
	case <-oldCancel:
	default:
		t.Fatal("replaced session was not cancelled")
	}
	got, ok := store.get("EXAMPLE.ORG")
	if !ok || got != replacement {
		t.Fatalf("replacement session = %p, %v", got, ok)
	}
	if !replacement.valid() {
		t.Fatal("current session reported invalid")
	}
	realm, _, key := replacement.tgtDetails()
	if realm != "example.org" || !bytes.Equal(key.KeyValue, replacement.sessionKey.KeyValue) {
		t.Fatalf("session details = %q/%x", realm, key.KeyValue)
	}
	replacement.destroy()
	if replacement.valid() || replacement.endTime.After(time.Now().UTC()) {
		t.Fatal("destroyed session remained valid")
	}
	store.destroy()
	if len(store.Entries) != 0 {
		t.Fatalf("destroy left %d sessions", len(store.Entries))
	}
}

func TestClientSessionAccessAndSessionOnlyLogin(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	client := NewFromPrincipalName(principal, "EXAMPLE.ORG", cfg)
	now := time.Now().UTC()
	current := &session{
		realm: "EXAMPLE.ORG", authTime: now.Add(-time.Hour), endTime: now.Add(time.Hour),
		renewTill: now.Add(2 * time.Hour), sessionKeyExpiration: now.Add(30 * time.Minute),
		tgt: messages.Ticket{Realm: "EXAMPLE.ORG"}, sessionKey: types.EncryptionKey{KeyType: 17, KeyValue: []byte("key")},
	}
	client.sessions.update(current)

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
	ticket, key, err := client.sessionTGT("EXAMPLE.ORG")
	if err != nil || ticket.Realm != "EXAMPLE.ORG" || string(key.KeyValue) != "key" {
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

	current.endTime = now.Add(-time.Minute)
	if err := client.Login(); err == nil || !strings.Contains(err.Error(), "no valid existing session") {
		t.Fatalf("expired session login error = %v", err)
	}
}

func TestClientConfigurationFailures(t *testing.T) {
	if ok, err := (&Client{}).IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("nil configuration = %v, %v", ok, err)
	}
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.ORG"
	if ok, err := NewWithPassword("", "EXAMPLE.ORG", "password", cfg).IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("empty username = %v, %v", ok, err)
	}
	cfg.LibDefaults.DefaultRealm = ""
	if ok, err := NewWithPassword("alice", "", "password", cfg).IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), "defined realm") {
		t.Fatalf("empty realm = %v, %v", ok, err)
	}
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.ORG"
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG"}}
	if ok, err := NewWithPassword("alice", "EXAMPLE.ORG", "password", cfg).IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), "defined KDCs") {
		t.Fatalf("realm without KDC = %v, %v", ok, err)
	}

	cfg.LibDefaults.DNSLookupKDC = true
	withoutCredentials := NewFromPrincipalName(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), "EXAMPLE.ORG", cfg)
	if ok, err := withoutCredentials.IsConfigured(); ok || err == nil || !strings.Contains(err.Error(), "neither a keytab nor a password") {
		t.Fatalf("missing credentials = %v, %v", ok, err)
	}
	if err := withoutCredentials.AffirmLogin(); err == nil || !strings.Contains(err.Error(), "could not get valid TGT") {
		t.Fatalf("AffirmLogin error = %v", err)
	}
}

func TestClientDiagnosticsPrintAndDestroy(t *testing.T) {
	cfg := config.New()
	client := NewWithPassword("alice", "EXAMPLE.ORG", "password", cfg)
	var output bytes.Buffer
	if err := client.Diagnostics(&output); err == nil || !strings.Contains(err.Error(), "no KDCs") {
		t.Fatalf("Diagnostics error = %v", err)
	}
	if !strings.Contains(output.String(), "Credentials:") || !strings.Contains(output.String(), "TGT Sessions:") || !strings.Contains(output.String(), "Settings:") {
		t.Fatalf("diagnostic output = %q", output.String())
	}

	now := time.Now().UTC()
	client.sessions.Entries["EXAMPLE.ORG"] = &session{realm: "EXAMPLE.ORG", authTime: now.Add(-time.Hour), endTime: now.Add(time.Hour)}
	client.setPKINITReplyKey("EXAMPLE.ORG", types.EncryptionKey{KeyType: 17, KeyValue: []byte{1, 2, 3}})
	storedKey := client.pkinitKeys["EXAMPLE.ORG"].KeyValue
	credentialBytes := []byte{4, 5, 6}
	client.pkinitCreds = &pac.CredentialData{CredentialCount: 1, Credentials: []pac.SECPKGSupplementalCred{{CredentialSize: 3, Credentials: credentialBytes}}}
	client.fastArmorCl = NewWithPassword("armor", "EXAMPLE.ORG", "password", cfg)
	client.Destroy()
	if client.Credentials.UserName() != "" || len(client.sessions.Entries) != 0 || client.fastArmorCl != nil || client.pkinitCreds != nil {
		t.Fatal("Destroy did not clear client state")
	}
	if !bytes.Equal(storedKey, []byte{0, 0, 0}) || !bytes.Equal(credentialBytes, []byte{0, 0, 0}) {
		t.Fatalf("sensitive bytes not zeroed: %v/%v", storedKey, credentialBytes)
	}
}

func TestClientPrintWithEmptyState(t *testing.T) {
	client := &Client{
		Credentials: credentials.New("alice", "EXAMPLE.ORG"), Config: config.New(), settings: NewSettings(),
		sessions: &sessions{Entries: make(map[string]*session)}, cache: NewCache(), s4uCache: NewCache(),
	}
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
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG", KDC: []string{"127.0.0.1:88"}}}
	kt := keytab.New()
	principal := keytab.Principal{Realm: "EXAMPLE.ORG", Components: []string{"alice"}, NameType: nametype.KRB_NT_PRINCIPAL}
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	if err := kt.AddKey(principal, 1, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	client := NewWithKeytab("alice", "EXAMPLE.ORG", kt, cfg)
	var output bytes.Buffer
	if err := client.Diagnostics(&output); err != nil {
		t.Fatalf("configured diagnostics: %v", err)
	}
	if !strings.Contains(output.String(), "UDP KDCs:") || !strings.Contains(output.String(), "TCP KDCs:") {
		t.Fatalf("diagnostic output = %q", output.String())
	}

	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.AES256_CTS_HMAC_SHA1_96)}
	if err := client.Diagnostics(io.Discard); err == nil || !strings.Contains(err.Error(), "default_tkt_enctypes") || !strings.Contains(err.Error(), "preferred_preauth_types") {
		t.Fatalf("mismatched diagnostics = %v", err)
	}
}
