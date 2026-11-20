package client

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestSettingsOptions(t *testing.T) {
	var identity pkinit.Identity
	identity.SID = "S-1-5-21"
	anchors := x509.NewCertPool()
	var policy pkinit.KDCCertificatePolicy
	policy.Realm = clientTestComRealm
	policy.Hostname = "kdc.example.com"
	policy.EKUChecking = pkinit.KDCEKUKDCAuthentication
	policy.RequireRevocation = true
	ocspResponse := []byte{1, 2, 3}
	var armorTicket messages.Ticket
	armorTicket.Realm = clientTestComRealm
	armorKey := types.EncryptionKey{KeyType: 18, KeyValue: []byte{4, 5, 6}}
	armorName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "armor")
	armorKeytab := keytab.New()
	var httpClient http.Client
	httpClient.Timeout = 17 * time.Second
	var logOutput bytes.Buffer
	logger := log.New(&logOutput, "", 0)

	settings := NewSettings(
		PKINITIdentity(&identity),
		PKINITKDCCertificatePolicy(policy),
		PKINITAnchors(anchors),
		PKINITMode(pkinit.ModeRSA),
		PKINITMinimumDHBits(3072),
		PKINITRequireFreshness(true),
		PKINITOCSPResponse(ocspResponse),
		DisablePAFXFAST(true),
		AssumePreAuthentication(true),
		FASTArmorWithIdentity(armorTicket, armorKey, armorName, clientTestComRealm),
		FASTArmorFromKeytab(armorKeytab),
		RequireFAST(true),
		KKDCPClient(&httpClient),
		Logger(logger),
	)
	ocspResponse[0] = 9

	if settings.pkinitOptions.Identity != &identity {
		t.Fatal("PKINIT identity was not retained")
	}
	assertPKINITCertificatePolicy(t, settings.pkinitOptions.KDCCertificate, anchors, policy)
	assertPKINITSettings(t, settings)
	assertArmorSettings(t, settings, armorTicket.Realm, armorKey, armorKeytab)
	if settings.httpClient() != &httpClient || settings.Logger() != logger {
		t.Fatal("client dependencies were not retained")
	}

	client := NewWithPassword("user", clientTestComRealm, "password", config.New(), Logger(logger))
	client.Log("message %d", 7)
	if got := logOutput.String(); !strings.Contains(got, "message 7") {
		t.Fatalf("log output = %q", got)
	}
	NewWithPassword("user", clientTestComRealm, "password", config.New()).Log("discarded")
}

func assertPKINITCertificatePolicy(
	t *testing.T,
	gotPolicy pkinit.KDCCertificatePolicy,
	anchors *x509.CertPool,
	policy pkinit.KDCCertificatePolicy,
) {
	t.Helper()
	if gotPolicy.Roots != anchors {
		t.Fatal("PKINIT trust anchors were not retained")
	}
	if gotPolicy.Realm != policy.Realm || gotPolicy.Hostname != policy.Hostname ||
		gotPolicy.EKUChecking != policy.EKUChecking || !gotPolicy.RequireRevocation {
		t.Fatalf("KDC certificate policy = %+v, want %+v", gotPolicy, policy)
	}
}

func assertPKINITSettings(t *testing.T, settings *Settings) {
	t.Helper()
	if settings.pkinitOptions.Mode != pkinit.ModeRSA || settings.pkinitOptions.MinimumDHBits != 3072 ||
		!settings.pkinitOptions.RequireFreshness {
		t.Fatalf("PKINIT options = %+v", settings.pkinitOptions)
	}
	if got := settings.pkinitOptions.OCSPResponse; len(got) != 3 || got[0] != 1 {
		t.Fatalf("OCSP response was not defensively copied: %v", got)
	}
}

func assertArmorSettings(
	t *testing.T,
	settings *Settings,
	armorRealm string,
	armorKey types.EncryptionKey,
	armorKeytab *keytab.Keytab,
) {
	t.Helper()
	for _, enabled := range []func() bool{
		settings.DisablePAReqEncPARep, settings.DisablePAFXFAST, settings.AssumePreAuthentication, settings.RequireFAST,
	} {
		if !enabled() {
			t.Fatal("boolean settings were not applied")
		}
	}
	if settings.fastArmor == nil || settings.fastArmor.realm != clientTestComRealm ||
		settings.fastArmor.cname.NameString[0] != "armor" {
		t.Fatalf("FAST armor identity = %+v", settings.fastArmor)
	}
	if settings.fastArmor.ticket.Realm != armorRealm || settings.fastArmor.key.KeyType != armorKey.KeyType ||
		settings.fastArmorKeytab != armorKeytab {
		t.Fatal("FAST armor credentials were not retained")
	}
}

func TestSettingsDefaultsAndJSON(t *testing.T) {
	var ticket messages.Ticket
	var key types.EncryptionKey
	settings := NewSettings(FASTArmor(ticket, key))
	if settings.httpClient().Timeout != 5*time.Second {
		t.Fatalf("default HTTP timeout = %v", settings.httpClient().Timeout)
	}
	if settings.fastArmor == nil || settings.fastArmor.realm != "" || len(settings.fastArmor.cname.NameString) != 0 {
		t.Fatalf("default FAST armor identity = %+v", settings.fastArmor)
	}

	encoded, err := NewSettings(DisablePAReqEncPARep(true), AssumePreAuthentication(true), RequireFAST(true)).JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]bool
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"DisablePAFXFast", "AssumePreAuthentication", "RequireFAST"} {
		if !got[key] {
			t.Fatalf("JSON field %s = false", key)
		}
	}
}

func TestPKINITReplyKeyLifecycle(t *testing.T) {
	client := NewWithPassword("user", clientTestComRealm, "password", config.New())
	input := types.EncryptionKey{KeyType: 18, KeyValue: []byte{1, 2, 3}}
	client.setPKINITReplyKey("example.com", input)
	input.KeyValue[0] = 9

	got, ok := client.takePKINITReplyKey(clientTestComRealm)
	if !ok || got.KeyType != 18 || !bytes.Equal(got.KeyValue, []byte{1, 2, 3}) {
		t.Fatalf("reply key = %+v, %v", got, ok)
	}
	if _, ok := client.takePKINITReplyKey("example.com"); ok {
		t.Fatal("reply key was not consumed")
	}
}

func TestPKINITCredentialsLifecycle(t *testing.T) {
	client := NewWithPassword("user", clientTestComRealm, "password", config.New())
	if _, err := client.PKINITCredentials(); err == nil {
		t.Fatal("missing PKINIT credentials did not return an error")
	}

	storedErr := errors.New("credential decryption failed")
	client.pkinitCredErr = storedErr
	if _, err := client.PKINITCredentials(); !errors.Is(err, storedErr) {
		t.Fatalf("PKINITCredentials() error = %v", err)
	}

	client.pkinitCredErr = nil
	var credentials pac.CredentialData
	var supplemental pac.SECPKGSupplementalCred
	supplemental.Credentials = []byte{1, 2, 3}
	credentials.Credentials = []pac.SECPKGSupplementalCred{supplemental}
	client.pkinitCreds = &credentials
	got, err := client.PKINITCredentials()
	if err != nil {
		t.Fatal(err)
	}
	got.Credentials[0].Credentials[0] = 9
	if client.pkinitCreds.Credentials[0].Credentials[0] != 1 {
		t.Fatal("PKINIT credentials were not defensively copied")
	}
}
