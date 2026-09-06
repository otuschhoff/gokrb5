package credentials

import (
	"crypto/x509"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestCredentialsIdentityAndAuthorizationLifecycle(t *testing.T) {
	credentials := New("initial", "INITIAL.REALM")
	principal := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service/host")
	authTime := time.Date(2026, time.September, 7, 10, 11, 12, 0, time.UTC)

	credentials.SetUserName("effective")
	credentials.SetDisplayName("Example User")
	credentials.SetCName(principal)
	credentials.SetRealm("EXAMPLE.COM")
	credentials.SetHuman(false)
	credentials.SetAuthTime(authTime)
	credentials.SetAuthenticated(true)

	if credentials.UserName() != "effective" || credentials.DisplayName() != "Example User" {
		t.Fatal("identity names were not retained")
	}
	if credentials.CName().PrincipalNameString() != "service/host" {
		t.Fatalf("principal = %+v", credentials.CName())
	}
	if credentials.Domain() != "EXAMPLE.COM" || credentials.Realm() != "EXAMPLE.COM" {
		t.Fatal("realm was not retained")
	}
	if credentials.Human() || !credentials.Authenticated() || !credentials.AuthTime().Equal(authTime) {
		t.Fatal("authentication state was not retained")
	}
	if credentials.SessionID() == "" {
		t.Fatal("session ID was not generated")
	}

	credentials.AddAuthzAttribute("group-a")
	credentials.AddAuthzAttribute("group-b")
	credentials.DisableAuthzAttribute("group-a")
	credentials.DisableAuthzAttribute("missing")
	if credentials.Authorized("group-a") || !credentials.Authorized("group-b") || credentials.Authorized("missing") {
		t.Fatal("authorization disable state is incorrect")
	}
	credentials.EnableAuthzAttribute("group-a")
	credentials.EnableAuthzAttribute("missing")
	if !credentials.Authorized("group-a") {
		t.Fatal("authorization enable state is incorrect")
	}
	credentials.RemoveAuthzAttribute("missing")
	credentials.RemoveAuthzAttribute("group-b")
	attributes := credentials.AuthzAttributes()
	sort.Strings(attributes)
	if len(attributes) != 1 || attributes[0] != "group-a" {
		t.Fatalf("authorization attributes = %v", attributes)
	}
}

func TestCredentialsADAndCertificateAttributes(t *testing.T) {
	credentials := New("initial", "EXAMPLE.COM")
	ad := ADCredentials{
		EffectiveName:       "effective",
		FullName:            "Example User",
		GroupMembershipSIDs: []string{"S-1-5-21-1", "S-1-5-21-2"},
		UserSID:             "S-1-5-21-3",
	}
	credentials.SetADCredentials(ad)
	if got := credentials.GetADCredentials(); got.UserSID != ad.UserSID {
		t.Fatalf("AD credentials = %+v", got)
	}
	if credentials.UserName() != ad.EffectiveName || credentials.DisplayName() != ad.FullName {
		t.Fatal("AD names were not applied")
	}
	for _, sid := range ad.GroupMembershipSIDs {
		if !credentials.Authorized(sid) {
			t.Fatalf("AD group %s was not authorized", sid)
		}
	}

	chain := []*x509.Certificate{{SerialNumber: nil}, {SerialNumber: nil}}
	identity := CertificateIdentity{Chain: chain, SubjectDN: "CN=client", UPN: "user@example.com"}
	credentials.SetCertificateIdentity(identity)
	chain[0] = nil
	got, ok := credentials.GetCertificateIdentity()
	if !ok || got.SubjectDN != identity.SubjectDN || got.Chain[0] == nil {
		t.Fatalf("certificate identity = %+v, %v", got, ok)
	}
	got.Chain[0] = nil
	again, _ := credentials.GetCertificateIdentity()
	if again.Chain[0] == nil {
		t.Fatal("certificate chain slice was not defensively copied")
	}

	if got := New("user", "EXAMPLE.COM").GetADCredentials(); got.UserSID != "" || len(got.GroupMembershipSIDs) != 0 {
		t.Fatalf("missing AD credentials = %+v", got)
	}
	if _, ok := New("user", "EXAMPLE.COM").GetCertificateIdentity(); ok {
		t.Fatal("missing certificate identity was reported present")
	}
}

func TestCredentialsExpiryAttributesAndSerialization(t *testing.T) {
	credentials := New("user", "EXAMPLE.COM")
	if credentials.Expired() {
		t.Fatal("credentials without expiry are expired")
	}
	past := time.Now().UTC().Add(-time.Minute)
	credentials.SetValidUntil(past)
	if !credentials.Expired() || !credentials.ValidUntil().Equal(past) {
		t.Fatal("past expiry was not applied")
	}
	future := time.Now().UTC().Add(time.Hour)
	credentials.SetValidUntil(future)
	if credentials.Expired() {
		t.Fatal("future credentials are expired")
	}

	credentials.SetAttribute("one", 1)
	if credentials.Attributes()["one"] != 1 {
		t.Fatal("attribute was not retained")
	}
	credentials.RemoveAttribute("one")
	credentials.SetAttributes(map[string]interface{}{"two": "value"})
	if credentials.Attributes()["two"] != "value" {
		t.Fatal("attribute map was not replaced")
	}

	encoded, err := credentials.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded := New("", "")
	if err := decoded.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.UserName() != "user" || decoded.Realm() != "EXAMPLE.COM" || !decoded.ValidUntil().Equal(future) {
		t.Fatalf("round-tripped credentials = %+v", decoded)
	}
	if err := decoded.Unmarshal([]byte("not a gob")); err == nil {
		t.Fatal("invalid credential encoding was accepted")
	}

	jsonValue, err := credentials.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal([]byte(jsonValue), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["Username"] != "user" || fields["Realm"] != "EXAMPLE.COM" {
		t.Fatalf("JSON fields = %v", fields)
	}
}
