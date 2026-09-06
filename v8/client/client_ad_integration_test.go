package client

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/test/ad"
	"github.com/stretchr/testify/assert"
)

// The AD integration tests discover the domain from the host's FQDN and read
// credentials from the repository root (krb5.keytab, user, pw). See ad.Environment.

// AD does not return the PA-FX-FAST marker gokrb5 expects alongside PA-REQ-ENC-PA-REP (see USAGE.md).
func adSettings() []func(*Settings) { return []func(*Settings){DisablePAReqEncPARep(true)} }

func TestClient_SuccessfulLogin_AD(t *testing.T) {
	env := ad.Environment(t)

	cl := NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, adSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("Error on login to %s: %v", env.Realm, err)
	}
	assert.True(t, strings.EqualFold(env.UserRealm, cl.Credentials.Realm()), "client realm should match the user realm")
}

func TestClient_SuccessfulLogin_AD_Keytab(t *testing.T) {
	env := ad.Environment(t)
	machine, ok := env.MachineAccountPrincipal()
	if !ok {
		t.Skipf("keytab %s has no computer account principal", env.KeytabPath)
	}

	cl := NewWithKeytab(machine.Components[0], machine.Realm, env.Keytab, env.Config, adSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("Error on keytab login as %s: %v", machine, err)
	}
}

func TestClient_GetServiceTicket_AD(t *testing.T) {
	env := ad.Environment(t)
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}

	cl := NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, adSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("Error on login: %v", err)
	}
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("Error getting service ticket for %s: %v", spn, err)
	}
	assert.True(t, strings.EqualFold(spn, tkt.SName.PrincipalNameString()), "ticket sname %q should match %q", tkt.SName.PrincipalNameString(), spn)
	assert.NotEmpty(t, key.KeyValue, "session key should be present")

	if err := tkt.DecryptEncPart(env.Keytab, nil); err != nil {
		t.Fatalf("could not decrypt service ticket with %s: %v", env.KeytabPath, err)
	}
	assert.True(t, strings.EqualFold(env.User, tkt.DecryptedEncPart.CName.PrincipalNameString()), "ticket cname should be the logged in user")

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	isPAC, pac, err := tkt.GetPACType(env.Keytab, nil, l)
	if err != nil {
		t.Log(w.String())
		t.Fatalf("error getting PAC: %v", err)
	}
	if !assert.True(t, isPAC, "AD service ticket should carry a PAC") {
		return
	}
	assert.True(t, strings.EqualFold(env.User, pac.KerbValidationInfo.EffectiveName.Value), "PAC EffectiveName %q should match user %q", pac.KerbValidationInfo.EffectiveName.Value, env.User)
	assert.NotEmpty(t, pac.KerbValidationInfo.LogonDomainName.Value, "PAC should name the logon domain")
	assert.NotEmpty(t, pac.KerbValidationInfo.GetGroupMembershipSIDs(), "PAC should list group SIDs")
	assert.NotNil(t, pac.ClientInfo, "PAC should carry client info")
	assert.NotNil(t, pac.ServerChecksum, "PAC should carry the server checksum")
	assert.NotNil(t, pac.KDCChecksum, "PAC should carry the KDC checksum")
}

func TestClient_GetServiceTicket_AD_CachedTicketReused(t *testing.T) {
	env := ad.Environment(t)
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}

	cl := NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, adSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("Error on login: %v", err)
	}
	first, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, first.EncPart.Cipher, second.EncPart.Cipher, "second request should be served from the ticket cache")
}
