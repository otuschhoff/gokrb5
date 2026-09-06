package client

import (
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/ad"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestClientS4U2SelfAD(t *testing.T) {
	env := ad.Environment(t)
	machine, ok := env.MachineAccountPrincipal()
	if !ok {
		t.Skipf("keytab %s has no computer account principal", env.KeytabPath)
	}
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	cl := NewWithKeytab(machine.Components[0], machine.Realm, env.Keytab, env.Config, adSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("service login failed: %v", err)
	}
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, env.User)
	ticket, key, err := cl.GetServiceTicketForUser(user, env.UserRealm, spn, S4UWithForwardable(true))
	if err != nil {
		t.Fatalf("S4U2self failed: %v", err)
	}
	if len(key.KeyValue) == 0 {
		t.Fatal("S4U2self returned an empty session key")
	}
	if err := ticket.DecryptEncPart(env.Keytab, nil); err != nil {
		t.Fatalf("decrypt S4U2self ticket: %v", err)
	}
	if !strings.EqualFold(ticket.DecryptedEncPart.CName.PrincipalNameString(), env.User) || !types.RealmEqual(ticket.DecryptedEncPart.CRealm, env.UserRealm) {
		t.Fatalf("S4U2self ticket identity = %s@%s, want %s@%s", ticket.DecryptedEncPart.CName.PrincipalNameString(), ticket.DecryptedEncPart.CRealm, env.User, env.UserRealm)
	}
	if _, ok := cl.GetCachedServiceTicketForUserInfo(user, env.UserRealm, spn); !ok {
		t.Fatal("S4U2self ticket was not added to the user-specific cache")
	}
}
