//go:build adintegration

package adintegration

import (
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/ad"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func clientSettings() []func(*client.Settings) {
	return []func(*client.Settings){client.DisablePAReqEncPARep(true)}
}

func TestPasswordAndMachineLogon(t *testing.T) {
	env := ad.Environment(t)
	passwordClient := client.NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, clientSettings()...)
	if err := passwordClient.Login(); err != nil {
		t.Fatalf("%s password login failed: %v", env.Kind(), err)
	}
	defer passwordClient.Destroy()
	if !types.RealmEqual(passwordClient.Credentials.Realm(), env.UserRealm) {
		t.Fatalf("login realm %q does not match %q", passwordClient.Credentials.Realm(), env.UserRealm)
	}

	machine, ok := env.MachineAccountPrincipal()
	if !ok {
		t.Skipf("keytab %s has no machine-account principal", env.KeytabPath)
	}
	machineClient := client.NewWithKeytab(machine.Components[0], machine.Realm, env.Keytab, env.Config, clientSettings()...)
	if err := machineClient.Login(); err != nil {
		t.Fatalf("%s machine login failed: %v", env.Kind(), err)
	}
	machineClient.Destroy()
}

func TestEnterprisePrincipalLogon(t *testing.T) {
	env := ad.Environment(t)
	env.Config.LibDefaults.Canonicalize = true
	enterprise := types.PrincipalName{
		NameType:   nametype.KRB_NT_ENTERPRISE,
		NameString: []string{env.User + "@" + env.UserRealm},
	}
	cl := client.NewFromPrincipalName(enterprise, env.Realm, env.Config, clientSettings()...)
	cl.Credentials.WithPassword(env.Password)
	if err := cl.Login(); err != nil {
		t.Fatalf("enterprise principal login failed: %v", err)
	}
	defer cl.Destroy()
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	ticket, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("enterprise principal service ticket failed: %v", err)
	}
	if err := ticket.DecryptEncPart(env.Keytab, nil); err != nil {
		t.Fatalf("decrypt enterprise principal service ticket: %v", err)
	}
	if !strings.EqualFold(ticket.DecryptedEncPart.CName.PrincipalNameString(), env.User) || !types.RealmEqual(ticket.DecryptedEncPart.CRealm, env.UserRealm) {
		t.Fatalf("canonical ticket identity = %s@%s, want %s@%s", ticket.DecryptedEncPart.CName.PrincipalNameString(), ticket.DecryptedEncPart.CRealm, env.User, env.UserRealm)
	}
}

func TestDisabledAccountNTStatus(t *testing.T) {
	env := ad.Environment(t)
	user, password, ok := env.DisabledAccount()
	if !ok {
		t.Skip("disabled-account credentials are not configured")
	}
	cl := client.NewWithPassword(user, env.Realm, password, env.Config, clientSettings()...)
	err := cl.Login()
	cl.Destroy()
	if err == nil {
		t.Fatal("disabled account login unexpectedly succeeded")
	}
	provider, ok := err.(interface {
		NTStatus() (ntstatus.Code, bool)
	})
	if !ok {
		if env.Kind() == ad.KindSamba {
			t.Skipf("Samba rejected the disabled account without KERB-EXT-ERROR: %v", err)
		}
		t.Fatalf("disabled account error does not expose NTStatus: %v", err)
	}
	status, ok := provider.NTStatus()
	if !ok && env.Kind() == ad.KindSamba {
		t.Skipf("Samba rejected the disabled account without KERB-EXT-ERROR: %v", err)
	}
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("disabled account NTSTATUS = %s, %t; want STATUS_ACCOUNT_DISABLED", status, ok)
	}
}

func TestServiceTicketPAC(t *testing.T) {
	env := ad.Environment(t)
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, clientSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer cl.Destroy()
	ticket, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("get service ticket for %s: %v", spn, err)
	}
	if len(key.KeyValue) == 0 {
		t.Fatal("service ticket has an empty session key")
	}
	if err := ticket.DecryptEncPart(env.Keytab, nil); err != nil {
		t.Fatalf("decrypt service ticket: %v", err)
	}
	isPAC, pac, err := ticket.GetPACType(env.Keytab, nil, log.Default())
	if err != nil {
		t.Fatalf("validate PAC: %v", err)
	}
	if !isPAC || pac.ClientInfo == nil || pac.ServerChecksum == nil || pac.KDCChecksum == nil {
		t.Fatal("service ticket does not contain a validated PAC")
	}
	if !strings.EqualFold(pac.KerbValidationInfo.EffectiveName.Value, env.User) {
		t.Fatalf("PAC effective name %q does not match %q", pac.KerbValidationInfo.EffectiveName.Value, env.User)
	}
}

func TestS4U2Self(t *testing.T) {
	env := ad.Environment(t)
	machine, ok := env.DelegationPrincipal()
	if !ok {
		t.Skipf("keytab %s has no machine-account principal", env.KeytabPath)
	}
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithKeytab(machine.Components[0], machine.Realm, env.Keytab, env.Config, clientSettings()...)
	if err := cl.Login(); err != nil {
		t.Fatalf("service login failed: %v", err)
	}
	defer cl.Destroy()
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, env.User)
	ticket, key, err := cl.GetServiceTicketForUser(user, env.UserRealm, spn, client.S4UWithForwardable(true))
	if err != nil {
		t.Fatalf("S4U2self failed: %v", err)
	}
	if len(key.KeyValue) == 0 {
		t.Fatal("S4U2self returned an empty session key")
	}
	if err := ticket.DecryptEncPart(env.Keytab, nil); err != nil {
		t.Fatalf("decrypt S4U2self ticket: %v", err)
	}
	if !ticket.DecryptedEncPart.CName.Equal(user) || !types.RealmEqual(ticket.DecryptedEncPart.CRealm, env.UserRealm) {
		t.Fatalf("S4U2self ticket identity = %s@%s, want %s@%s", ticket.DecryptedEncPart.CName.PrincipalNameString(), ticket.DecryptedEncPart.CRealm, env.User, env.UserRealm)
	}
}

func TestS4U2Proxy(t *testing.T) {
	env := ad.Environment(t)
	target, ok := env.DelegationTargetSPN()
	if !ok {
		t.Skip("TESTAD_TARGET_SPN is not configured")
	}
	for _, test := range []struct {
		name    string
		options []client.S4UOption
	}{
		{name: "classic"},
		{name: "resource based", options: []client.S4UOption{client.S4UWithResourceBasedDelegation()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cl, evidence := s4uClientAndEvidence(t, env)
			defer cl.Destroy()
			ticket, key, err := cl.GetServiceTicketOnBehalfOf(evidence, target, test.options...)
			if err != nil {
				t.Fatalf("S4U2proxy to %s failed: %v", target, err)
			}
			if len(key.KeyValue) == 0 {
				t.Fatal("S4U2proxy returned an empty session key")
			}
			if err := ticket.DecryptEncPart(env.Keytab, nil); err != nil {
				t.Fatalf("decrypt S4U2proxy ticket: %v", err)
			}
			isPAC, parsed, err := ticket.GetPACType(env.Keytab, nil, log.Default())
			if err != nil {
				t.Fatalf("validate S4U2proxy PAC: %v", err)
			}
			if !isPAC || parsed.S4UDelegationInfo == nil {
				t.Fatal("S4U2proxy ticket has no S4U_DELEGATION_INFO")
			}
			if !strings.EqualFold(parsed.S4UDelegationInfo.ProxyTarget(), target) {
				t.Fatalf("PAC proxy target = %q, want %q", parsed.S4UDelegationInfo.ProxyTarget(), target)
			}
			if len(parsed.S4UDelegationInfo.TransitedServices()) == 0 {
				t.Fatal("PAC S4U transited-services list is empty")
			}
		})
	}
}

func TestS4U2ProxyDenied(t *testing.T) {
	env := ad.Environment(t)
	denied, ok := env.DeniedTargetSPN()
	if !ok {
		t.Skip("TESTAD_DENIED_SPN is not configured")
	}
	cl, evidence := s4uClientAndEvidence(t, env)
	defer cl.Destroy()
	_, _, err := cl.GetServiceTicketOnBehalfOf(evidence, denied)
	if !errors.Is(err, krberror.ErrDelegationNotPermitted) {
		t.Fatalf("S4U2proxy to unauthorized target error = %v, want ErrDelegationNotPermitted", err)
	}
}

func TestFASTArmoredLogon(t *testing.T) {
	env := ad.Environment(t)
	if env.Kind() == ad.KindSamba {
		t.Skip("the pinned Samba CI image does not provide interoperable required FAST")
	}
	cl := client.NewWithPassword(env.User, env.UserRealm, env.Password, env.Config,
		client.FASTArmorFromKeytab(env.Keytab), client.RequireFAST(true))
	if err := cl.Login(); err != nil {
		t.Fatalf("required FAST login failed: %v", err)
	}
	defer cl.Destroy()
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.GetServiceTicket(spn); err != nil {
		t.Fatalf("required FAST service-ticket exchange failed: %v", err)
	}
}

func s4uClientAndEvidence(t *testing.T, env *ad.Env) (*client.Client, messages.Ticket) {
	t.Helper()
	env.Config.LibDefaults.Forwardable = true
	machine, ok := env.DelegationPrincipal()
	if !ok {
		t.Skipf("keytab %s has no machine-account principal", env.KeytabPath)
	}
	service, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithKeytab(machine.Components[0], machine.Realm, env.Keytab, env.Config, clientSettings()...)
	if err := cl.Login(); err != nil {
		cl.Destroy()
		t.Fatalf("service login failed: %v", err)
	}
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, env.User)
	evidence, _, err := cl.GetServiceTicketForUser(user, env.UserRealm, service, client.S4UWithForwardable(true))
	if err != nil {
		cl.Destroy()
		t.Fatalf("S4U2self evidence ticket failed: %v", err)
	}
	return cl, evidence
}
