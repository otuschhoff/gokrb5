package client

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	cl := NewWithKeytab("username", "REALM", &keytab.Keytab{}, &config.Config{}, AssumePreAuthentication(true))
	if !cl.settings.assumePreAuthentication {
		t.Fatal("assumePreAuthentication should be true")
	}
	if !cl.settings.AssumePreAuthentication() {
		t.Fatal("AssumePreAuthentication() should be true")
	}
}

func TestPrincipalDefaulting(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = "DEFAULT.ORG"

	cl, err := NewFromPrincipalString("service/host", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Credentials.Domain() != "DEFAULT.ORG" {
		t.Fatalf("default realm = %q, want DEFAULT.ORG", cl.Credentials.Domain())
	}
	if got := cl.Credentials.CName().NameString; len(got) != 2 || got[0] != "service" || got[1] != "host" {
		t.Fatalf("principal components = %#v", got)
	}

	cl, err = NewFromPrincipalString("user@corp.example@EXPLICIT.ORG", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Credentials.Domain() != "EXPLICIT.ORG" || cl.Credentials.CName().NameType != nametype.KRB_NT_ENTERPRISE {
		t.Fatalf("enterprise principal parsed incorrectly: %#v@%s", cl.Credentials.CName(), cl.Credentials.Domain())
	}

	empty := config.New()
	empty.LibDefaults.DefaultRealm = ""
	if _, err := NewFromPrincipalString("user", empty); err == nil {
		t.Fatal("expected missing realm error")
	}
}

func TestConstructorsResolveDefaultRealm(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = "DEFAULT.ORG"
	if got := NewWithPassword("user", "", "password", cfg).Credentials.Domain(); got != "DEFAULT.ORG" {
		t.Fatalf("password client realm = %q", got)
	}
	if got := NewWithKeytab("user", "", keytab.New(), cfg).Credentials.Domain(); got != "DEFAULT.ORG" {
		t.Fatalf("keytab client realm = %q", got)
	}
}

func TestDisablePAReqEncPARep(t *testing.T) {
	settings := NewSettings(DisablePAReqEncPARep(true))
	if !settings.DisablePAReqEncPARep() || !settings.DisablePAFXFAST() {
		t.Fatal("new and deprecated setting accessors should share behavior")
	}
}
