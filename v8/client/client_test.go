package client

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const testDefaultRealm = "DEFAULT.ORG"

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	var kt keytab.Keytab
	var cfg config.Config
	cl := NewWithKeytab("username", "REALM", &kt, &cfg, AssumePreAuthentication(true))
	if !cl.settings.assumePreAuthentication {
		t.Fatal("assumePreAuthentication should be true")
	}
	if !cl.settings.AssumePreAuthentication() {
		t.Fatal("AssumePreAuthentication() should be true")
	}
}

func TestKDCTimeOffsetOption(t *testing.T) {
	t.Parallel()

	offset := 7*time.Minute + 23*time.Second
	client := NewWithPassword("username", "REALM", "password", config.New(), KDCTimeOffset(offset))
	if client.kdcTimeOffset != offset {
		t.Fatalf("KDC time offset = %s, want %s", client.kdcTimeOffset, offset)
	}
}

func TestPrincipalDefaulting(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = testDefaultRealm

	cl, err := NewFromPrincipalString("service/host", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Credentials.Domain() != testDefaultRealm {
		t.Fatalf("default realm = %q, want %q", cl.Credentials.Domain(), testDefaultRealm)
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
	cfg.LibDefaults.DefaultRealm = testDefaultRealm
	if got := NewWithPassword("user", "", "password", cfg).Credentials.Domain(); got != testDefaultRealm {
		t.Fatalf("password client realm = %q", got)
	}
	if got := NewWithKeytab("user", "", keytab.New(), cfg).Credentials.Domain(); got != testDefaultRealm {
		t.Fatalf("keytab client realm = %q", got)
	}
}

func TestDisablePAReqEncPARep(t *testing.T) {
	settings := NewSettings(DisablePAReqEncPARep(true))
	if !settings.DisablePAReqEncPARep() || !settings.DisablePAFXFAST() {
		t.Fatal("new and deprecated setting accessors should share behavior")
	}
}

func TestKeyPreservesPasswordDerivationCause(t *testing.T) {
	t.Parallel()

	const password = "test-password"
	cl := NewWithPassword("user", "EXAMPLE.ORG", password, config.New())
	et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	paData, err := asn1.Marshal(types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte{0x30, 0x01}},
	})
	require.NoError(t, err)
	server := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.ORG")
	hint := messages.NewKRBError(server, cl.Credentials.Domain(), errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
	hint.CName = cl.Credentials.CName()
	hint.CRealm = cl.Credentials.Domain()
	hint.EData = paData

	key, kvno, err := cl.Key(et, 0, &hint)
	require.ErrorContains(t, err, "derive key from password")
	var syntax asn1.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.NotContains(t, err.Error(), password)
	require.Zero(t, key)
	require.Zero(t, kvno)
}
