package ad

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func time0() time.Time { return time.Unix(1700000000, 0) }

func TestDomainOf(t *testing.T) {
	assert.Equal(t, "eu.example.com", domainOf("host.eu.example.com"))
	assert.Equal(t, "", domainOf("host"))
}

func TestEnvironmentKind(t *testing.T) {
	tests := []struct {
		name, value, realm, domain string
		want                       Kind
		wantError                  bool
	}{
		{name: "explicit Samba", value: " SAMBA ", want: KindSamba},
		{name: "explicit Windows", value: "windows", realm: "SAMBA.EXAMPLE", want: KindWindows},
		{name: "Samba realm", realm: "SAMBA.GOKRB5", want: KindSamba},
		{name: "Samba domain", realm: "EXAMPLE.COM", domain: "samba.example.com", want: KindSamba},
		{name: "default Windows", realm: "AD.EXAMPLE.COM", want: KindWindows},
		{name: "invalid", value: "mit", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := environmentKind(test.value, test.realm, test.domain)
			if test.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestDiscoverADEnvironmentFromFiles(t *testing.T) {
	dir := t.TempDir()
	kt := keytab.New()
	realm := "AD.EXAMPLE.COM"
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	for _, p := range []keytab.Principal{
		{Realm: realm, Components: []string{"HOST", "WS01"}},
		{Realm: realm, Components: []string{"host", "ws01.ad.example.com"}},
		{Realm: realm, Components: []string{"WS01$"}},
		{Realm: "OTHER.EXAMPLE", Components: []string{"host", "ws01.other.example"}},
	} {
		if err := kt.AddKey(p, 3, key, time0()); err != nil {
			t.Fatal(err)
		}
	}
	if err := kt.WriteFile(filepath.Join(dir, KeytabFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, UserFile), []byte("alice@AD.EXAMPLE.COM\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PasswordFile), []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnvVar, dir)
	t.Setenv(RealmEnvVar, realm)
	t.Setenv(KindEnvVar, string(KindWindows))
	t.Setenv(KDCEnvVar, " 127.0.0.1:88, 127.0.0.2:88 ")
	t.Setenv(ServiceSPNEnvVar, "HTTP/service.ad.example.com")
	t.Setenv(TargetSPNEnvVar, "HTTP/target.ad.example.com")
	t.Setenv(DeniedSPNEnvVar, "HTTP/denied.ad.example.com")
	t.Setenv(DisabledUserEnvVar, "disabled")
	t.Setenv(DisabledPassEnvVar, "DisabledPassw0rd!")

	env, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, realm, env.Realm)
	assert.Equal(t, "alice", env.User)
	assert.Equal(t, realm, env.UserRealm)
	assert.Equal(t, "secret", env.Password)
	assert.Equal(t, realm, env.Config.LibDefaults.DefaultRealm)
	assert.False(t, env.Config.LibDefaults.DNSLookupKDC)
	if assert.Len(t, env.Config.Realms, 1) {
		assert.Equal(t, []string{"127.0.0.1:88", "127.0.0.2:88"}, env.Config.Realms[0].KDC)
	}
	assert.Equal(t, KindWindows, env.Kind())

	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "HTTP/service.ad.example.com", spn)
	target, ok := env.DelegationTargetSPN()
	assert.True(t, ok)
	assert.Equal(t, "HTTP/target.ad.example.com", target)
	denied, ok := env.DeniedTargetSPN()
	assert.True(t, ok)
	assert.Equal(t, "HTTP/denied.ad.example.com", denied)
	disabledUser, disabledPassword, ok := env.DisabledAccount()
	assert.True(t, ok)
	assert.Equal(t, "disabled", disabledUser)
	assert.Equal(t, "DisabledPassw0rd!", disabledPassword)
	machine, ok := env.MachineAccountPrincipal()
	assert.True(t, ok)
	assert.Equal(t, "WS01$", machine.Components[0])
}

func TestDiscoverADEnvironmentMissingFiles(t *testing.T) {
	t.Setenv(DirEnvVar, t.TempDir())
	t.Setenv(RealmEnvVar, "AD.EXAMPLE.COM")
	_, err := Discover()
	assert.Error(t, err)
}
