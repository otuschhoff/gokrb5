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

	env, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, realm, env.Realm)
	assert.Equal(t, "alice", env.User)
	assert.Equal(t, realm, env.UserRealm)
	assert.Equal(t, "secret", env.Password)
	assert.Equal(t, realm, env.Config.LibDefaults.DefaultRealm)
	assert.True(t, env.Config.LibDefaults.DNSLookupKDC)

	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "host/ws01.ad.example.com", spn, "should prefer the lower-case FQDN host principal in the test realm")
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
