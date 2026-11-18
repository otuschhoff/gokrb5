package ad

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
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
		{Realm: realm, Components: []string{"frontendsvc"}},
		{Realm: "OTHER.EXAMPLE", Components: []string{"host", "ws01.other.example"}},
	} {
		if err := kt.AddKey(p, 3, key, time0()); err != nil {
			t.Fatal(err)
		}
	}
	if err := kt.WriteFile(filepath.Join(dir, KeytabFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, UserFile), []byte("alice@AD.EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PasswordFile), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DirEnvVar, dir)
	t.Setenv(RealmEnvVar, realm)
	t.Setenv(KindEnvVar, string(KindWindows))
	t.Setenv(KDCEnvVar, " 127.0.0.1:88, 127.0.0.2:88 ")
	t.Setenv(ServiceSPNEnvVar, "HTTP/service.ad.example.com")
	t.Setenv(DelegatorEnvVar, "FRONTENDSVC")
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
	delegator, ok := env.DelegationPrincipal()
	assert.True(t, ok)
	assert.Equal(t, "frontendsvc", delegator.Components[0])
}

func TestDiscoverADEnvironmentMissingFiles(t *testing.T) {
	t.Setenv(DirEnvVar, t.TempDir())
	t.Setenv(RealmEnvVar, "AD.EXAMPLE.COM")
	_, err := Discover()
	assert.Error(t, err)
}

func TestServicePrincipalSelectionAndFallbacks(t *testing.T) {
	realm := "AD.EXAMPLE.COM"
	kt := keytab.New()
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	principals := []keytab.Principal{
		{Realm: "OTHER.EXAMPLE", Components: []string{"host", "other.example"}},
		{Realm: realm, Components: []string{"HTTP", "service.ad.example.com"}},
		{Realm: realm, Components: []string{"host", "ws01.ad.example.com"}},
		{Realm: realm, Components: []string{"WS01$"}},
	}
	for _, principal := range principals {
		if err := kt.AddKey(principal, 1, key, time0()); err != nil {
			t.Fatal(err)
		}
	}
	env := &Env{Realm: realm, HostFQDN: "ws01.ad.example.com", Keytab: kt}
	principal, err := env.ServicePrincipal()
	if err != nil || len(principal.Components) != 2 || principal.Components[1] != env.HostFQDN {
		t.Fatalf("service principal = %+v, %v", principal, err)
	}
	spn, err := env.ServiceSPN()
	if err != nil || spn != "host/ws01.ad.example.com" {
		t.Fatalf("service SPN = %q, %v", spn, err)
	}
	machine, ok := env.DelegationPrincipal()
	if !ok || machine.Components[0] != "WS01$" {
		t.Fatalf("delegation fallback = %+v, %v", machine, ok)
	}
	env.delegator = "missing"
	if _, ok := env.DelegationPrincipal(); ok {
		t.Fatal("missing configured delegator was found")
	}

	empty := &Env{Keytab: keytab.New()}
	if _, err := empty.ServicePrincipal(); err == nil {
		t.Fatal("empty keytab returned a service principal")
	}
	if _, err := empty.ServiceSPN(); err == nil {
		t.Fatal("empty keytab returned a service SPN")
	}
}

func TestADLocalDiscoveryHelpers(t *testing.T) {
	repoRoot := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(repoRoot, ".git"), 0o700))
	nested := filepath.Join(repoRoot, "v8", "test", "ad")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	t.Chdir(nested)
	t.Setenv("GITHUB_WORKSPACE", "")
	root, err := findRepoRoot()
	require.NoError(t, err)
	rootInfo, err := os.Stat(root)
	require.NoError(t, err)
	expectedInfo, err := os.Stat(repoRoot)
	require.NoError(t, err)
	assert.True(t, os.SameFile(rootInfo, expectedInfo), "repository root = %q, want %q", root, repoRoot)

	t.Setenv("AD_TEST_OVERRIDE", "override")
	t.Setenv("AD_TEST_MISSING", "")
	assert.Equal(t, "override", envOr("AD_TEST_OVERRIDE", "fallback"))
	assert.Equal(t, "fallback", envOr("AD_TEST_MISSING", "fallback"))
	_ = resolvConfDomain()
}

func TestReadTrimmedFilePreservesSpaces(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credential")
	require.NoError(t, os.WriteFile(path, []byte(" test value \r\n"), 0o600))
	value, err := readTrimmedFile(path)
	require.NoError(t, err)
	assert.Equal(t, " test value ", value)
}

func TestReadTrimmedFileErrorContext(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing")
	value, err := readTrimmedFile(path)
	assert.Empty(t, value)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.ErrorContains(t, err, "read AD credential file:")

	pathErr, ok := errors.AsType[*fs.PathError](err)
	if !ok || pathErr == nil {
		t.Fatalf("readTrimmedFile() error = %v, want a file path error", err)
	}
	assert.Equal(t, path, pathErr.Path)
}

func TestFindRepoRootWorkingDirectoryError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux semantics for removing the current directory")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("GITHUB_WORKSPACE", "")
	require.NoError(t, os.Remove(dir))

	root, err := findRepoRoot()
	assert.Empty(t, root)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.ErrorContains(t, err, "get working directory:")
}

func TestFindRepoRootFromGitHubWorkspace(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o700))
	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, KeytabFile), nil, 0o600))
	t.Chdir(other)
	t.Setenv("GITHUB_WORKSPACE", root)
	got, err := findRepoRoot()
	require.NoError(t, err)
	assert.Equal(t, root, got)

	t.Setenv("GITHUB_WORKSPACE", filepath.Join(root, "missing"))
	got, err = findRepoRoot()
	require.NoError(t, err)
	gotInfo, err := os.Stat(got)
	require.NoError(t, err)
	otherInfo, err := os.Stat(other)
	require.NoError(t, err)
	assert.True(t, os.SameFile(gotInfo, otherInfo), "fallback root = %q, want %q", got, other)
}
