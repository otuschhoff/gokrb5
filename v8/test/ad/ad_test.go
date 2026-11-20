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

const (
	fixtureRealm   = "AD.EXAMPLE.COM"
	fixtureHost    = "ws01.ad.example.com"
	fixtureMachine = "WS01$"
	hostService    = "host"
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
		{name: "explicit Samba", value: " SAMBA ", realm: "", domain: "", want: KindSamba, wantError: false},
		{
			name: "explicit Windows", value: "windows", realm: "SAMBA.EXAMPLE",
			domain: "", want: KindWindows, wantError: false,
		},
		{name: "Samba realm", value: "", realm: "SAMBA.GOKRB5", domain: "", want: KindSamba, wantError: false},
		{
			name: "Samba domain", value: "", realm: "EXAMPLE.COM", domain: "samba.example.com",
			want: KindSamba, wantError: false,
		},
		{name: "default Windows", value: "", realm: fixtureRealm, domain: "", want: KindWindows, wantError: false},
		{name: "invalid", value: "mit", realm: "", domain: "", want: "", wantError: true},
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

func fixtureKeytab(t *testing.T, kvno uint32, principals []keytab.Principal) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	for _, p := range principals {
		require.NoError(t, kt.AddKey(p, kvno, key, time0()))
	}
	return kt
}

func TestDiscoverADEnvironmentFromFiles(t *testing.T) {
	dir := t.TempDir()
	kt := fixtureKeytab(t, 3, []keytab.Principal{
		{Realm: fixtureRealm, Components: []string{"HOST", "WS01"}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{hostService, fixtureHost}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{fixtureMachine}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{"frontendsvc"}, NameType: 0},
		{Realm: "OTHER.EXAMPLE", Components: []string{hostService, "ws01.other.example"}, NameType: 0},
	})
	require.NoError(t, kt.WriteFile(filepath.Join(dir, KeytabFile)))
	require.NoError(t, os.WriteFile(filepath.Join(dir, UserFile), []byte("alice@"+fixtureRealm+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, PasswordFile), []byte("secret\n"), 0o600))
	t.Setenv(DirEnvVar, dir)
	t.Setenv(KeytabEnvVar, "")
	t.Setenv(UserFileEnvVar, "")
	t.Setenv(PasswordFileEnvVar, "")
	t.Setenv(RealmEnvVar, fixtureRealm)
	t.Setenv(KindEnvVar, string(KindWindows))
	t.Setenv(KDCEnvVar, " 127.0.0.1:88, 127.0.0.2:88 ")
	t.Setenv(ServiceSPNEnvVar, "HTTP/service.ad.example.com")
	t.Setenv(DelegatorEnvVar, "FRONTENDSVC")
	t.Setenv(TargetSPNEnvVar, "HTTP/target.ad.example.com")
	t.Setenv(DeniedSPNEnvVar, "HTTP/denied.ad.example.com")
	t.Setenv(DisabledUserEnvVar, "disabled")
	t.Setenv(DisabledPassEnvVar, "DisabledPassw0rd!")

	env, err := Discover()
	require.NoError(t, err)
	assert.Equal(t, fixtureRealm, env.Realm)
	assert.Equal(t, "alice", env.User)
	assert.Equal(t, fixtureRealm, env.UserRealm)
	assert.Equal(t, "secret", env.Password)
	assert.Equal(t, fixtureRealm, env.Config.LibDefaults.DefaultRealm)
	assert.False(t, env.Config.LibDefaults.DNSLookupKDC)
	if assert.Len(t, env.Config.Realms, 1) {
		assert.Equal(t, []string{"127.0.0.1:88", "127.0.0.2:88"}, env.Config.Realms[0].KDC)
	}
	assert.Equal(t, KindWindows, env.Kind())
	assertConfiguredPrincipals(t, env)

	t.Run("blank KDC override keeps DNS discovery", func(t *testing.T) {
		t.Setenv(KDCEnvVar, " , ")
		env, err := Discover()
		require.NoError(t, err)
		assert.True(t, env.Config.LibDefaults.DNSLookupKDC)
		assert.Empty(t, env.Config.Realms)
	})
}

func assertConfiguredPrincipals(t *testing.T, env *Env) {
	t.Helper()
	spn, err := env.ServiceSPN()
	require.NoError(t, err)
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
	require.True(t, ok)
	assert.Equal(t, []string{fixtureMachine}, machine.Components)
	delegator, ok := env.DelegationPrincipal()
	require.True(t, ok)
	assert.Equal(t, []string{"frontendsvc"}, delegator.Components)
}

func TestDiscoverADEnvironmentMissingFiles(t *testing.T) {
	t.Setenv(DirEnvVar, t.TempDir())
	t.Setenv(KeytabEnvVar, "")
	t.Setenv(UserFileEnvVar, "")
	t.Setenv(PasswordFileEnvVar, "")
	t.Setenv(KindEnvVar, "")
	t.Setenv(RealmEnvVar, fixtureRealm)
	_, err := Discover()
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestServicePrincipalSelectionAndFallbacks(t *testing.T) {
	kt := fixtureKeytab(t, 1, []keytab.Principal{
		{Realm: "OTHER.EXAMPLE", Components: []string{hostService, "other.example"}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{"HTTP", "service.ad.example.com"}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{hostService, fixtureHost}, NameType: 0},
		{Realm: fixtureRealm, Components: []string{fixtureMachine}, NameType: 0},
	})
	var env Env
	env.Realm = fixtureRealm
	env.HostFQDN = fixtureHost
	env.Keytab = kt
	principal, err := env.ServicePrincipal()
	require.NoError(t, err)
	assert.Equal(t, []string{hostService, fixtureHost}, principal.Components)
	spn, err := env.ServiceSPN()
	require.NoError(t, err)
	assert.Equal(t, hostService+"/"+fixtureHost, spn)
	machine, ok := env.DelegationPrincipal()
	require.True(t, ok)
	assert.Equal(t, []string{fixtureMachine}, machine.Components)
	env.delegator = "missing"
	_, ok = env.DelegationPrincipal()
	assert.False(t, ok)
}

func TestServicePrincipalWithEmptyKeytab(t *testing.T) {
	var env Env
	env.Keytab = keytab.New()
	_, err := env.ServicePrincipal()
	assert.Error(t, err)
	_, err = env.ServiceSPN()
	assert.Error(t, err)
	principal, ok := env.MachineAccountPrincipal()
	assert.False(t, ok)
	assert.Zero(t, principal)
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
