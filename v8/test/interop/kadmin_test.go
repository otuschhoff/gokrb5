//go:build interop
// +build interop

package interop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

func TestClientLoginKVNO300Keytab(t *testing.T) {
	test.Integration(t)
	requireCommands(t, "docker")
	container := os.Getenv("TEST_KDC_CONTAINER")
	if container == "" {
		container = "krb5kdc"
	}
	username := fmt.Sprintf("phase7-kvno300-%d", os.Getpid())
	principalName := username + "@TEST.GOKRB5"
	containerPath := fmt.Sprintf("/tmp/%s.keytab", username)
	runKadmin := func(query string) commandResult {
		return runCommand(t, "", nil, "docker", "exec", container, "kadmin.local", "-q", query)
	}
	created := runKadmin("addprinc -pw " + interopPassword + " " + principalName)
	if created.err != nil {
		t.Fatalf("INTEGRATION=1 but kadmin.local is unavailable in %s: %v: %s", container, created.err, created.stderr)
	}
	t.Cleanup(func() {
		_ = runKadmin("delprinc -force " + principalName)
		_ = runCommand(t, "", nil, "docker", "exec", container, "rm", "-f", containerPath)
	})
	modified := runKadmin("modprinc -kvno 299 " + principalName)
	if modified.err != nil {
		t.Fatalf("set principal KVNO: %v: %s", modified.err, modified.stderr)
	}
	added := runKadmin("ktadd -k " + containerPath + " " + principalName)
	if added.err != nil {
		t.Fatalf("write KVNO 300 keytab: %v: %s", added.err, added.stderr)
	}
	path := filepath.Join(t.TempDir(), "kvno300.keytab")
	copied := runCommand(t, "", nil, "docker", "cp", container+":"+containerPath, path)
	if copied.err != nil {
		t.Fatalf("copy KVNO 300 keytab: %v: %s", copied.err, copied.stderr)
	}
	kt, err := keytab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := keytab.ParsePrincipal(principalName)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := kt.GetEntry(principal, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if entry.KVNO != 300 {
		t.Fatalf("generated keytab KVNO = %d, want 300", entry.KVNO)
	}
	env := liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5)
	cfg, err := config.Load(strings.TrimPrefix(env[0], "KRB5_CONFIG="))
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithKeytab(username, "TEST.GOKRB5", kt, cfg)
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("Go client login with KVNO 300 keytab failed: %v", err)
	}
}

func TestKadminModifyInterop(t *testing.T) {
	test.Integration(t)
	requireCommands(t, "docker", "klist")
	container := os.Getenv("TEST_KDC_CONTAINER")
	if container == "" {
		container = "krb5kdc"
	}
	principalName := fmt.Sprintf("phase7-%d@TEST.GOKRB5", os.Getpid())
	containerPath := fmt.Sprintf("/tmp/phase7-%d.keytab", os.Getpid())
	runKadmin := func(query string) commandResult {
		return runCommand(t, "", nil, "docker", "exec", container, "kadmin.local", "-q", query)
	}
	created := runKadmin("addprinc -pw " + interopPassword + " " + principalName)
	if created.err != nil {
		t.Fatalf("INTEGRATION=1 but kadmin.local is unavailable in %s: %v: %s", container, created.err, created.stderr)
	}
	t.Cleanup(func() {
		_ = runKadmin("delprinc -force " + principalName)
		_ = runCommand(t, "", nil, "docker", "exec", container, "rm", "-f", containerPath)
	})
	for index := 0; index < 2; index++ {
		result := runKadmin("ktadd -k " + containerPath + " " + principalName)
		if result.err != nil {
			t.Fatalf("kadmin.local ktadd failed: %v: %s", result.err, result.stderr)
		}
	}
	path := filepath.Join(t.TempDir(), "kadmin.keytab")
	copied := runCommand(t, "", nil, "docker", "cp", container+":"+containerPath, path)
	if copied.err != nil {
		t.Fatalf("copy kadmin keytab: %v: %s", copied.err, copied.stderr)
	}
	kt, err := keytab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := keytab.ParsePrincipal(principalName)
	if len(distinctKVNOs(kt, principal)) < 2 {
		t.Fatal("kadmin.local did not produce multiple KVNOs")
	}
	if removed := kt.RemoveOldKVNO(principal, 1); removed == 0 {
		t.Fatal("Go did not remove an old kadmin.local KVNO")
	}
	if err := kt.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	listed := runCommand(t, "", []string{"LC_ALL=C"}, "klist", "-kte", path)
	if listed.err != nil {
		t.Fatalf("MIT rejected Go-modified kadmin keytab: %v: %s", listed.err, listed.stderr)
	}

	_ = runCommand(t, "", nil, "docker", "exec", container, "rm", "-f", containerPath)
	copied = runCommand(t, "", nil, "docker", "cp", path, container+":"+containerPath)
	if copied.err != nil {
		t.Fatalf("copy modified keytab into KDC: %v: %s", copied.err, copied.stderr)
	}
	appended := runKadmin("ktadd -k " + containerPath + " " + principalName)
	if appended.err != nil {
		t.Fatalf("kadmin.local append failed: %v: %s", appended.err, appended.stderr)
	}
	copied = runCommand(t, "", nil, "docker", "cp", container+":"+containerPath, path)
	if copied.err != nil {
		t.Fatalf("copy appended keytab: %v: %s", copied.err, copied.stderr)
	}
	reloaded, err := keytab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(distinctKVNOs(reloaded, principal)) < 2 {
		t.Fatal("Go did not observe retained and newly appended kadmin.local KVNOs")
	}
}

func distinctKVNOs(kt *keytab.Keytab, principal keytab.Principal) map[uint32]struct{} {
	result := make(map[uint32]struct{})
	for _, entry := range kt.Entries {
		if entry.Principal.String() == principal.String() {
			result[entry.KVNO] = struct{}{}
		}
	}
	return result
}
