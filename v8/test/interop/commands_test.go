//go:build interop
// +build interop

package interop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

const interopService = "HTTP/host.test.gokrb5"

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func moduleRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func commandPath(t *testing.T, name string) string {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "gokrb5-interop-tools-")
		if buildErr != nil {
			return
		}
		for _, tool := range []string{"gokinit", "goklist", "gokdestroy"} {
			command := exec.Command("go", "build", "-tags", "interop", "-o", filepath.Join(buildDir, tool), "./cmd/"+tool)
			command.Dir = moduleRoot()
			if output, err := command.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("build %s: %v: %s", tool, err, output)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(buildDir, name)
}

func liveEnvironment(t *testing.T, port string) []string {
	t.Helper()
	test.Integration(t)
	requireCommands(t, "kinit", "klist", "kvno", "kdestroy")
	host := os.Getenv("TEST_KDC_ADDR")
	if host == "" {
		host = "127.0.0.1"
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("INTEGRATION=1 but test KDC is unavailable at %s:%s: %v", host, port, err)
	}
	_ = connection.Close()
	configuration := fmt.Sprintf(`[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = true
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 TEST.GOKRB5 = {
  kdc = %s:%s
  admin_server = %s:749
 }
[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
`, host, port, host)
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"KRB5_CONFIG=" + path, "LC_ALL=C", "TZ=UTC"}
}

func runPTYPassword(t *testing.T, env []string, name string, args ...string) commandResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = mergedEnvironment(env)
	tty, err := pty.Start(command)
	if err != nil {
		t.Fatalf("start PTY: %v", err)
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	var output bytes.Buffer
	for !strings.Contains(output.String(), "Password for ") || !strings.HasSuffix(output.String(), ": ") {
		value, readErr := reader.ReadByte()
		if readErr != nil {
			if ctx.Err() != nil {
				t.Fatalf("timeout waiting for password prompt: %v: %s", ctx.Err(), output.String())
			}
			t.Fatalf("read password prompt: %v: %s", readErr, output.String())
		}
		output.WriteByte(value)
	}
	if _, err := io.WriteString(tty, interopPassword+"\n"); err != nil {
		t.Fatal(err)
	}
	remainder, readErr := io.ReadAll(reader)
	if readErr != nil && !errors.Is(readErr, syscall.EIO) {
		t.Fatal(readErr)
	}
	output.Write(remainder)
	err = command.Wait()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return commandResult{stdout: output.String(), err: err}
}

func TestGokinitToMIT(t *testing.T) {
	keytabBytes, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(t.TempDir(), "client.keytab")
	if err := os.WriteFile(keytabPath, keytabBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for name, port := range map[string]string{
		"default": testdata.KDC_PORT_TEST_GOKRB5,
		"older":   testdata.KDC_PORT_TEST_GOKRB5_OLD,
		"latest":  testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	} {
		t.Run(name, func(t *testing.T) {
			env := liveEnvironment(t, port)
			for _, mode := range []string{"password", "keytab"} {
				t.Run(mode, func(t *testing.T) {
					cacheName := "FILE:" + filepath.Join(t.TempDir(), "gokinit.ccache")
					args := []string{"-r", "7d", "-c", cacheName, interopPrincipal}
					if port == testdata.KDC_PORT_TEST_GOKRB5_OLD {
						args = append([]string{"--no-request-enc-pa-rep"}, args...)
					}
					if mode == "password" {
						result := runPTYPassword(t, env, commandPath(t, "gokinit"), args...)
						if result.err != nil {
							t.Fatalf("gokinit failed: %v: %s", result.err, result.stdout)
						}
						if strings.Contains(result.stdout, interopPassword) {
							t.Fatal("gokinit echoed the password")
						}
					} else {
						args = append([]string{"-kt", keytabPath}, args...)
						result := runCommand(t, "", env, commandPath(t, "gokinit"), args...)
						if result.err != nil {
							t.Fatalf("gokinit keytab login failed: %v: %s", result.err, result.stderr)
						}
					}
					listed := runCommand(t, "", env, "klist", "-c", cacheName)
					if listed.err != nil || !strings.Contains(listed.stdout, interopPrincipal) || !strings.Contains(listed.stdout, "krbtgt/TEST.GOKRB5@TEST.GOKRB5") {
						t.Fatalf("MIT klist rejected gokinit cache: %v\n%s%s", listed.err, listed.stdout, listed.stderr)
					}
					renewed := runCommand(t, "", env, "kinit", "-R", "-c", cacheName)
					if renewed.err != nil {
						t.Fatalf("MIT kinit -R rejected gokinit cache: %v: %s", renewed.err, renewed.stderr)
					}
					service := runCommand(t, "", append(env, "KRB5CCNAME="+cacheName), "kvno", "-c", cacheName, interopService)
					if service.err != nil {
						t.Fatalf("MIT kvno rejected gokinit cache: %v: %s", service.err, service.stderr)
					}
					destroyed := runCommand(t, "", env, "kdestroy", "-c", cacheName)
					if destroyed.err != nil {
						t.Fatalf("MIT kdestroy rejected gokinit cache: %v: %s", destroyed.err, destroyed.stderr)
					}
				})
			}
		})
	}
}

func TestMITKinitToGokrb5(t *testing.T) {
	env := liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5)
	cacheName := "FILE:" + filepath.Join(t.TempDir(), "mit.ccache")
	login := runCommand(t, interopPassword+"\n", append(env, "KRB5CCNAME="+cacheName), "kinit", interopPrincipal)
	if login.err != nil {
		t.Fatalf("MIT kinit failed: %v: %s", login.err, login.stderr)
	}
	cache, err := credentials.LoadCCache(cacheName)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(strings.TrimPrefix(env[0], "KRB5_CONFIG="))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.NewFromCCache(cache, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.GetServiceTicket(interopService); err != nil {
		t.Fatalf("gokrb5 could not use MIT cache: %v", err)
	}
	exported, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	exportedName := "FILE:" + filepath.Join(t.TempDir(), "exported.ccache")
	if err := exported.WriteFile(exportedName); err != nil {
		t.Fatal(err)
	}
	listed := runCommand(t, "", env, "klist", "-c", exportedName)
	if listed.err != nil || !strings.Contains(listed.stdout, interopService) {
		t.Fatalf("MIT klist rejected re-exported cache: %v\n%s%s", listed.err, listed.stdout, listed.stderr)
	}
}

func TestKeytabLoginParity(t *testing.T) {
	env := liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5)
	keytabBytes, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(t.TempDir(), "client.keytab")
	if err := os.WriteFile(keytabPath, keytabBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		args []string
	}{
		{name: "default"},
		{name: "ticket options", args: []string{"-f", "-r", "7d", "-l", "2h", "-C"}},
		{name: "initial service", args: []string{"-S", interopService}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			mitCache := "FILE:" + filepath.Join(t.TempDir(), "mit.ccache")
			goCache := "FILE:" + filepath.Join(t.TempDir(), "go.ccache")
			mitArgs := append([]string{"-kt", keytabPath, "-c", mitCache}, scenario.args...)
			mitArgs = append(mitArgs, interopPrincipal)
			goArgs := append([]string{"-kt", keytabPath, "-c", goCache}, scenario.args...)
			goArgs = append(goArgs, interopPrincipal)
			mit := runCommand(t, "", env, "kinit", mitArgs...)
			if mit.err != nil {
				t.Fatalf("MIT keytab login failed: %v: %s", mit.err, mit.stderr)
			}
			goLogin := runCommand(t, "", env, commandPath(t, "gokinit"), goArgs...)
			if goLogin.err != nil {
				t.Fatalf("gokinit keytab login failed: %v: %s", goLogin.err, goLogin.stderr)
			}
			compareCaches(t, env, mitCache, goCache)
		})
	}
}

func compareCaches(t *testing.T, env []string, mitCache, goCache string) {
	t.Helper()
	mitList := runCommand(t, "", env, "klist", "-ef", "-c", mitCache)
	goList := runCommand(t, "", env, "klist", "-ef", "-c", goCache)
	if mitList.err != nil || goList.err != nil {
		t.Fatalf("klist parity failed: MIT=%v Go=%v", mitList.err, goList.err)
	}
	if !reflect.DeepEqual(klistSemantics(mitList.stdout), klistSemantics(goList.stdout)) {
		t.Fatalf("keytab login semantics differ\nMIT:\n%s\nGo:\n%s", mitList.stdout, goList.stdout)
	}
	mitParsed, err := credentials.LoadCCache(mitCache)
	if err != nil {
		t.Fatal(err)
	}
	goParsed, err := credentials.LoadCCache(goCache)
	if err != nil {
		t.Fatal(err)
	}
	mitEntries := mitParsed.GetEntries()
	goEntries := goParsed.GetEntries()
	if len(mitEntries) != len(goEntries) {
		t.Fatalf("credential counts differ: MIT=%d Go=%d", len(mitEntries), len(goEntries))
	}
	sort.Slice(mitEntries, func(left, right int) bool {
		return credentialName(mitEntries[left]) < credentialName(mitEntries[right])
	})
	sort.Slice(goEntries, func(left, right int) bool { return credentialName(goEntries[left]) < credentialName(goEntries[right]) })
	for index := range mitEntries {
		mitEntry := mitEntries[index]
		goEntry := goEntries[index]
		if mitEntry.Server.Realm != goEntry.Server.Realm || !mitEntry.Server.PrincipalName.Equal(goEntry.Server.PrincipalName) ||
			mitEntry.Key.KeyType != goEntry.Key.KeyType || !reflect.DeepEqual(mitEntry.TicketFlags, goEntry.TicketFlags) {
			t.Fatalf("parsed credential %d differs", index)
		}
		assertDurationClose(t, "ticket lifetime", mitEntry.EndTime.Sub(mitEntry.StartTime), goEntry.EndTime.Sub(goEntry.StartTime))
		assertDurationClose(t, "renew lifetime", mitEntry.RenewTill.Sub(mitEntry.StartTime), goEntry.RenewTill.Sub(goEntry.StartTime))
	}
}

func credentialName(credential *credentials.Credential) string {
	return credential.Server.PrincipalName.PrincipalNameString() + "@" + credential.Server.Realm
}

func assertDurationClose(t *testing.T, name string, left, right time.Duration) {
	t.Helper()
	difference := left - right
	if difference < 0 {
		difference = -difference
	}
	if difference > 5*time.Second {
		t.Fatalf("%s differs by %s (MIT=%s Go=%s)", name, difference, left, right)
	}
}

func klistSemantics(output string) []string {
	var result []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Default principal:") || strings.HasPrefix(trimmed, "Etype ") || strings.HasPrefix(trimmed, "Flags:") ||
			strings.Contains(trimmed, "@TEST.GOKRB5") {
			fields := strings.Fields(trimmed)
			if !strings.HasPrefix(trimmed, "Default principal:") && strings.Contains(trimmed, "@TEST.GOKRB5") && len(fields) >= 2 {
				trimmed = fields[len(fields)-1]
			}
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}

func TestRenewalParity(t *testing.T) {
	env := liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS)
	cacheName := "FILE:" + filepath.Join(t.TempDir(), "renew.ccache")
	login := runCommand(t, interopPassword+"\n", env, commandPath(t, "gokinit"), "--password-stdin", "-l", "1m", "-r", "1h", "-c", cacheName, interopPrincipal)
	if login.err != nil {
		t.Fatalf("renewable login failed: %v: %s", login.err, login.stderr)
	}
	before, err := credentials.LoadCCache(cacheName)
	if err != nil {
		t.Fatal(err)
	}
	entry := before.GetEntries()[0]
	lifetime := entry.EndTime.Sub(entry.StartTime)
	wait := entry.StartTime.Add(lifetime*5/6).Sub(time.Now().UTC()) + time.Second
	if wait > 90*time.Second {
		t.Fatalf("short-ticket KDC issued %s lifetime, requiring an excessive %s wait", lifetime, wait)
	}
	if wait > 0 {
		time.Sleep(wait)
	}
	renew := runCommand(t, "", env, commandPath(t, "gokinit"), "-R", "-c", cacheName)
	if renew.err != nil {
		t.Fatalf("gokinit renewal failed: %v: %s", renew.err, renew.stderr)
	}
	after, err := credentials.LoadCCache(cacheName)
	if err != nil {
		t.Fatal(err)
	}
	if !after.GetEntries()[0].EndTime.After(entry.EndTime) {
		t.Fatalf("renewal did not extend expiry beyond %s", entry.EndTime)
	}
	listed := runCommand(t, "", env, "klist", "-c", cacheName)
	if listed.err != nil {
		t.Fatalf("MIT klist rejected renewed cache: %v: %s", listed.err, listed.stderr)
	}
}

func TestClockSkewParity(t *testing.T) {
	env := append(liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5), "GOKRB5_TEST_TIME_OFFSET=1h")
	cacheName := "FILE:" + filepath.Join(t.TempDir(), "timesync.ccache")
	login := runCommand(t, interopPassword+"\n", env, commandPath(t, "gokinit"), "--password-stdin", "-c", cacheName, interopPrincipal)
	if login.err != nil {
		t.Fatalf("clock-skew retry failed: %v: %s", login.err, login.stderr)
	}
	cache, err := credentials.LoadCCache(cacheName)
	if err != nil {
		t.Fatal(err)
	}
	offset, found := cache.KDCTimeOffset()
	if !found || offset > -59*time.Minute || offset < -61*time.Minute {
		t.Fatalf("ccache KDC offset = %s, found=%t; want approximately -1h", offset, found)
	}
	listed := runCommand(t, "", env, "klist", "-c", cacheName)
	if listed.err != nil {
		t.Fatalf("MIT klist rejected skew-adjusted cache: %v: %s", listed.err, listed.stderr)
	}

	disabledEnv := withKrb5Setting(t, env, " kdc_timesync = 0\n")
	disabledCache := "FILE:" + filepath.Join(t.TempDir(), "disabled.ccache")
	disabled := runCommand(t, interopPassword+"\n", disabledEnv, commandPath(t, "gokinit"), "--password-stdin", "-c", disabledCache, interopPrincipal)
	if disabled.err == nil {
		t.Fatal("gokinit unexpectedly accepted a one-hour skew with kdc_timesync disabled")
	}
	if text := canonicalKinitError(disabled.stderr); text != "Clock skew too great" {
		t.Fatalf("disabled kdc_timesync error = %q, want %q; stderr: %s", text, "Clock skew too great", disabled.stderr)
	}
}

func withKrb5Setting(t *testing.T, env []string, setting string) []string {
	t.Helper()
	var configPath string
	for _, value := range env {
		if strings.HasPrefix(value, "KRB5_CONFIG=") {
			configPath = strings.TrimPrefix(value, "KRB5_CONFIG=")
			break
		}
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("[libdefaults]\n"), []byte("[libdefaults]\n"+setting), 1)
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return append(env, "KRB5_CONFIG="+path)
}

func TestErrorTextParity(t *testing.T) {
	liveEnv := liveEnvironment(t, testdata.KDC_PORT_TEST_GOKRB5)
	unreachableEnv := liveEnvironmentFile(t, "127.0.0.1", "1")
	tests := []struct {
		name      string
		env       []string
		principal string
		password  string
	}{
		{name: "wrong password", env: liveEnv, principal: interopPrincipal, password: "wrong-password"},
		{name: "unknown principal", env: liveEnv, principal: "does-not-exist@TEST.GOKRB5", password: interopPassword},
		{name: "unreachable KDC", env: unreachableEnv, principal: interopPrincipal, password: interopPassword},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mitCache := "FILE:" + filepath.Join(t.TempDir(), "mit.ccache")
			goCache := "FILE:" + filepath.Join(t.TempDir(), "go.ccache")
			mit := runCommand(t, tc.password+"\n", tc.env, "kinit", "-c", mitCache, tc.principal)
			gokrb5 := runCommand(t, tc.password+"\n", tc.env, commandPath(t, "gokinit"), "--password-stdin", "-c", goCache, tc.principal)
			if mit.err == nil || gokrb5.err == nil {
				t.Fatalf("expected both commands to fail: MIT=%v Go=%v", mit.err, gokrb5.err)
			}
			mitText := canonicalKinitError(mit.stderr)
			goText := canonicalKinitError(gokrb5.stderr)
			if mitText == "" || goText == "" {
				t.Fatalf("empty error text: MIT=%q Go=%q", mit.stderr, gokrb5.stderr)
			}
			if mitText != goText {
				t.Fatalf("error text differs: MIT=%q Go=%q\nMIT stderr: %s\nGo stderr: %s", mitText, goText, mit.stderr, gokrb5.stderr)
			}
		})
	}
}

func liveEnvironmentFile(t *testing.T, host, port string) []string {
	t.Helper()
	configuration := fmt.Sprintf("[libdefaults]\n default_realm = TEST.GOKRB5\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n TEST.GOKRB5 = {\n  kdc = %s:%s\n }\n", host, port)
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"KRB5_CONFIG=" + path, "LC_ALL=C", "TZ=UTC"}
}

func canonicalKinitError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if index := strings.Index(line, "kinit: "); index >= 0 {
			text := line[index+len("kinit: "):]
			if while := strings.Index(text, " while "); while >= 0 {
				text = text[:while]
			}
			return strings.TrimSpace(text)
		}
	}
	return strings.TrimSpace(output)
}
