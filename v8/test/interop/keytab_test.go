//go:build interop
// +build interop

package interop

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	interopPrincipal = "testuser1@TEST.GOKRB5"
	interopPassword  = "passwordvalue"
)

type commandResult struct {
	stdout string
	stderr string
	err    error
}

func requireCommands(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is required for MIT interoperability testing", name)
		}
	}
}

func runCommand(t *testing.T, stdin string, env []string, name string, args ...string) commandResult {
	t.Helper()
	command := exec.Command(name, args...)
	command.Stdin = strings.NewReader(stdin)
	command.Env = mergedEnvironment(env)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return commandResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func mergedEnvironment(overrides []string) []string {
	replaced := make(map[string]struct{}, len(overrides))
	lastOverride := make(map[string]int, len(overrides))
	for overrideIndex, value := range overrides {
		if separator := strings.IndexByte(value, '='); separator >= 0 {
			key := value[:separator]
			replaced[key] = struct{}{}
			lastOverride[key] = overrideIndex
		}
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, value := range os.Environ() {
		key := value
		if index := strings.IndexByte(value, '='); index >= 0 {
			key = value[:index]
		}
		if _, replace := replaced[key]; !replace {
			result = append(result, value)
		}
	}
	for index, value := range overrides {
		separator := strings.IndexByte(value, '=')
		if separator < 0 || lastOverride[value[:separator]] == index {
			result = append(result, value)
		}
	}
	return result
}

func TestMergedEnvironmentLastOverrideWins(t *testing.T) {
	t.Setenv("GOKRB5_INTEROP_ENV_TEST", "inherited")
	environment := mergedEnvironment([]string{"GOKRB5_INTEROP_ENV_TEST=first", "GOKRB5_INTEROP_ENV_TEST=last"})
	var matches []string
	for _, value := range environment {
		if strings.HasPrefix(value, "GOKRB5_INTEROP_ENV_TEST=") {
			matches = append(matches, value)
		}
	}
	if len(matches) != 1 || matches[0] != "GOKRB5_INTEROP_ENV_TEST=last" {
		t.Fatalf("merged overrides = %v, want only the final value", matches)
	}
}

func ktutilWrite(t *testing.T, path string, entries ...string) {
	t.Helper()
	requireCommands(t, "ktutil")
	var script strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&script, "addent -password %s\n%s\n", entry, interopPassword)
	}
	fmt.Fprintf(&script, "wkt %s\nquit\n", path)
	result := runCommand(t, script.String(), nil, "ktutil")
	if result.err != nil {
		t.Fatalf("ktutil failed: %v: %s", result.err, result.stderr)
	}
}

func TestGoKeytabToMIT(t *testing.T) {
	requireCommands(t, "klist", "ktutil")
	principal, err := keytab.ParsePrincipal(interopPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	etypes := []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.RC4_HMAC,
		etypeID.DES3_CBC_SHA1_KD,
	}
	kt := keytab.New()
	timestamp := time.Unix(1700000000, 0).UTC()
	for _, etype := range etypes {
		if err := kt.AddEntry(strings.Join(principal.Components, "/"), principal.Realm, interopPassword, timestamp, 300, etype); err != nil {
			t.Fatalf("add enctype %d: %v", etype, err)
		}
	}
	path := filepath.Join(t.TempDir(), "go.keytab")
	if err := kt.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	listed := runCommand(t, "", []string{"LC_ALL=C", "TZ=UTC"}, "klist", "-kte", path)
	if listed.err != nil {
		t.Fatalf("MIT klist rejected Go keytab: %v: %s", listed.err, listed.stderr)
	}
	if count := strings.Count(listed.stdout, interopPrincipal); count != len(etypes) {
		t.Fatalf("MIT klist showed %d entries, want %d:\n%s", count, len(etypes), listed.stdout)
	}
	for _, etype := range etypes {
		if !strings.Contains(listed.stdout, "("+etypeID.ETypeToString(etype)+")") {
			t.Errorf("MIT klist omitted enctype %d:\n%s", etype, listed.stdout)
		}
	}
	if !strings.Contains(listed.stdout, " 300 ") {
		t.Fatalf("MIT klist did not preserve kvno 300:\n%s", listed.stdout)
	}

	result := runCommand(t, fmt.Sprintf("rkt %s\nlist -e -t\nquit\n", path), []string{"LC_ALL=C", "TZ=UTC"}, "ktutil")
	if result.err != nil || strings.Count(result.stdout, interopPrincipal) != len(etypes) {
		t.Fatalf("MIT ktutil did not parse Go keytab: %v: %s%s", result.err, result.stdout, result.stderr)
	}
}

func TestMITKeytabToGo(t *testing.T) {
	requireCommands(t, "klist", "ktutil")
	path := filepath.Join(t.TempDir(), "mit.keytab")
	ktutilWrite(t, path,
		"-p "+interopPrincipal+" -k 7 -e aes128-cts-hmac-sha1-96",
		"-p "+interopPrincipal+" -k 300 -e aes256-cts-hmac-sha1-96",
	)

	listed := runCommand(t, "", []string{"LC_ALL=C", "TZ=UTC"}, "klist", "-kteK", path)
	if listed.err != nil {
		t.Fatalf("MIT klist failed: %v: %s", listed.err, listed.stderr)
	}
	parsed, err := keytab.Load(path)
	if err != nil {
		t.Fatalf("Go rejected MIT keytab: %v", err)
	}
	principal, _ := keytab.ParsePrincipal(interopPrincipal)
	linePattern := regexp.MustCompile(`(?m)^\s*(\d+)\s+.*?` + regexp.QuoteMeta(interopPrincipal) + `\s+\([^)]*\)\s+\(0x([0-9a-fA-F]+)\)$`)
	matches := linePattern.FindAllStringSubmatch(listed.stdout, -1)
	if len(matches) != 2 {
		t.Fatalf("could not parse MIT keys from output:\n%s", listed.stdout)
	}
	for _, match := range matches {
		kvno, _ := strconv.ParseUint(match[1], 10, 32)
		var etype int32
		if kvno == 7 {
			etype = etypeID.AES128_CTS_HMAC_SHA1_96
		} else {
			etype = etypeID.AES256_CTS_HMAC_SHA1_96
		}
		entry, err := parsed.GetEntry(principal, uint32(kvno), etype)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(entry.Key.KeyValue) != strings.ToLower(match[2]) {
			t.Errorf("key mismatch for kvno %d", kvno)
		}
	}
}

func TestModifyInterop(t *testing.T) {
	requireCommands(t, "klist", "ktutil")
	path := filepath.Join(t.TempDir(), "modify.keytab")
	ktutilWrite(t, path,
		"-p "+interopPrincipal+" -k 1 -e aes256-cts-hmac-sha1-96",
		"-p "+interopPrincipal+" -k 2 -e aes256-cts-hmac-sha1-96",
	)
	kt, err := keytab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := keytab.ParsePrincipal(interopPrincipal)
	if removed := kt.RemoveOldKVNO(principal, 1); removed != 1 {
		t.Fatalf("removed %d old entries, want 1", removed)
	}
	if err := kt.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	listed := runCommand(t, "", []string{"LC_ALL=C"}, "klist", "-kt", path)
	if listed.err != nil || strings.Contains(listed.stdout, "   1 ") || !strings.Contains(listed.stdout, "   2 ") {
		t.Fatalf("MIT did not observe Go modification: %v\n%s%s", listed.err, listed.stdout, listed.stderr)
	}

	newPath := path + ".new"
	script := fmt.Sprintf("rkt %s\naddent -password -p %s -k 3 -e aes256-cts-hmac-sha1-96\n%s\nwkt %s\nquit\n", path, interopPrincipal, interopPassword, newPath)
	result := runCommand(t, script, nil, "ktutil")
	if result.err != nil {
		t.Fatalf("ktutil append failed: %v: %s", result.err, result.stderr)
	}
	if err := os.Rename(newPath, path); err != nil {
		t.Fatal(err)
	}
	modified, err := keytab.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modified.GetEntry(principal, 2, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	if _, err := modified.GetEntry(principal, 3, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAppendInterop(t *testing.T) {
	requireCommands(t, "klist", "ktutil")
	path := filepath.Join(t.TempDir(), "concurrent.keytab")
	ktutilWrite(t, path, "-p "+interopPrincipal+" -k 1 -e aes256-cts-hmac-sha1-96")
	principal, _ := keytab.ParsePrincipal(interopPrincipal)
	entry := keytab.Entry{
		Principal: principal,
		Timestamp: time.Now().UTC(),
		KVNO:      2,
		Key: types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: bytes.Repeat([]byte{0x42}, 32),
		},
	}
	script := fmt.Sprintf("addent -password -p %s -k 3 -e aes128-cts-hmac-sha1-96\n%s\nwkt %s\nquit\n", interopPrincipal, interopPassword, path)
	command := exec.Command("ktutil")
	command.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	command.Stderr = &stderr

	start := make(chan struct{})
	var appendErr error
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		appendErr = keytab.AppendToFile(path, entry)
	}()
	close(start)
	mitErr := command.Run()
	wait.Wait()
	if mitErr != nil {
		t.Fatalf("concurrent ktutil write failed: %v: %s", mitErr, stderr.String())
	}
	if appendErr != nil {
		t.Fatalf("concurrent Go append failed: %v", appendErr)
	}
	if _, err := keytab.Load(path); err != nil {
		t.Fatalf("Go could not parse concurrently written keytab: %v", err)
	}
	listed := runCommand(t, "", nil, "klist", "-kte", path)
	if listed.err != nil {
		t.Fatalf("MIT could not parse concurrently written keytab: %v: %s", listed.err, listed.stderr)
	}
}
