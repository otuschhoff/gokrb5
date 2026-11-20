package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const testRealm = "EXAMPLE.ORG"

func testCacheEntry(endTime time.Time) *credentials.Credential {
	entry := new(credentials.Credential)
	entry.Client = credentials.Principal{
		Realm:         testRealm,
		PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
	}
	entry.Server = credentials.Principal{
		Realm:         testRealm,
		PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+testRealm),
	}
	entry.EndTime = endTime
	return entry
}

func TestListCacheAndSilentStatus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	cachePath := filepath.Join(dir, "ccache")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_realm = EXAMPLE.ORG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	clientName := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"user"}}
	cache := credentials.NewCCache(clientName, testRealm)
	now := time.Now().UTC()
	entry := testCacheEntry(now.Add(time.Hour))
	entry.AuthTime = now.Add(-time.Minute)
	entry.StartTime = entry.AuthTime
	entry.RenewTill = entry.EndTime
	cache.AddCredential(entry)
	if err := cache.WriteFile(cachePath); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-c", cachePath}, &stdout, &stderr))
	assert.Contains(t, stdout.String(), "Default principal: user@EXAMPLE.ORG")
	assert.Contains(t, stdout.String(), "krbtgt/EXAMPLE.ORG@EXAMPLE.ORG")
	stdout.Reset()
	assert.Equal(t, 0, run([]string{"-s", "-c", cachePath}, &stdout, &stderr))
	assert.Empty(t, stdout.String())
}

func TestListArgsRejectKeytabCacheCombination(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"-k", "-c", "cache"}, &stderr)
	assert.EqualError(t, err, "-k and -c are mutually exclusive")
}

func TestSilentMissingCacheProducesNoOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 1, run([]string{"-s", "-c", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr))
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
}

func TestHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-h"}, &stdout, &stderr))
	assert.Contains(t, stderr.String(), usageLine)
}

func TestListKeytabModes(t *testing.T) {
	data, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.keytab")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-k", "-t", "-K", "-e", path}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "testuser1@TEST.GOKRB5") {
		t.Fatalf("keytab listing = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	code = run([]string{"-k", "-s", path}, &stdout, &stderr)
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("silent keytab listing = %d, %q", code, stdout.String())
	}
	stderr.Reset()
	code = run([]string{"-k", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "goklist:") {
		t.Fatalf("missing keytab = %d, %q", code, stderr.String())
	}
}

func TestListCacheExpiredAndArgumentErrors(t *testing.T) {
	clientName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	cache := credentials.NewCCache(clientName, testRealm)
	cache.AddCredential(testCacheEntry(time.Now().UTC().Add(-time.Hour)))
	path := filepath.Join(t.TempDir(), "expired.ccache")
	if err := cache.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-s", "-c", path}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("expired cache status = %d", code)
	}
	for _, args := range [][]string{{"-t"}, {"-K"}, {"one", "two"}} {
		if _, err := parseArgs(args, io.Discard); err == nil {
			t.Fatalf("arguments %q were accepted", args)
		}
	}
}

func TestListCacheFixtureWithEtypesAndPositionalName(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.ccache")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-e", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("fixture listing = %d, %q", code, stderr.String())
	}
	assert.Contains(t, stdout.String(), "Etype (skey, tkt):")
	assert.Contains(t, stdout.String(), "Ticket cache: "+displayCacheName(path))
}

func TestListCacheReportsOutputFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "empty.ccache")
	name := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	if err := credentials.NewCCache(name, testRealm).WriteFile(path); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	writer := failingWriter{err: errors.New("stdout failed")}
	code := run([]string{"-c", path, "ignored.ccache"}, writer, &stderr)
	assert.Equal(t, 1, code)
	assert.Equal(t, "goklist: stdout failed\n", stderr.String())
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestListDefaultAndParseFailures(t *testing.T) {
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "goklist:") {
		t.Fatalf("missing config = %d, %q", code, stderr.String())
	}
	stderr.Reset()
	code := run([]string{"-unknown"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "flag provided") {
		t.Fatalf("invalid flag = %d, %q", code, stderr.String())
	}
}

func TestListDefaultKeytab(t *testing.T) {
	directory := t.TempDir()
	keytabData, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(directory, "default.keytab")
	if ierr := os.WriteFile(keytabPath, keytabData, 0o600); ierr != nil {
		t.Fatal(ierr)
	}
	t.Setenv("KRB5_KTNAME", "FILE:"+keytabPath)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-k"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "testuser1@TEST.GOKRB5") {
		t.Fatalf("default keytab = %d, %q, %q", code, stdout.String(), stderr.String())
	}
}

func TestListDefaultCache(t *testing.T) {
	directory := t.TempDir()
	cacheData, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(directory, "default.ccache")
	if err := os.WriteFile(cachePath, cacheData, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "krb5.conf")
	configText := "[libdefaults]\n default_ccache_name = FILE:" + cachePath + "\n"
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	t.Setenv("KRB5CCNAME", "")
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Ticket cache: "+displayCacheName(cachePath)) {
		t.Fatalf("default cache = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if displayCacheName("MEMORY:cache") != "MEMORY:cache" {
		t.Fatal("typed cache name was modified")
	}
}
