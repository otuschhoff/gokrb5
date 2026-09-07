package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestListCacheAndSilentStatus(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	cachePath := filepath.Join(dir, "ccache")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_realm = EXAMPLE.ORG\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	clientName := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"user"}}
	cache := credentials.NewCCache(clientName, "EXAMPLE.ORG")
	now := time.Now().UTC()
	cache.AddCredential(&credentials.Credential{
		Client:    credentials.Principal{Realm: "EXAMPLE.ORG", PrincipalName: clientName},
		Server:    credentials.Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "EXAMPLE.ORG"}}},
		AuthTime:  now.Add(-time.Minute),
		StartTime: now.Add(-time.Minute),
		EndTime:   now.Add(time.Hour),
		RenewTill: now.Add(time.Hour),
	})
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
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-k", "-t", "-K", "-e", path}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "testuser1@TEST.GOKRB5") {
		t.Fatalf("keytab listing = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := listKeytab(listOptions{keytab: true, silent: true, name: path}, &stdout, &stderr); code != 0 || stdout.Len() != 0 {
		t.Fatalf("silent keytab listing = %d, %q", code, stdout.String())
	}
	stderr.Reset()
	if code := run([]string{"-k", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "goklist:") {
		t.Fatalf("missing keytab = %d, %q", code, stderr.String())
	}
}

func TestListCacheExpiredAndArgumentErrors(t *testing.T) {
	clientName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	cache := credentials.NewCCache(clientName, "EXAMPLE.ORG")
	cache.AddCredential(&credentials.Credential{
		Client:  credentials.Principal{Realm: "EXAMPLE.ORG", PrincipalName: clientName},
		Server:  credentials.Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.ORG")},
		EndTime: time.Now().UTC().Add(-time.Hour),
	})
	path := filepath.Join(t.TempDir(), "expired.ccache")
	if err := cache.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	if code := listCache(listOptions{cacheName: path, silent: true}, io.Discard, io.Discard); code != 1 {
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
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-e", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("fixture listing = %d, %q", code, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "Etype (skey, tkt):") || !strings.Contains(output, "Ticket cache: FILE:") {
		t.Fatalf("fixture output = %q", output)
	}
}

func TestListDefaultAndParseFailures(t *testing.T) {
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "goklist:") {
		t.Fatalf("missing config = %d, %q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"-unknown"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "flag provided") {
		t.Fatalf("invalid flag = %d, %q", code, stderr.String())
	}
}

func TestListDefaultKeytabAndCache(t *testing.T) {
	directory := t.TempDir()
	keytabData, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(directory, "default.keytab")
	if err := os.WriteFile(keytabPath, keytabData, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_KTNAME", "FILE:"+keytabPath)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-k"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "testuser1@TEST.GOKRB5") {
		t.Fatalf("default keytab = %d, %q, %q", code, stdout.String(), stderr.String())
	}

	cacheData, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(directory, "default.ccache")
	if err := os.WriteFile(cachePath, cacheData, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "krb5.conf")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_ccache_name = FILE:"+cachePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	t.Setenv("KRB5CCNAME", "")
	stdout.Reset()
	stderr.Reset()
	if code := run(nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Ticket cache: FILE:") {
		t.Fatalf("default cache = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if displayCacheName("MEMORY:cache") != "MEMORY:cache" {
		t.Fatal("typed cache name was modified")
	}
}
