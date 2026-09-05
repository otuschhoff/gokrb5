package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
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
