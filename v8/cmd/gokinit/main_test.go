package main

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestParseArgsMapsMITFlags(t *testing.T) {
	var stderr bytes.Buffer
	opts, err := parseArgs([]string{"-V", "-l", "2h", "-r", "7d", "-F", "-p", "-A", "-C", "-E", "-k", "-t", "client.keytab", "-c", "FILE:cache", "-S", "HTTP/host", "user@REALM"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, opts.verbose)
	assert.True(t, opts.useKeytab)
	assert.Equal(t, "client.keytab", opts.keytabName)
	assert.Equal(t, "user@REALM", opts.principal)
	assert.Equal(t, boolChoice{set: true, value: false}, opts.forwardable)
	assert.Equal(t, boolChoice{set: true, value: true}, opts.proxiable)
	assert.Equal(t, boolChoice{set: true, value: false}, opts.addresses)
}

func TestASRequestOptions(t *testing.T) {
	cfg := config.New()
	opts := initOptions{
		lifetime:      "2h",
		renewLifetime: "7d",
		forwardable:   boolChoice{set: true, value: false},
		proxiable:     boolChoice{set: true, value: true},
		addresses:     boolChoice{set: true, value: false},
		canonicalize:  true,
		enterprise:    true,
		service:       "HTTP/host.example.org",
	}
	request, err := asRequestOptions(opts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2*time.Hour, *request.Lifetime)
	assert.Equal(t, 7*24*time.Hour, *request.RenewLifetime)
	assert.False(t, *request.Forwardable)
	assert.True(t, *request.Proxiable)
	assert.Empty(t, request.Addresses)
	assert.NotNil(t, request.Addresses)
	assert.True(t, *request.Canonicalize)
	assert.True(t, *request.Enterprise)
	assert.Equal(t, []string{"HTTP", "host.example.org"}, request.ServicePrincipal.NameString)
}

func TestParseArgsRejectsConflicts(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"-i", "-t", "client.keytab"}, &stderr)
	assert.EqualError(t, err, "-i and -t are mutually exclusive")
	_, err = parseArgs([]string{"-R", "user@REALM"}, &stderr)
	assert.EqualError(t, err, "-R cannot be combined with credential acquisition options")
}

func TestParseArgsAcceptsCombinedKeytabFlags(t *testing.T) {
	var stderr bytes.Buffer
	opts, err := parseArgs([]string{"-kt", "client.keytab", "user@REALM"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, opts.useKeytab)
	assert.Equal(t, "client.keytab", opts.keytabName)

	opts, err = parseArgs([]string{"-ki", "user@REALM"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, opts.useKeytab)
	assert.True(t, opts.clientKeytab)
}

func TestValidateIsExplicitlyUnsupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 1, run([]string{"-v"}, bytes.NewReader(nil), &stdout, &stderr))
	assert.Equal(t, "gokinit: -v not supported\n", stderr.String())
}

func TestHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-h"}, bytes.NewReader(nil), &stdout, &stderr))
	assert.Contains(t, stderr.String(), usageLine)
}

func TestWriteCacheOmitsGSSRefreshTime(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cache := new(credentials.CCache)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	cl, err := client.NewFromCCache(cache, config.New())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ccache")
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 0, writeCache(cl, "FILE:"+path, false, &stdout, &stderr))
	written, err := credentials.LoadCCache(path)
	if err != nil {
		t.Fatal(err)
	}
	_, found := written.GetConfig("refresh_time", "")
	assert.False(t, found)
}
