package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
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

func TestParseArgsDisablesPAReqEncPARep(t *testing.T) {
	var stderr bytes.Buffer
	opts, err := parseArgs([]string{"--no-request-enc-pa-rep", "user@REALM"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, opts.disablePAReqEncPARep)
}

func TestParseArgsAcceptsPKINITOptions(t *testing.T) {
	var stderr bytes.Buffer
	opts, err := parseArgs([]string{"-X", "X509_user_identity=PKCS12:user.p12", "-X", "X509_anchors=FILE:ca.pem", "user@REALM"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, stringList{"X509_user_identity=PKCS12:user.p12", "X509_anchors=FILE:ca.pem"}, opts.pkinitOptions)
}

func TestPKINITFilePath(t *testing.T) {
	path, err := pkinitFilePath("FILE:/etc/krb5/ca.pem")
	assert.NoError(t, err)
	assert.Equal(t, "/etc/krb5/ca.pem", path)
	_, err = pkinitFilePath("DIR:/etc/krb5/certs")
	assert.EqualError(t, err, `unsupported PKINIT anchor source "DIR:/etc/krb5/certs"`)
}

func TestValidateIsExplicitlyUnsupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	assert.Equal(t, 1, run([]string{"-v"}, bytes.NewReader(nil), &stdout, &stderr))
	assert.Equal(t, "gokinit: -v not supported\n", stderr.String())
}

func TestRunCredentialAcquisitionFailures(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "krb5.conf")
	configText := `[libdefaults]
 default_realm = EXAMPLE.ORG
 dns_lookup_kdc = false
 udp_preference_limit = 1
 default_tkt_enctypes = aes128-cts-hmac-sha1-96
[realms]
 EXAMPLE.ORG = {
  kdc = 127.0.0.1:1
 }
`
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)

	var stdout, stderr bytes.Buffer
	cachePath := filepath.Join(directory, "ccache")
	code := run([]string{"--password-stdin", "-c", "FILE:" + cachePath, "user@EXAMPLE.ORG"}, strings.NewReader("password\n"), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "while getting initial credentials") {
		t.Fatalf("password acquisition = code %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-k", "-t", filepath.Join(directory, "missing.keytab"), "-c", "FILE:" + cachePath, "user@EXAMPLE.ORG"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "while resolving keytab") {
		t.Fatalf("keytab acquisition = code %d, stderr %q", code, stderr.String())
	}
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

func TestLoadPKINITSettings(t *testing.T) {
	directory := t.TempDir()
	certificatePath, keyPath := writePKINITIdentity(t, directory)
	cfg := config.New()
	cfg.LibDefaults.PKINITIdentities = []string{"FILE:" + certificatePath + "," + keyPath}
	cfg.LibDefaults.PKINITAnchors = []string{"FILE:" + certificatePath}
	cfg.LibDefaults.PKINITPool = []string{"FILE:" + certificatePath}

	settings, usingPKINIT, err := loadPKINITSettings(initOptions{}, cfg, bytes.NewReader(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !usingPKINIT || len(settings) != 3 {
		t.Fatalf("using/settings = %v/%d", usingPKINIT, len(settings))
	}

	override := initOptions{pkinitOptions: stringList{
		"X509_user_identity=FILE:" + certificatePath + "," + keyPath,
		"X509_anchors=FILE:" + certificatePath,
	}}
	settings, usingPKINIT, err = loadPKINITSettings(override, config.New(), bytes.NewReader(nil), io.Discard)
	if err != nil || !usingPKINIT || len(settings) != 3 {
		t.Fatalf("override settings = %d, %v, %v", len(settings), usingPKINIT, err)
	}
}

func TestLoadPKINITSettingsRejectsInvalidConfiguration(t *testing.T) {
	directory := t.TempDir()
	certificatePath, keyPath := writePKINITIdentity(t, directory)
	identity := "FILE:" + certificatePath + "," + keyPath
	tests := []struct {
		name    string
		options stringList
		setup   func(*config.Config)
		wantErr string
	}{
		{name: "malformed option", options: stringList{"X509_user_identity"}, wantErr: "invalid -X option"},
		{name: "empty option", options: stringList{"X509_user_identity="}, wantErr: "invalid -X option"},
		{name: "unsupported option", options: stringList{"flag=value"}, wantErr: "unsupported -X option"},
		{name: "multiple identities", setup: func(config *config.Config) {
			config.LibDefaults.PKINITIdentities = []string{identity, identity}
		}, wantErr: "exactly one"},
		{name: "unsupported identity", setup: func(config *config.Config) {
			config.LibDefaults.PKINITIdentities = []string{"PKCS11:token"}
		}, wantErr: "unsupported PKINIT identity"},
		{name: "missing anchors", setup: func(config *config.Config) {
			config.LibDefaults.PKINITIdentities = []string{identity}
		}, wantErr: "trust anchors are required"},
		{name: "unsupported anchor", setup: func(config *config.Config) {
			config.LibDefaults.PKINITIdentities = []string{identity}
			config.LibDefaults.PKINITAnchors = []string{"DIR:" + directory}
		}, wantErr: "unsupported PKINIT anchor"},
		{name: "malformed anchor", setup: func(config *config.Config) {
			path := filepath.Join(directory, "malformed.pem")
			if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
				t.Fatal(err)
			}
			config.LibDefaults.PKINITIdentities = []string{identity}
			config.LibDefaults.PKINITAnchors = []string{"FILE:" + path}
		}, wantErr: "contains no certificates"},
		{name: "missing pool", setup: func(config *config.Config) {
			config.LibDefaults.PKINITIdentities = []string{identity}
			config.LibDefaults.PKINITAnchors = []string{"FILE:" + certificatePath}
			config.LibDefaults.PKINITPool = []string{"FILE:" + filepath.Join(directory, "missing.pem")}
		}, wantErr: "read PKINIT certificate pool"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := config.New()
			if test.setup != nil {
				test.setup(config)
			}
			_, _, err := loadPKINITSettings(initOptions{pkinitOptions: test.options}, config, bytes.NewReader(nil), io.Discard)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestGokinitPureHelpers(t *testing.T) {
	if displayCacheName("/tmp/ccache") != "FILE:/tmp/ccache" || displayCacheName("MEMORY:cache") != "MEMORY:cache" {
		t.Fatal("displayCacheName returned an unexpected value")
	}
	var stderr bytes.Buffer
	if code := fail(&stderr, errors.New("failure"), "testing"); code != 1 || !strings.Contains(stderr.String(), "failure testing") {
		t.Fatalf("fail = %d, %q", code, stderr.String())
	}
	if isPasswordExpired(errors.New("ordinary error")) {
		t.Fatal("ordinary error treated as an expired password")
	}
	if _, err := asRequestOptions(initOptions{lifetime: "invalid"}, config.New()); err == nil {
		t.Fatal("invalid lifetime accepted")
	}
	if _, err := asRequestOptions(initOptions{renewLifetime: "invalid"}, config.New()); err == nil {
		t.Fatal("invalid renewable lifetime accepted")
	}
	if _, err := asRequestOptions(initOptions{service: "/"}, config.New()); err == nil {
		t.Fatal("invalid service principal accepted")
	}
	if _, err := parseArgs([]string{"one", "two"}, io.Discard); err == nil {
		t.Fatal("multiple principals accepted")
	}
}

func TestLoadKeytabAndVerboseCacheOutput(t *testing.T) {
	data, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.keytab")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadKeytab(initOptions{keytabName: path}, config.New())
	if err != nil || len(loaded.Entries) == 0 {
		t.Fatalf("loaded keytab entries = %d, %v", len(loaded.Entries), err)
	}
	if _, err := loadKeytab(initOptions{keytabName: filepath.Join(t.TempDir(), "missing")}, config.New()); err == nil {
		t.Fatal("missing keytab returned no error")
	}

	cacheData, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cache := new(credentials.CCache)
	if err := cache.Unmarshal(cacheData); err != nil {
		t.Fatal(err)
	}
	cl, err := client.NewFromCCache(cache, config.New())
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cachePath := filepath.Join(t.TempDir(), "ccache")
	if code := writeCache(cl, cachePath, true, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Authenticated to Kerberos v5") || !strings.Contains(stdout.String(), "Using default cache: "+displayCacheName(cachePath)) {
		t.Fatalf("write cache = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if code := writeCache(cl, t.TempDir(), false, io.Discard, &stderr); code != 1 {
		t.Fatalf("directory cache write = %d", code)
	}
}

func TestLoadPKINITIdentityIOFailures(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"missing certificate", "FILE:" + missing, "read PKINIT certificate"},
		{"missing separate key", "FILE:" + filepath.Join(directory, "certificate") + "," + missing, "read PKINIT private key"},
		{"missing PKCS12", "PKCS12:" + missing, "read PKINIT PKCS#12 identity"},
		{"unsupported", "PKCS11:token", "unsupported PKINIT identity"},
	}
	if err := os.WriteFile(filepath.Join(directory, "certificate"), []byte("certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadPKINITIdentity(test.source, bytes.NewReader(nil), io.Discard, true); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadDefaultKeytabVariants(t *testing.T) {
	data, err := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	acceptorPath := filepath.Join(directory, "acceptor.keytab")
	clientPath := filepath.Join(directory, "client.keytab")
	if err := os.WriteFile(acceptorPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_KTNAME", "FILE:"+acceptorPath)
	t.Setenv("KRB5_CLIENT_KTNAME", "FILE:"+clientPath)
	if loaded, err := loadKeytab(initOptions{}, config.New()); err != nil || len(loaded.Entries) == 0 {
		t.Fatalf("default keytab = %v, %v", loaded, err)
	}
	if loaded, err := loadKeytab(initOptions{clientKeytab: true}, config.New()); err != nil || len(loaded.Entries) == 0 {
		t.Fatalf("client keytab = %v, %v", loaded, err)
	}
}

func TestRenewAndPasswordChangeFailures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := renewCredentials(filepath.Join(t.TempDir(), "missing.ccache"), config.New(), false, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "while renewing credentials") {
		t.Fatalf("missing renewal cache = %d, %q", code, stderr.String())
	}

	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(t.TempDir(), "ccache")
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := renewCredentials(cachePath, config.New(), false, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "while renewing credentials") {
		t.Fatalf("offline renewal = %d, %q", code, stderr.String())
	}

	cl := client.NewWithPassword("user", "EXAMPLE.ORG", "old", config.New())
	stderr.Reset()
	if err := changeExpiredPassword(cl, "user@EXAMPLE.ORG", strings.NewReader("first\nsecond\n"), &stderr, true); err == nil || err.Error() != "Password mismatch" {
		t.Fatalf("password mismatch error = %v", err)
	}
}

func TestRunRejectsInvalidArgumentsAndConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"one", "two"}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "too many arguments") {
		t.Fatalf("invalid arguments = %d, %q", code, stderr.String())
	}
	stderr.Reset()
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))
	if code := run([]string{"user@EXAMPLE.ORG"}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "loading Kerberos configuration") {
		t.Fatalf("missing configuration = %d, %q", code, stderr.String())
	}
}

func writePKINITIdentity(t *testing.T, directory string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PKINIT Test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "identity.pem")
	keyPath := filepath.Join(directory, "identity.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
