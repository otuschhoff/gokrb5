package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDestroyExplicitFileCache(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	cachePath := filepath.Join(dir, "ccache")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_realm = EXAMPLE.ORG\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	var stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-c", "FILE:" + cachePath}, &stderr))
	_, err := os.Stat(cachePath)
	assert.True(t, os.IsNotExist(err))
}

func TestDestroyQuietSuppressesErrors(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_realm = EXAMPLE.ORG\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	var stderr bytes.Buffer
	assert.Equal(t, 1, run([]string{"-q", "-c", "DIR:/unsupported"}, &stderr))
	assert.Empty(t, stderr.String())
}

func TestDestroyRejectsAllWithExplicitCache(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseArgs([]string{"-A", "-c", "cache"}, &stderr)
	assert.EqualError(t, err, "-A and -c are mutually exclusive")
}

func TestDestroyAllRemovesDefaultFileCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "ccache")
	configPath := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(cachePath, []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_ccache_name = FILE:"+cachePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	t.Setenv("KRB5CCNAME", "")
	var stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-A"}, &stderr))
	_, err := os.Stat(cachePath)
	assert.True(t, os.IsNotExist(err))
}

func TestHelpSucceeds(t *testing.T) {
	var stderr bytes.Buffer
	assert.Equal(t, 0, run([]string{"-h"}, &stderr))
	assert.Contains(t, stderr.String(), usageLine)
}

func TestDestroyMissingCacheIsIdempotent(t *testing.T) {
	var stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "missing.ccache")
	if code := run([]string{"-c", path}, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("missing cache removal = %d, %q", code, stderr.String())
	}
}

func TestDestroyReportsRemovalAndConfigurationErrors(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "child"), []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"-c", directory}, &stderr); code != 1 || !strings.Contains(stderr.String(), "while destroying cache") {
		t.Fatalf("directory removal = %d, %q", code, stderr.String())
	}

	stderr.Reset()
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))
	if code := run([]string{"-A"}, &stderr); code != 1 || !strings.Contains(stderr.String(), "while destroying cache") {
		t.Fatalf("missing config = %d, %q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"unexpected"}, &stderr); code != 1 || !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("unexpected argument = %d, %q", code, stderr.String())
	}
}

func TestDestroyDefaultCacheAndUnsupportedDefault(t *testing.T) {
	directory := t.TempDir()
	cachePath := filepath.Join(directory, "default.ccache")
	configPath := filepath.Join(directory, "krb5.conf")
	if err := os.WriteFile(cachePath, []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_ccache_name = FILE:"+cachePath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", configPath)
	t.Setenv("KRB5CCNAME", "")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 0 {
		t.Fatalf("default cache removal = %d, %q", code, stderr.String())
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("default cache still exists: %v", err)
	}

	t.Setenv("KRB5CCNAME", "DIR:/unsupported")
	stderr.Reset()
	if code := run([]string{"-A"}, &stderr); code != 1 || !strings.Contains(stderr.String(), "while destroying cache") {
		t.Fatalf("unsupported default = %d, %q", code, stderr.String())
	}
}
