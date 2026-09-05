package main

import (
	"bytes"
	"os"
	"path/filepath"
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
