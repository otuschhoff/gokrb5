package credentials

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const spn = "HTTP/host.test.gokrb5"

func loadNativeCCache(t *testing.T, withServiceTicket bool) *CCache {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "krb5.conf")
	cachePath := filepath.Join(dir, "ccache")
	require.NoError(t, os.WriteFile(configPath, []byte(testdata.KRB5_CONF), 0o600), "write test configuration")

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	login := exec.CommandContext(ctx, "kinit", "testuser1@TEST.GOKRB5")
	login.Stdin = strings.NewReader(testdata.TESTUSER_PASSWORD + "\n")
	commands := []*exec.Cmd{login}
	if withServiceTicket {
		commands = append(commands, exec.CommandContext(ctx, "kvno", spn))
	}
	for _, cmd := range commands {
		cmd.Env = append(cmd.Environ(), "KRB5_CONFIG="+configPath, "KRB5CCNAME=FILE:"+cachePath)
		cmd.WaitDelay = time.Second
		if _, err := cmd.Output(); err != nil {
			if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && len(exitErr.Stderr) > 0 {
				t.Logf("%s stderr: %s", cmd.Args[0], strings.TrimSpace(string(exitErr.Stderr)))
			}
			t.Fatalf("run %s: %v", cmd.Args[0], errors.Join(err, ctx.Err()))
		}
	}
	cache, err := LoadCCache(cachePath)
	require.NoError(t, err, "load native credential cache")
	return cache
}

func TestLoadCCache(t *testing.T) {
	test.Privileged(t)

	c := loadNativeCCache(t, false)
	pn := c.GetClientPrincipalName()
	assert.Equal(t, "testuser1", pn.PrincipalNameString(), "principal not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.GetClientRealm(), "realm not as expected")
}

func TestCCacheEntries(t *testing.T) {
	test.Privileged(t)

	// Deliberately give the parent a config and cache that the native tools must not use.
	dir := t.TempDir()
	inheritedCache := filepath.Join(dir, "caller.ccache")
	t.Setenv("KRB5_CONFIG", filepath.Join(dir, "missing.conf"))
	t.Setenv("KRB5CCNAME", "FILE:"+inheritedCache)

	c := loadNativeCCache(t, true)
	assert.NoFileExists(t, inheritedCache, "native commands must not create the caller's cache")
	n := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	found := slices.ContainsFunc(c.GetEntries(), func(cred *Credential) bool {
		return cred.Server.PrincipalName.Equal(n)
	})
	assert.True(t, found, "entry for %s not found in cache", spn)
}
