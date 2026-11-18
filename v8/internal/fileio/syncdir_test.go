//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package fileio

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "missing")
	err := syncDir(path)
	require.ErrorContains(t, err, "open directory:")
	require.ErrorIs(t, err, fs.ErrNotExist)
	pathErr, ok := errors.AsType[*fs.PathError](err)
	require.True(t, ok)
	require.Equal(t, path, pathErr.Path)
	require.NoError(t, syncDir(dir))
}
