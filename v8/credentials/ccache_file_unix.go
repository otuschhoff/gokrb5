//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd illumos linux netbsd openbsd solaris

package credentials

import (
	"errors"
	"os"
	"strconv"
)

func currentCacheUIDs() (string, string) {
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Geteuid())
}

func syncCacheDir(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- path is an explicit API/test/config input, not request-derived traversal.
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}
