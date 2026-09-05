//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd illumos linux netbsd openbsd solaris

package credentials

import (
	"os"
	"strconv"
)

func currentCacheUIDs() (string, string) {
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Geteuid())
}

func syncCacheDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
