//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows
// +build !aix,!darwin,!dragonfly,!freebsd,!illumos,!linux,!netbsd,!openbsd,!solaris,!windows

package keytab

import (
	"os"
	"os/user"
)

func lockFile(_ *os.File) error { return nil }

func unlockFile(_ *os.File) {}

func syncDir(_ string) error { return nil }

func currentUIDs() (string, string) {
	if current, err := user.Current(); err == nil {
		return current.Uid, current.Gid
	}
	return "0", "0"
}
