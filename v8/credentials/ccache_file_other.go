//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris
// +build !aix,!darwin,!dragonfly,!freebsd,!illumos,!linux,!netbsd,!openbsd,!solaris

package credentials

import (
	"os/user"
)

func currentCacheUIDs() (string, string) {
	if current, err := user.Current(); err == nil {
		return current.Uid, current.Uid
	}
	return "0", "0"
}

func syncCacheDir(_ string) error { return nil }
