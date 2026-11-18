//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package fileio

// Keep directory syncing disabled on platforms where it was not enabled.
func syncDir(_ string) error { return nil }
