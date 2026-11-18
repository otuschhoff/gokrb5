//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package fileio

import (
	"errors"
	"fmt"
	"os"
)

func syncDir(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- directory is derived from the caller-selected credential path.
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	syncErr := dir.Sync()
	if syncErr != nil {
		syncErr = fmt.Errorf("sync directory: %w", syncErr)
	}
	if closeErr := dir.Close(); closeErr != nil {
		return errors.Join(syncErr, fmt.Errorf("close directory: %w", closeErr))
	}
	return syncErr
}
