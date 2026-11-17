//go:build aix || illumos || solaris
// +build aix illumos solaris

package keytab

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

func lockFile(f *os.File) error {
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: int16(io.SeekStart)}
	return syscall.FcntlFlock(f.Fd(), syscall.F_SETLKW, &lock)
}

func unlockFile(f *os.File) error {
	lock := syscall.Flock_t{Type: syscall.F_UNLCK, Whence: int16(io.SeekStart)}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); err != nil {
		return fmt.Errorf("unlock keytab: %w", err)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

func currentUIDs() (string, string) {
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Geteuid())
}
