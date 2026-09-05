//go:build aix || illumos || solaris
// +build aix illumos solaris

package keytab

import (
	"io"
	"os"
	"strconv"
	"syscall"
)

func lockFile(f *os.File) error {
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: int16(io.SeekStart)}
	return syscall.FcntlFlock(f.Fd(), syscall.F_SETLKW, &lock)
}

func unlockFile(f *os.File) {
	lock := syscall.Flock_t{Type: syscall.F_UNLCK, Whence: int16(io.SeekStart)}
	_ = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func currentUIDs() (string, string) {
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Geteuid())
}
