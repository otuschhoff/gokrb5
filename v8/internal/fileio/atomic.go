// Package fileio implements shared credential-file persistence.
package fileio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type temporaryFile interface {
	io.WriteCloser
	Name() string
	Chmod(os.FileMode) error
	Sync() error
}

type fileOps struct {
	create func(string, string) (temporaryFile, error)
	rename func(string, string) error
	remove func(string) error
}

// AtomicWrite replaces path with private, synced data, then syncs its directory
// using the caller's platform-specific directory synchronization policy.
func AtomicWrite(path string, data []byte, syncDir func(string) error) error {
	ops := fileOps{
		create: func(dir, pattern string) (temporaryFile, error) {
			return os.CreateTemp(dir, pattern)
		},
		rename: os.Rename,
		remove: os.Remove,
	}
	return atomicWrite(path, data, syncDir, ops)
}

func atomicWrite(path string, data []byte, syncDir func(string) error, ops fileOps) error {
	dir := filepath.Dir(path)
	tmp, err := ops.create(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	if err := writeTemporary(tmp, data); err != nil {
		return removeTemporary(tmp.Name(), err, ops.remove)
	}
	if err := ops.rename(tmp.Name(), path); err != nil {
		return removeTemporary(tmp.Name(), fmt.Errorf("replace credential file: %w", err), ops.remove)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	return nil
}

func writeTemporary(tmp temporaryFile, data []byte) error {
	err := tmp.Chmod(0o600)
	if err == nil {
		var written int
		written, err = tmp.Write(data)
		if err == nil && written != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if err != nil {
		err = fmt.Errorf("persist temporary credential file: %w", err)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("close temporary credential file: %w", closeErr))
	}
	return err
}

func removeTemporary(path string, primary error, remove func(string) error) error {
	if err := remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(primary, fmt.Errorf("remove temporary credential file: %w", err))
	}
	return primary
}
