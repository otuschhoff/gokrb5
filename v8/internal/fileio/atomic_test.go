package fileio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type faultFile struct {
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
	short    bool
	closes   int
}

func (*faultFile) Name() string { return "temporary" }
func (f *faultFile) Chmod(mode os.FileMode) error {
	if mode != 0o600 {
		return os.ErrPermission
	}
	return f.chmodErr
}

func (f *faultFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (f *faultFile) Sync() error { return f.syncErr }
func (f *faultFile) Close() error {
	f.closes++
	return f.closeErr
}

func TestAtomicWriteRetainsFirstTypedCause(t *testing.T) {
	primary := &os.PathError{Op: "write", Path: "cache", Err: io.ErrClosedPipe}
	cleanup := &os.PathError{Op: "close", Path: "cache", Err: os.ErrPermission}
	file := &faultFile{writeErr: primary, closeErr: cleanup}
	ops := fileOps{
		create: func(_, _ string) (temporaryFile, error) { return file, nil },
		remove: func(_ string) error { return nil },
		rename: func(_, _ string) error { t.Fatal("renamed failed file"); return nil },
	}
	err := atomicWrite("cache", []byte("data"), func(_ string) error {
		t.Fatal("synced uncommitted file")
		return nil
	}, ops)
	got, ok := errors.AsType[*os.PathError](err)
	if !ok || got != primary || !errors.Is(err, cleanup) {
		t.Fatalf("primary failure order or cleanup identity lost: %v", err)
	}
}

func TestAtomicWriteFailures(t *testing.T) {
	primary := errors.New("injected operation failure")
	cleanup := errors.New("injected cleanup failure")
	tests := []struct {
		name      string
		file      faultFile
		createErr error
		renameErr error
		dirErr    error
		removeErr error
		wantErr   error
		wantClean bool
	}{
		{name: "success"},
		{name: "create", createErr: primary, wantErr: primary},
		{name: "permissions", file: faultFile{chmodErr: primary}, wantErr: primary, wantClean: true},
		{name: "write and close", file: faultFile{writeErr: primary, closeErr: cleanup}, wantErr: primary, wantClean: true},
		{name: "short write", file: faultFile{short: true}, wantErr: io.ErrShortWrite, wantClean: true},
		{name: "sync", file: faultFile{syncErr: primary}, wantErr: primary, wantClean: true},
		{name: "close", file: faultFile{closeErr: primary}, wantErr: primary, wantClean: true},
		{name: "rename", renameErr: primary, wantErr: primary, wantClean: true},
		{name: "rename and remove", renameErr: primary, removeErr: cleanup, wantErr: primary, wantClean: true},
		{name: "directory sync after commit", dirErr: primary, wantErr: primary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			removed, renamed, synced := false, false, false
			ops := fileOps{
				create: func(dir, pattern string) (temporaryFile, error) {
					if dir != "directory" || pattern != ".cache.tmp-" {
						t.Fatalf("temporary location = %q, %q", dir, pattern)
					}
					return &tt.file, tt.createErr
				},
				rename: func(_, _ string) error { renamed = true; return tt.renameErr },
				remove: func(_ string) error { removed = true; return tt.removeErr },
			}
			err := atomicWrite(filepath.Join("directory", "cache"), []byte("data"), func(_ string) error {
				synced = true
				return tt.dirErr
			}, ops)
			if !errors.Is(err, tt.wantErr) || removed != tt.wantClean {
				t.Fatalf("write = %v, removed = %v; want %v, %v", err, removed, tt.wantErr, tt.wantClean)
			}
			if tt.createErr == nil && tt.file.closes != 1 {
				t.Fatalf("Close called %d times", tt.file.closes)
			}
			if tt.file.closeErr != nil && !errors.Is(err, tt.file.closeErr) {
				t.Fatal("close failure was lost")
			}
			if tt.removeErr != nil && !errors.Is(err, tt.removeErr) {
				t.Fatal("cleanup failure was lost")
			}
			if (tt.file.chmodErr != nil || tt.file.writeErr != nil || tt.file.short || tt.file.syncErr != nil || tt.file.closeErr != nil) && renamed {
				t.Fatal("renamed an incomplete credential file")
			}
			if synced && (!renamed || tt.renameErr != nil) {
				t.Fatal("directory sync preceded a successful replacement")
			}
		})
	}
}
