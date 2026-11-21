package fileio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	var file faultFile
	file.writeErr = primary
	file.closeErr = cleanup
	ops := fileOps{
		create: func(_, _ string) (temporaryFile, error) { return &file, nil },
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

type writeFaults struct {
	file      faultFile
	createErr error
	renameErr error
	dirErr    error
	removeErr error
}

func (f *writeFaults) run(t *testing.T) (string, error) {
	t.Helper()

	const dir = "directory"
	path := filepath.Join(dir, "cache")
	var calls []string
	ops := fileOps{
		create: func(gotDir, pattern string) (temporaryFile, error) {
			calls = append(calls, "create")
			if gotDir != dir || pattern != ".cache.tmp-" {
				t.Fatalf("temporary location = %q, %q", gotDir, pattern)
			}
			return &f.file, f.createErr
		},
		rename: func(from, to string) error {
			calls = append(calls, "rename")
			if from != f.file.Name() || to != path {
				t.Fatalf("rename paths = %q, %q", from, to)
			}
			return f.renameErr
		},
		remove: func(path string) error {
			calls = append(calls, "remove")
			if path != f.file.Name() {
				t.Fatalf("removed path = %q", path)
			}
			return f.removeErr
		},
	}
	syncDirectory := func(gotDir string) error {
		calls = append(calls, "sync directory")
		if gotDir != dir {
			t.Fatalf("synced directory = %q, want %q", gotDir, dir)
		}
		return f.dirErr
	}
	err := atomicWrite(path, []byte("data"), syncDirectory, ops)
	return strings.Join(calls, ", "), err
}

type atomicWriteCase struct {
	name        string
	inject      func(*writeFaults)
	wantErr     error
	wantCleanup error
	wantCalls   string
	wantCloses  int
}

func atomicWriteCases() []atomicWriteCase {
	primary := errors.New("injected operation failure")
	cleanup := errors.New("injected cleanup failure")
	const (
		committed    = "create, rename, sync directory"
		abandoned    = "create, remove"
		renameFailed = "create, rename, remove"
	)
	return []atomicWriteCase{
		{name: "success", inject: nil, wantErr: nil, wantCleanup: nil, wantCalls: committed, wantCloses: 1},
		{
			name: "create", inject: func(f *writeFaults) { f.createErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: "create", wantCloses: 0,
		},
		{
			name: "permissions", inject: func(f *writeFaults) { f.file.chmodErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: abandoned, wantCloses: 1,
		},
		{
			name: "write and close", inject: func(f *writeFaults) { f.file.writeErr, f.file.closeErr = primary, cleanup },
			wantErr: primary, wantCleanup: cleanup, wantCalls: abandoned, wantCloses: 1,
		},
		{
			name: "short write", inject: func(f *writeFaults) { f.file.short = true },
			wantErr: io.ErrShortWrite, wantCleanup: nil, wantCalls: abandoned, wantCloses: 1,
		},
		{
			name: "sync", inject: func(f *writeFaults) { f.file.syncErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: abandoned, wantCloses: 1,
		},
		{
			name: "close", inject: func(f *writeFaults) { f.file.closeErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: abandoned, wantCloses: 1,
		},
		{
			name: "rename", inject: func(f *writeFaults) { f.renameErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: renameFailed, wantCloses: 1,
		},
		{
			name: "rename and remove", inject: func(f *writeFaults) { f.renameErr, f.removeErr = primary, cleanup },
			wantErr: primary, wantCleanup: cleanup, wantCalls: renameFailed, wantCloses: 1,
		},
		{
			name: "directory sync after commit", inject: func(f *writeFaults) { f.dirErr = primary },
			wantErr: primary, wantCleanup: nil, wantCalls: committed, wantCloses: 1,
		},
	}
}

func TestAtomicWriteFailures(t *testing.T) {
	for _, tt := range atomicWriteCases() {
		t.Run(tt.name, func(t *testing.T) {
			var faults writeFaults
			if tt.inject != nil {
				tt.inject(&faults)
			}
			calls, err := faults.run(t)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("write error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantCleanup != nil && !errors.Is(err, tt.wantCleanup) {
				t.Errorf("write error = %v, missing cleanup cause %v", err, tt.wantCleanup)
			}
			if calls != tt.wantCalls {
				t.Errorf("operation trace = %q, want %q", calls, tt.wantCalls)
			}
			if faults.file.closes != tt.wantCloses {
				t.Errorf("Close called %d times, want %d", faults.file.closes, tt.wantCloses)
			}
		})
	}
}
