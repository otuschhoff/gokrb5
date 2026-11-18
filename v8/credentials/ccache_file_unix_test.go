//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd illumos linux netbsd openbsd solaris

package credentials

import (
	"testing"
)

// TestSyncCacheDirErrors covers the directory open failure path.
func TestSyncCacheDirErrors(t *testing.T) {
	if err := syncCacheDir("/nonexistent-dir-gokrb5"); err == nil {
		t.Fatal("syncCacheDir accepted a missing directory")
	}
	if err := syncCacheDir(t.TempDir()); err != nil {
		t.Fatalf("syncCacheDir on a temporary directory: %v", err)
	}
}
