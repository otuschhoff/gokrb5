//go:build !interop
// +build !interop

package client

import "time"

func clientNow() time.Time {
	return time.Now()
}
