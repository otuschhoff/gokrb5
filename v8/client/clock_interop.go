//go:build interop
// +build interop

package client

import (
	"os"
	"time"
)

func clientNow() time.Time {
	offset, _ := time.ParseDuration(os.Getenv("GOKRB5_TEST_TIME_OFFSET"))
	return time.Now().Add(offset)
}
