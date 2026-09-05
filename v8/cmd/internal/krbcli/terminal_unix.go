//go:build !windows
// +build !windows

package krbcli

import (
	"io"
	"os"
)

type controllingTerminal struct {
	input  *os.File
	output io.Writer
	close  func() error
}

func openControllingTerminal() (*controllingTerminal, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &controllingTerminal{input: tty, output: tty, close: tty.Close}, nil
}
