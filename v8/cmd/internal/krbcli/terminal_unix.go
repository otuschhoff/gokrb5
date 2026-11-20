//go:build !windows

package krbcli

import (
	"fmt"
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
		return nil, fmt.Errorf("open controlling terminal: %w", err)
	}
	return &controllingTerminal{
		input:  tty,
		output: tty,
		close: func() error {
			if err := tty.Close(); err != nil {
				return fmt.Errorf("close controlling terminal: %w", err)
			}
			return nil
		},
	}, nil
}
