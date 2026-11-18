//go:build windows
// +build windows

package krbcli

import (
	"errors"
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
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open console input: %w", err)
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open console output: %w", err), closeConsoleFile(input, "input"))
	}
	return &controllingTerminal{
		input:  input,
		output: output,
		close: func() error {
			return errors.Join(closeConsoleFile(output, "output"), closeConsoleFile(input, "input"))
		},
	}, nil
}

func closeConsoleFile(file *os.File, name string) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close console %s: %w", name, err)
	}
	return nil
}
