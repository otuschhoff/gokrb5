//go:build windows
// +build windows

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
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		input.Close()
		return nil, err
	}
	return &controllingTerminal{
		input:  input,
		output: output,
		close: func() error {
			outputErr := output.Close()
			inputErr := input.Close()
			if outputErr != nil {
				return outputErr
			}
			return inputErr
		},
	}, nil
}
