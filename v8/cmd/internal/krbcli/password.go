package krbcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

// ReadPassword reads a password without echo from the controlling terminal.
// Standard input is used only when allowStdin is true.
func ReadPassword(prompt string, stdin io.Reader, stderr io.Writer, allowStdin bool) (string, error) {
	if allowStdin {
		if _, err := fmt.Fprint(stderr, prompt); err != nil {
			return "", fmt.Errorf("write password prompt: %w", err)
		}
		reader, ok := stdin.(*bufio.Reader)
		if !ok {
			reader = bufio.NewReader(stdin)
		}
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	tty, err := openControllingTerminal()
	if err != nil {
		return "", fmt.Errorf("cannot read password: %w", err)
	}
	fd := int(tty.input.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", errors.Join(fmt.Errorf("set password terminal mode: %w", err), tty.close())
	}

	password, readErr := readTerminalPassword(tty.output, prompt, fd)
	restoreErr := term.Restore(fd, state)
	if restoreErr != nil {
		restoreErr = fmt.Errorf("restore password terminal mode: %w", restoreErr)
	}
	if err := errors.Join(readErr, restoreErr, tty.close()); err != nil {
		return "", err
	}
	return string(password), nil
}

func readTerminalPassword(output io.Writer, prompt string, fd int) ([]byte, error) {
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return nil, fmt.Errorf("write password prompt: %w", err)
	}
	password, err := term.ReadPassword(fd)
	if err != nil {
		err = fmt.Errorf("read password from terminal: %w", err)
	}
	if _, newlineErr := fmt.Fprintln(output); newlineErr != nil {
		err = errors.Join(err, fmt.Errorf("write password prompt newline: %w", newlineErr))
	}
	return password, err
}
