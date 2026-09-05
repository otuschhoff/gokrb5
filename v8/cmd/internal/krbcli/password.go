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
			return "", err
		}
		reader, ok := stdin.(*bufio.Reader)
		if !ok {
			reader = bufio.NewReader(stdin)
		}
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	tty, err := openControllingTerminal()
	if err == nil {
		defer tty.close()
		state, err := term.MakeRaw(int(tty.input.Fd()))
		if err != nil {
			return "", err
		}
		defer term.Restore(int(tty.input.Fd()), state)
		if _, err := fmt.Fprint(tty.output, prompt); err != nil {
			return "", err
		}
		password, err := term.ReadPassword(int(tty.input.Fd()))
		fmt.Fprintln(tty.output)
		if err != nil {
			return "", err
		}
		return string(password), nil
	}
	return "", errors.New("Cannot read password")
}
