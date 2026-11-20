package krbcli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadPasswordWithoutControllingTerminal(t *testing.T) {
	const helperEnv = "GOKRB5_NO_TERMINAL_HELPER"
	if os.Getenv(helperEnv) == "1" {
		password, err := ReadPassword("Password: ", strings.NewReader("fixture\n"), io.Discard, false)
		var openErr *os.PathError
		if password != "" || !errors.As(err, &openErr) || openErr.Path != "/dev/tty" || !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("want empty password and controlling terminal open failure, got empty=%t, err=%v", password == "", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// #nosec G204,G702 -- executes the current test binary with a fixed argument.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadPasswordWithoutControllingTerminal$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.SysProcAttr = new(syscall.SysProcAttr)
	cmd.SysProcAttr.Setsid = true
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated password reader: %v\n%s", err, output)
	}
}
