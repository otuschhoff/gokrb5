package krbcli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfigFromEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte("[libdefaults]\n default_realm = EXAMPLE.ORG\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing")+string(os.PathListSeparator)+path)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "EXAMPLE.ORG", cfg.LibDefaults.DefaultRealm)
}

func TestParseDuration(t *testing.T) {
	for input, expected := range map[string]time.Duration{
		"3600":     time.Hour,
		"2h30m":    2*time.Hour + 30*time.Minute,
		"7d":       7 * 24 * time.Hour,
		"1d2h3m4s": 26*time.Hour + 3*time.Minute + 4*time.Second,
		"12:30:15": 12*time.Hour + 30*time.Minute + 15*time.Second,
	} {
		actual, err := ParseDuration(input)
		if assert.NoError(t, err, input) {
			assert.Equal(t, expected, actual, input)
		}
	}
	for _, value := range []string{"tomorrow", "1x:30", "1:2x", "1h2d", "d", "1:60", "1:02:60", "1000000000d", "999999999999:00", "99999999999999999999"} {
		_, err := ParseDuration(value)
		assert.Error(t, err, value)
	}
}

func TestReadPasswordFromTTYWithoutEcho(t *testing.T) {
	if os.Getenv("GOKRB5_PASSWORD_HELPER") == "1" {
		password, err := ReadPassword("Password: ", os.Stdin, os.Stderr, false)
		if err != nil {
			fmt.Fprintln(os.Stdout, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stdout, "RESULT:%s\n", password)
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		t.Skip("PTY test is Unix-specific")
	}
	command := exec.Command(os.Args[0], "-test.run=TestReadPasswordFromTTYWithoutEcho")
	command.Env = append(os.Environ(), "GOKRB5_PASSWORD_HELPER=1")
	tty, err := pty.Start(command)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	prompt, err := reader.ReadString(' ')
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "Password: ", prompt)
	if _, err := io.WriteString(tty, "secret\n"); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil && !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, string(output), "RESULT:secret")
	assert.Equal(t, 1, strings.Count(string(output), "secret"), "password was echoed by the terminal")
}

func TestResolveExplicitPrincipalUsesDefaultRealm(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.ORG"
	principal, err := ResolvePrincipal("user@corp.example", "", false, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "EXAMPLE.ORG", principal.Realm)
	assert.Equal(t, []string{"user@corp.example"}, principal.Components)
}

func TestReadPasswordFromExplicitStdin(t *testing.T) {
	var stderr bytes.Buffer
	password, err := ReadPassword("Password: ", bytes.NewBufferString("secret\n"), &stderr, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "secret", password)
	assert.Contains(t, stderr.String(), "Password: ")
}

func TestReadPasswordReusesBufferedStdin(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("old\nnew\nnew\n"))
	var stderr bytes.Buffer
	for _, expected := range []string{"old", "new", "new"} {
		password, err := ReadPassword("Password: ", reader, &stderr, true)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, expected, password)
	}
}

func TestErrorTextUsesWrappedKDCCode(t *testing.T) {
	wrapped := krberror.Errorf(messages.KRBError{ErrorCode: errorcode.KDC_ERR_KEY_EXPIRED}, krberror.KDCError, "login failed")
	assert.Equal(t, "Password has expired", ErrorText(wrapped))
	assert.Equal(t, "plain failure", ErrorText(errors.New("plain failure")))
}
