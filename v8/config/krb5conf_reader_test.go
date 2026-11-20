package config

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingConfigReader struct{ err error }

type configReadCloser struct {
	io.Reader
	isClosed bool
}

func (r *configReadCloser) Close() error {
	r.isClosed = true
	return nil
}

func (reader failingConfigReader) Read([]byte) (int, error) { return 0, reader.err }

func TestNewFromReaderLeavesInputOpen(t *testing.T) {
	t.Parallel()

	const input = "[libdefaults]\ndefault_realm = EXAMPLE.COM\n"
	r := &configReadCloser{Reader: strings.NewReader(input), isClosed: false}

	cfg, err := NewFromReader(r)
	assert.False(t, r.isClosed, "NewFromReader closed its input")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "EXAMPLE.COM", cfg.LibDefaults.DefaultRealm)
}

func TestNewFromReaderReturnsReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("configuration read failed")
	r := &configReadCloser{Reader: failingConfigReader{err: readErr}, isClosed: false}

	cfg, err := NewFromReader(r)
	assert.False(t, r.isClosed, "NewFromReader closed its input")
	assert.ErrorIs(t, err, readErr)
	assert.Nil(t, cfg)
}

func TestNewFromScannerReturnsLateReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("configuration stream interrupted")
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "valid section",
			input: "[libdefaults]\ndefault_realm = EXAMPLE.COM\n",
		},
		{
			name:  "invalid section",
			input: "[domain_realm]\nmissing assignment\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := io.MultiReader(strings.NewReader(tt.input), failingConfigReader{err: readErr})
			cfg, err := NewFromScanner(bufio.NewScanner(r))

			assert.ErrorIs(t, err, readErr)
			assert.Nil(t, cfg)
		})
	}
}

func TestNewFromScannerUsesConfiguredBuffer(t *testing.T) {
	t.Parallel()

	const (
		header = "[libdefaults]\n"
		realm  = "EXAMPLE.COM"
		input  = header + "default_realm = " + realm + "\n"
	)

	t.Run("line exceeds configured limit", func(t *testing.T) {
		t.Parallel()

		scanner := bufio.NewScanner(strings.NewReader(input))
		scanner.Buffer(nil, len(header))

		cfg, err := NewFromScanner(scanner)
		assert.ErrorIs(t, err, bufio.ErrTooLong)
		assert.Nil(t, cfg)
	})

	t.Run("line fits configured limit", func(t *testing.T) {
		t.Parallel()

		scanner := bufio.NewScanner(strings.NewReader(input))
		scanner.Buffer(nil, len(input))

		cfg, err := NewFromScanner(scanner)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, realm, cfg.LibDefaults.DefaultRealm)
	})
}
