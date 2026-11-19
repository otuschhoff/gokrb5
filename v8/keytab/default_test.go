package keytab

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
)

func TestResolveNameTypeBoundary(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		input    string
		path     string
		writable bool
		wantErr  string
	}{
		{
			name:     "colon after first component",
			input:    "keys/client:archive.keytab",
			path:     "keys/client:archive.keytab",
			writable: false,
			wantErr:  "",
		},
		{
			name:     "explicit file path with colon",
			input:    "FILE:keys:archive/client.keytab",
			path:     "keys:archive/client.keytab",
			writable: false,
			wantErr:  "",
		},
		{
			name:     "explicit writable path with colon",
			input:    "WRFILE:keys:archive/client.keytab",
			path:     "keys:archive/client.keytab",
			writable: true,
			wantErr:  "",
		},
		{
			name:     "unknown type",
			input:    "other:/keys/client.keytab",
			path:     "",
			writable: false,
			wantErr:  `unsupported keytab type in "other:/keys/client.keytab"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path, writable, err := ResolveName(tt.input, nil)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.path, path)
			require.Equal(t, tt.writable, writable)
		})
	}
}

func TestResolveNameConfiguredDefault(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.LibDefaults.DefaultKeytabName = "WRFILE:keys/configured.keytab"
	path, writable, err := ResolveName("", cfg)
	require.NoError(t, err)
	require.Equal(t, "keys/configured.keytab", path)
	require.True(t, writable)

	path, writable, err = ResolveName("keys/explicit.keytab", cfg)
	require.NoError(t, err)
	require.Equal(t, "keys/explicit.keytab", path)
	require.False(t, writable)
}
