package keytab

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// TestParsePrincipalExactErrors pins the exact error text of every reachable
// rejection branch in ParsePrincipal.
func TestParsePrincipalExactErrors(t *testing.T) {
	for input, expected := range map[string]string{
		`a@b@c@d`:            "principal contains too many realm separators",
		"":                   "principal contains an empty component",
		"/host@REALM":        "principal contains an empty component",
		"a//b@REALM":         "principal contains an empty component",
		"user@":              "principal contains an empty realm",
		`user\`:              "principal ends with an incomplete escape",
		"user@REALM/EXTRA":   "realm contains an unescaped component separator",
		"user@ONE@TWO@THREE": "principal contains too many realm separators",
	} {
		t.Run("reject "+input, func(t *testing.T) {
			_, err := ParsePrincipal(input)
			require.EqualError(t, err, expected)
		})
	}
}

// TestParsePrincipalBranches pins successful parse branches: realm-less names,
// escaped separators, literal slashes in enterprise names, and escape
// sequences.
func TestParsePrincipalBranches(t *testing.T) {
	t.Run("realm-less name", func(t *testing.T) {
		p, err := ParsePrincipal("single")
		require.NoError(t, err)
		assert.Equal(t, Principal{Components: []string{"single"}, NameType: nametype.KRB_NT_PRINCIPAL}, p)
	})
	t.Run("escaped backslash", func(t *testing.T) {
		p, err := ParsePrincipal(`a\\b@REALM`)
		require.NoError(t, err)
		assert.Equal(t, []string{`a\b`}, p.Components)
		assert.Equal(t, "REALM", p.Realm)
	})
	t.Run("enterprise literal slash", func(t *testing.T) {
		p, err := ParsePrincipal("user/dept@corp.example@EXAMPLE.ORG")
		require.NoError(t, err)
		assert.Equal(t, Principal{
			Realm:      "EXAMPLE.ORG",
			Components: []string{"user/dept@corp.example"},
			NameType:   nametype.KRB_NT_ENTERPRISE,
		}, p)
	})
	t.Run("escaped separator is not enterprise", func(t *testing.T) {
		// An escaped '@' does not count as a realm separator, so a single
		// unescaped '@' keeps the name a plain principal.
		p, err := ParsePrincipal(`user\@corp@REALM`)
		require.NoError(t, err)
		assert.Equal(t, []string{"user@corp"}, p.Components)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, p.NameType)
	})
	t.Run("enterprise with escaped slash", func(t *testing.T) {
		p, err := ParsePrincipal(`u\/ser@corp.example@EXAMPLE.ORG`)
		require.NoError(t, err)
		assert.Equal(t, Principal{
			Realm:      "EXAMPLE.ORG",
			Components: []string{"u/ser@corp.example"},
			NameType:   nametype.KRB_NT_ENTERPRISE,
		}, p)
	})
	t.Run("all escape sequences", func(t *testing.T) {
		p, err := ParsePrincipal(`a\nb\tc\bd\0e\@f\/g\\h@R`)
		require.NoError(t, err)
		assert.Equal(t, []string{"a\nb\tc\bd\x00e@f/g\\h"}, p.Components)
		assert.Equal(t, "R", p.Realm)
	})
	t.Run("escaped slash in realm", func(t *testing.T) {
		p, err := ParsePrincipal(`user@REALM\/X`)
		require.NoError(t, err)
		assert.Equal(t, "REALM/X", p.Realm)
	})
}

// TestGetEntryTieBreaks pins the newest-timestamp tie-break rules for exact
// KVNO matches and the 8-bit KVNO fallback.
func TestGetEntryTieBreaks(t *testing.T) {
	p := Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}}
	mk := func(kvno uint32, ts int64, key byte) Entry {
		return Entry{
			Principal: p,
			Timestamp: time.Unix(ts, 0),
			KVNO:      kvno,
			Key:       types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte{key}},
		}
	}

	t.Run("exact kvno prefers newest timestamp", func(t *testing.T) {
		kt := New()
		kt.Entries = []Entry{mk(7, 200, 2), mk(7, 100, 1), mk(7, 300, 3)}
		entry, err := kt.GetEntry(p, 7, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte{3}, entry.Key.KeyValue)
	})
	t.Run("fallback prefers newest timestamp", func(t *testing.T) {
		kt := New()
		kt.Entries = []Entry{mk(44, 200, 2), mk(44, 400, 4), mk(44, 300, 3)}
		entry, err := kt.GetEntry(p, 300, 0)
		require.NoError(t, err)
		assert.Equal(t, uint32(44), entry.KVNO)
		assert.Equal(t, []byte{4}, entry.Key.KeyValue, "newest low-byte fallback entry wins")
	})
	t.Run("exact beats newer fallback", func(t *testing.T) {
		kt := New()
		kt.Entries = []Entry{mk(44, 900, 9), mk(300, 100, 1)}
		entry, err := kt.GetEntry(p, 300, 0)
		require.NoError(t, err)
		assert.Equal(t, uint32(300), entry.KVNO)
	})
}

// TestAppendToFileNoEntries pins the no-op and header-initialization behavior
// when appending zero entries.
func TestAppendToFileNoEntries(t *testing.T) {
	t.Run("empty file gets header", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.kt")
		require.NoError(t, AppendToFile(path))
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, []byte{keytabFirstByte, 2}, b)
	})
	t.Run("existing file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "existing.kt")
		kt := New()
		require.NoError(t, kt.AddEntry("user", "EXAMPLE.ORG", "password", time.Unix(1700000000, 0), 1, etypeID.AES128_CTS_HMAC_SHA1_96))
		require.NoError(t, kt.WriteFile(path))
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, AppendToFile(path))
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})
}
