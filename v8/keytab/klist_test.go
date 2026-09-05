package keytab

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestKlistMatchesCapturedOutput(t *testing.T) {
	tests := []struct {
		name     string
		keytab   string
		expected string
	}{
		{"keytab_all_etypes", testdata.KEYTAB_KTUTIL_ALL_ETYPES, testdata.KLIST_KTE_ALL_ETYPES},
		{"keytab_kvno_300", testdata.KEYTAB_KTUTIL_KVNO_300, testdata.KLIST_KTE_KVNO_300},
		{"keytab_multi_kvno_unordered", testdata.KEYTAB_KTUTIL_MULTI_KVNO_UNORDERED, testdata.KLIST_KTE_MULTI_KVNO_UNORDERED},
		{"keytab_multi_principal", testdata.KEYTAB_KTUTIL_MULTI_PRINCIPAL, testdata.KLIST_KTE_MULTI_PRINCIPAL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := hex.DecodeString(test.keytab)
			if err != nil {
				t.Fatal(err)
			}
			kt := New()
			if err := kt.Unmarshal(data); err != nil {
				t.Fatal(err)
			}
			for i := range kt.Entries {
				kt.Entries[i].Timestamp = kt.Entries[i].Timestamp.UTC()
			}
			kt.name = test.name
			assert.Equal(t, test.expected, kt.Klist(true, false, true))
		})
	}
}

func TestKlistOptionalColumns(t *testing.T) {
	kt := New()
	kt.name = "test.keytab"
	kt.Entries = []Entry{testEntry(1)}
	withoutOptions := kt.Klist(false, false, false)
	assert.Contains(t, withoutOptions, "KVNO Principal\n")
	assert.NotContains(t, withoutOptions, "Timestamp")
	assert.NotContains(t, withoutOptions, "(aes128")
	assert.NotContains(t, withoutOptions, "(0x")

	withOptions := kt.Klist(true, true, true)
	assert.Contains(t, withOptions, "(aes128-cts-hmac-sha1-96)")
	assert.Contains(t, withOptions, "(aes128-cts-hmac-sha1-96)  (0x"+strings.Repeat("01", 16)+")\n")
	assert.NotContains(t, withOptions, ") \n")
}
