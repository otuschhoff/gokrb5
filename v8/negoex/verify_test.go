package negoex

import (
	"errors"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestMakeChecksumPreservesCryptoErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, prefix, cause string
		key                 types.EncryptionKey
	}{
		{
			name:   "unknown enctype",
			prefix: "select NEGOEX VERIFY enctype:",
			cause:  "unsupported EType",
			key:    types.EncryptionKey{KeyType: 999, KeyValue: nil},
		},
		{
			name:   "short key",
			prefix: "compute NEGOEX VERIFY checksum:",
			cause:  "incorrect keysize",
			key:    types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte{1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checksum, err := MakeChecksum(tt.key, keyusage.NEGOEX_INITIATOR_CHECKSUM, []byte("transcript"))
			if err == nil {
				t.Fatal("expected a checksum error")
			}
			cause := errors.Unwrap(err)
			if cause == nil || !strings.HasPrefix(err.Error(), tt.prefix) || !strings.Contains(cause.Error(), tt.cause) {
				t.Fatalf("want contextual checksum error %q, got %v", tt.prefix, err)
			}
			if checksum.Value != nil {
				t.Fatal("failed computation returned a checksum")
			}
		})
	}
}

func TestVerifyChecksumPreservesCryptoErrors(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	transcript := []byte("transcript")
	const usage = keyusage.NEGOEX_INITIATOR_CHECKSUM
	checksum, err := MakeChecksum(key, usage, transcript)
	if err != nil {
		t.Fatal(err)
	}
	key.KeyValue = []byte{1}
	err = VerifyChecksum(key, usage, transcript, checksum)
	if err == nil {
		t.Fatal("expected a checksum verification error")
	}
	cause := errors.Unwrap(err)
	if cause == nil || !strings.HasPrefix(err.Error(), "recompute NEGOEX VERIFY checksum:") {
		t.Fatalf("want contextual checksum recomputation error, got %v", err)
	}
	if !strings.Contains(cause.Error(), "incorrect keysize") || errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("checksum computation error was lost or misclassified: %v", err)
	}
}
