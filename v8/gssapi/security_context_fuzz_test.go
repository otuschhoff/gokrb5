package gssapi

import (
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func FuzzSecurityContextUnwrap(f *testing.F) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA384_192, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	for _, confidential := range []bool{false, true} {
		token, _ := initiator.Wrap([]byte("seed message"), confidential)
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token []byte) {
		acceptor, err := NewSecurityContext(key, false, 0, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _ = acceptor.Unwrap(token)
	})
}

func FuzzSecurityContextVerifyMIC(f *testing.F) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	token, _ := initiator.GetMIC([]byte("seed message"))
	f.Add(token, []byte("seed message"))
	f.Fuzz(func(t *testing.T, token, message []byte) {
		acceptor, err := NewSecurityContext(key, false, 0, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		_ = acceptor.VerifyMIC(message, token)
	})
}
