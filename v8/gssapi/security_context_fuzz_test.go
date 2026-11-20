package gssapi

import (
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func FuzzSecurityContextUnwrap(f *testing.F) {
	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA384_192,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	for _, confidential := range []bool{false, true} {
		initiator := mustSecurityContext(f, key, true, 0, 0, true)
		token, err := initiator.Wrap([]byte("seed message"), confidential)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token []byte) {
		acceptor, err := NewSecurityContext(key, false, 0, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		message, confidential, err := acceptor.Unwrap(token)
		if err != nil && (message != nil || confidential || acceptor.receiveSequence != 0) {
			t.Fatal("unwrap failure released plaintext or advanced the receive sequence")
		}
	})
}

func FuzzSecurityContextVerifyMIC(f *testing.F) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator := mustSecurityContext(f, key, true, 0, 0, true)
	token, err := initiator.GetMIC([]byte("seed message"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token, []byte("seed message"))
	f.Fuzz(func(t *testing.T, token, message []byte) {
		acceptor, err := NewSecurityContext(key, false, 0, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		if verifyErr := acceptor.VerifyMIC(message, token); verifyErr != nil && acceptor.receiveSequence != 0 {
			t.Fatal("MIC verification failure advanced the receive sequence")
		}
	})
}
