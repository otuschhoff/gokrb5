package gssapi

import (
	"encoding/binary"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestSecurityContextBidirectionalProtection(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	initiator, err := NewSecurityContext(key, true, 7, 11, true)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewSecurityContext(key, false, 11, 7, true)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := initiator.Wrap([]byte("secret"), true)
	if err != nil {
		t.Fatal(err)
	}
	message, confidential, err := acceptor.Unwrap(sealed)
	if err != nil || !confidential || string(message) != "secret" {
		t.Fatalf("sealed unwrap = %q, %t, %v", message, confidential, err)
	}
	plain, err := acceptor.Wrap([]byte("visible"), false)
	if err != nil {
		t.Fatal(err)
	}
	message, confidential, err = initiator.Unwrap(plain)
	if err != nil || confidential || string(message) != "visible" {
		t.Fatalf("plain unwrap = %q, %t, %v", message, confidential, err)
	}
	mic, err := initiator.GetMIC([]byte("bound"))
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptor.VerifyMIC([]byte("bound"), mic); err != nil {
		t.Fatal(err)
	}
	if err := acceptor.VerifyMIC([]byte("bound"), mic); err == nil {
		t.Fatal("accepted replayed MIC token")
	}
}

func TestSecurityContextRejectsTamperedWrap(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	token, err := initiator.Wrap([]byte("message"), true)
	if err != nil {
		t.Fatal(err)
	}
	token[len(token)-1] ^= 1
	if _, _, err := acceptor.Unwrap(token); err == nil {
		t.Fatal("accepted tampered confidential wrap token")
	}
}

func TestSecurityContextAcceptsRotatedWrapTokens(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		t.Run(map[bool]string{false: "integrity", true: "confidentiality"}[confidential], func(t *testing.T) {
			key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA384_192, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
			initiator, err := NewSecurityContext(key, true, 0, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			acceptor, err := NewSecurityContext(key, false, 0, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			token, err := initiator.Wrap([]byte("rotated message"), confidential)
			if err != nil {
				t.Fatal(err)
			}
			body := token[HdrLen:]
			rotation := len(body) + 3
			rotated := append(append([]byte(nil), body[len(body)-3:]...), body[:len(body)-3]...)
			copy(body, rotated)
			binary.BigEndian.PutUint16(token[6:8], uint16(rotation))
			message, sealed, err := acceptor.Unwrap(token)
			if err != nil || sealed != confidential || string(message) != "rotated message" {
				t.Fatalf("rotated unwrap = %q, %t, %v", message, sealed, err)
			}
		})
	}
}

func TestSecurityContextIgnoresUnknownWrapFlags(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	token, err := initiator.Wrap([]byte("future flag"), false)
	if err != nil {
		t.Fatal(err)
	}
	token[2] |= 0x80
	checksumLength := int(binary.BigEndian.Uint16(token[4:6]))
	checksumHeader := append([]byte(nil), token[:HdrLen]...)
	for index := 4; index < 8; index++ {
		checksumHeader[index] = 0
	}
	etype, _ := crypto.GetEtype(key.KeyType)
	checksum, err := etype.GetChecksumHash(key.KeyValue, append(append([]byte(nil), token[HdrLen:len(token)-checksumLength]...), checksumHeader...), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	copy(token[len(token)-checksumLength:], checksum)
	message, _, err := acceptor.Unwrap(token)
	if err != nil || string(message) != "future flag" {
		t.Fatalf("unknown flag unwrap = %q, %v", message, err)
	}
}
