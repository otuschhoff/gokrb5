package rfc8009_test

import (
	"bytes"
	"strings"
	"testing"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc8009"
)

func TestEncryptionRoundTrips(t *testing.T) {
	tests := []struct {
		name  string
		etype etype.EType
		key   []byte
	}{
		{name: "AES128-SHA256", etype: krbcrypto.Aes128CtsHmacSha256128{}, key: bytes.Repeat([]byte{0x11}, 16)},
		{name: "AES256-SHA384", etype: krbcrypto.Aes256CtsHmacSha384192{}, key: bytes.Repeat([]byte{0x22}, 32)},
	}
	plaintext := []byte("RFC 8009 authenticated encryption payload")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, encrypted, err := rfc8009.EncryptData(test.key, plaintext, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := rfc8009.DecryptData(test.key, encrypted, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("DecryptData = %x, want %x", decrypted, plaintext)
			}

			_, message, err := rfc8009.EncryptMessage(test.key, plaintext, 42, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err = rfc8009.DecryptMessage(test.key, message, 42, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("DecryptMessage = %q, want %q", decrypted, plaintext)
			}
			if !rfc8009.VerifyIntegrity(test.key, message, 42, test.etype) {
				t.Fatal("valid integrity hash rejected")
			}

			tampered := append([]byte(nil), message...)
			tampered[len(tampered)-1] ^= 0xff
			if _, err := rfc8009.DecryptMessage(test.key, tampered, 42, test.etype); err == nil || !strings.Contains(err.Error(), "integrity verification failed") {
				t.Fatalf("tampered message error = %v", err)
			}
		})
	}
}

func TestEncryptionRejectsMalformedInputs(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha256128{}
	shortKey := []byte("short")

	if _, _, err := rfc8009.EncryptData(shortKey, []byte("plaintext"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("EncryptData error = %v", err)
	}
	if _, err := rfc8009.DecryptData(shortKey, []byte("ciphertext"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("DecryptData error = %v", err)
	}
	if _, _, err := rfc8009.EncryptMessage(shortKey, []byte("plaintext"), 1, etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("EncryptMessage error = %v", err)
	}
	if _, err := rfc8009.DecryptMessage(bytes.Repeat([]byte{0x44}, 16), []byte("short"), 1, etype); err == nil || !strings.Contains(err.Error(), "ciphertext is too short") {
		t.Fatalf("DecryptMessage error = %v", err)
	}
	if rfc8009.VerifyIntegrity(bytes.Repeat([]byte{0x44}, 16), []byte("short"), 1, etype) {
		t.Fatal("short ciphertext passed integrity verification")
	}
}

func TestKeyDerivationHelpers(t *testing.T) {
	aes128 := krbcrypto.Aes128CtsHmacSha256128{}
	aes256 := krbcrypto.Aes256CtsHmacSha384192{}
	key128 := bytes.Repeat([]byte{0x55}, 16)
	key256 := bytes.Repeat([]byte{0x66}, 32)

	if got := rfc8009.RandomToKey(key128); !bytes.Equal(got, key128) {
		t.Fatalf("RandomToKey = %x", got)
	}
	if got := rfc8009.DeriveKey(key128, []byte("kerberos"), aes128); len(got) != 16 {
		t.Fatalf("AES128 derived key length = %d", len(got))
	}
	if got := rfc8009.DeriveKey(key256, []byte("kerberos"), aes256); len(got) != 32 {
		t.Fatalf("AES256 protocol key length = %d", len(got))
	}
	if got := rfc8009.DeriveKey(key256, []byte{0, 0, 0, 1, 0xaa}, aes256); len(got) != 32 {
		t.Fatalf("AES256 encryption key length = %d", len(got))
	}
	if got := rfc8009.DeriveKey(key256, []byte{0, 0, 0, 1, 0x55}, aes256); len(got) != 24 {
		t.Fatalf("AES256 integrity key length = %d", len(got))
	}
	derived, err := rfc8009.DeriveRandom(key128, []byte("usage"), aes128)
	if err != nil || len(derived) != 32 {
		t.Fatalf("DeriveRandom length/error = %d/%v", len(derived), err)
	}
	withContext := rfc8009.KDF_HMAC_SHA2(key128, []byte("label"), []byte("context"), 128, aes128)
	withoutContext := rfc8009.KDF_HMAC_SHA2(key128, []byte("label"), nil, 128, aes128)
	if bytes.Equal(withContext, withoutContext) {
		t.Fatal("KDF context did not affect output")
	}
	if got := rfc8009.GetSaltP("realmuser", "aes128"); got != "aes128\x00realmuser" {
		t.Fatalf("GetSaltP = %q", got)
	}
}

func TestStringToKeyAndParameters(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha256128{}
	pbkdf := rfc8009.StringToPBKDF2("password", "salt", 2, etype)
	if len(pbkdf) != etype.GetKeyByteSize() {
		t.Fatalf("PBKDF2 length = %d", len(pbkdf))
	}
	iterKey, err := rfc8009.StringToKeyIter("password", "salt", 2, etype)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rfc8009.StringToKey("password", "salt", "00000002", etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, iterKey) {
		t.Fatalf("StringToKey = %x, want %x", key, iterKey)
	}

	for _, test := range []struct {
		params string
		want   int
		err    bool
	}{
		{params: "00000000", want: 0},
		{params: "00008000", want: 32768},
		{params: "bad", want: 32768, err: true},
		{params: "zzzzzzzz", want: 32768, err: true},
	} {
		got, err := rfc8009.S2KparamsToItertions(test.params)
		if got != test.want || (err != nil) != test.err {
			t.Fatalf("S2KparamsToItertions(%q) = %d, %v", test.params, got, err)
		}
	}
	if _, err := rfc8009.StringToKey("password", "salt", "bad", etype); err == nil {
		t.Fatal("StringToKey accepted malformed parameters")
	}
}
