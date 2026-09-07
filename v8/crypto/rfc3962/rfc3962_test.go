package rfc3962_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3962"
)

func TestEncryptDataRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		etype etype.EType
		key   []byte
	}{
		{name: "AES128", etype: krbcrypto.Aes128CtsHmacSha96{}, key: bytes.Repeat([]byte{0x11}, 16)},
		{name: "AES256", etype: krbcrypto.Aes256CtsHmacSha96{}, key: bytes.Repeat([]byte{0x22}, 32)},
	}
	plaintext := []byte("a deterministic plaintext spanning several AES blocks")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, ciphertext, err := rfc3962.EncryptData(test.key, plaintext, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(ciphertext, plaintext) {
				t.Fatal("ciphertext equals plaintext")
			}
			decrypted, err := rfc3962.DecryptData(test.key, ciphertext, test.etype)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("decrypted = %x, want %x", decrypted, plaintext)
			}
		})
	}
}

func TestEncryptMessageRoundTripAndIntegrity(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha96{}
	key := bytes.Repeat([]byte{0x33}, etype.GetKeyByteSize())
	plaintext := []byte("authenticated Kerberos payload")

	_, ciphertext, err := rfc3962.EncryptMessage(key, plaintext, 42, etype)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := rfc3962.DecryptMessage(key, ciphertext, 42, etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := rfc3962.DecryptMessage(key, tampered, 42, etype); err == nil || !strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
	if _, err := rfc3962.DecryptMessage(key, ciphertext, 43, etype); err == nil {
		t.Fatal("ciphertext accepted for a different key usage")
	}
}

func TestEncryptionRejectsMalformedInputs(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha96{}
	shortKey := []byte("short")

	if _, _, err := rfc3962.EncryptData(shortKey, []byte("plaintext"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("EncryptData error = %v", err)
	}
	if _, err := rfc3962.DecryptData(shortKey, []byte("ciphertext"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("DecryptData error = %v", err)
	}
	if _, _, err := rfc3962.EncryptMessage(shortKey, []byte("plaintext"), 1, etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("EncryptMessage error = %v", err)
	}
	if _, err := rfc3962.DecryptMessage(bytes.Repeat([]byte{0x44}, 16), []byte("short"), 1, etype); err == nil || !strings.Contains(err.Error(), "ciphertext is too short") {
		t.Fatalf("DecryptMessage error = %v", err)
	}
}

func TestStringToKeyRFC3962Vector(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha96{}
	wantPBKDF2, _ := hex.DecodeString("cdedb5281bb2f801565a1122b2563515")
	wantKey, _ := hex.DecodeString("42263c6e89f4fc28b8df68ee09799f15")

	if got := rfc3962.StringToPBKDF2("password", "ATHENA.MIT.EDUraeburn", 1, etype); !bytes.Equal(got, wantPBKDF2) {
		t.Fatalf("PBKDF2 = %x, want %x", got, wantPBKDF2)
	}
	got, err := rfc3962.StringToKeyIter("password", "ATHENA.MIT.EDUraeburn", 1, etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantKey) {
		t.Fatalf("StringToKeyIter = %x, want %x", got, wantKey)
	}
	got, err = rfc3962.StringToKey("password", "ATHENA.MIT.EDUraeburn", "00000001", etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantKey) {
		t.Fatalf("StringToKey = %x, want %x", got, wantKey)
	}
}

func TestS2KparamsToIterations(t *testing.T) {
	tests := []struct {
		name    string
		params  string
		want    int64
		wantErr string
	}{
		{name: "one", params: "00000001", want: 1},
		{name: "maximum", params: "ffffffff", want: 4294967295},
		{name: "zero", params: "00000000", want: 0},
		{name: "invalid length", params: "0001", want: 4294967296, wantErr: "invalid s2kparams length"},
		{name: "invalid hex", params: "zzzzzzzz", want: 4294967296, wantErr: "cannot decode"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := rfc3962.S2KparamsToItertions(test.params)
			if got != test.want {
				t.Fatalf("iterations = %d, want %d", got, test.want)
			}
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}

	if _, err := rfc3962.StringToKey("password", "salt", "bad", krbcrypto.Aes128CtsHmacSha96{}); err == nil {
		t.Fatal("StringToKey accepted malformed parameters")
	}
}
