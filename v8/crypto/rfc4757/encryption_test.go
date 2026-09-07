package rfc4757_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc4757"
)

func TestEncryptDataRoundTrip(t *testing.T) {
	etype := krbcrypto.RC4HMAC{}
	key := bytes.Repeat([]byte{0x11}, etype.GetKeyByteSize())
	plaintext := []byte("RC4-HMAC deterministic payload")

	ciphertext, err := rfc4757.EncryptData(key, plaintext, etype)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := rfc4757.DecryptData(key, ciphertext, etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
	if _, err := rfc4757.EncryptData([]byte("short"), plaintext, etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("invalid key error = %v", err)
	}
}

func TestEncryptMessageRoundTripAndIntegrity(t *testing.T) {
	etype := krbcrypto.RC4HMAC{}
	key := bytes.Repeat([]byte{0x22}, etype.GetKeyByteSize())
	plaintext := []byte("authenticated RC4-HMAC payload")

	for _, export := range []bool{false, true} {
		ciphertext, err := rfc4757.EncryptMessage(key, plaintext, 9, export, etype)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := rfc4757.DecryptMessage(key, ciphertext, 9, export, etype)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
		}

		tampered := append([]byte(nil), ciphertext...)
		tampered[0] ^= 0xff
		if _, err := rfc4757.DecryptMessage(key, tampered, 9, export, etype); err == nil || !strings.Contains(err.Error(), "integrity checksum incorrect") {
			t.Fatalf("tampered message error = %v", err)
		}
	}
	if _, err := rfc4757.DecryptMessage(key, []byte("short"), 9, false, etype); err == nil || !strings.Contains(err.Error(), "ciphertext is too short") {
		t.Fatalf("short message error = %v", err)
	}
	if rfc4757.VerifyIntegrity(key, nil, []byte("short"), etype) {
		t.Fatal("short message passed integrity verification")
	}
}

func TestChecksumAndUsageMapping(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16)
	checksum, err := rfc4757.Checksum(key, 23, []byte("checksum payload"))
	if err != nil {
		t.Fatal(err)
	}
	if len(checksum) != 16 {
		t.Fatalf("checksum length = %d", len(checksum))
	}
	if got := hex.EncodeToString(rfc4757.HMAC(key, []byte("data"))); got != "338a4e2337ca09a43473ef581e7270bd" {
		t.Fatalf("HMAC = %s", got)
	}

	tests := []struct {
		usage uint32
		want  []byte
	}{
		{usage: 3, want: []byte{8, 0, 0, 0}},
		{usage: 9, want: []byte{8, 0, 0, 0}},
		{usage: 23, want: []byte{13, 0, 0, 0}},
		{usage: 42, want: []byte{42, 0, 0, 0}},
	}
	for _, test := range tests {
		if got := rfc4757.UsageToMSMsgType(test.usage); !bytes.Equal(got, test.want) {
			t.Fatalf("UsageToMSMsgType(%d) = %v, want %v", test.usage, got, test.want)
		}
	}
}
