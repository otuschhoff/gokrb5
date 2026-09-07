package rfc3961_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3961"
)

func TestDES3EncryptionRoundTrips(t *testing.T) {
	etype := krbcrypto.Des3CbcSha1Kd{}
	key, _ := hex.DecodeString("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92")
	plaintext := []byte("12345678")

	iv, ciphertext, err := rfc3961.DES3EncryptData(key, plaintext, etype)
	if err != nil {
		t.Fatal(err)
	}
	if len(iv) != etype.GetMessageBlockByteSize() {
		t.Fatalf("IV length = %d", len(iv))
	}
	decrypted, err := rfc3961.DES3DecryptData(key, ciphertext, etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptData = %x, want %x", decrypted, plaintext)
	}

	_, message, err := rfc3961.DES3EncryptMessage(key, plaintext, 2, etype)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = rfc3961.DES3DecryptMessage(key, message, 2, etype)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptMessage = %x, want %x", decrypted, plaintext)
	}
	tampered := append([]byte(nil), message...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := rfc3961.DES3DecryptMessage(key, tampered, 2, etype); err == nil || !strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("tampered message error = %v", err)
	}
}

func TestDES3EncryptionRejectsMalformedInputs(t *testing.T) {
	etype := krbcrypto.Des3CbcSha1Kd{}
	key := bytes.Repeat([]byte{0x11}, etype.GetKeyByteSize())

	if _, _, err := rfc3961.DES3EncryptData([]byte("short"), []byte("12345678"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("EncryptData error = %v", err)
	}
	if _, err := rfc3961.DES3DecryptData([]byte("short"), []byte("12345678"), etype); err == nil || !strings.Contains(err.Error(), "incorrect keysize") {
		t.Fatalf("DecryptData key error = %v", err)
	}
	if _, err := rfc3961.DES3DecryptData(key, []byte("short"), etype); err == nil || !strings.Contains(err.Error(), "multiple of the block size") {
		t.Fatalf("DecryptData block error = %v", err)
	}
	if _, err := rfc3961.DES3DecryptMessage(key, []byte("short"), 2, etype); err == nil || !strings.Contains(err.Error(), "ciphertext is too short") {
		t.Fatalf("DecryptMessage error = %v", err)
	}
	if rfc3961.VerifyIntegrity(key, []byte("short"), nil, 2, etype) {
		t.Fatal("short ciphertext passed integrity verification")
	}
}

func TestKeyDerivationHelpers(t *testing.T) {
	etype := krbcrypto.Des3CbcSha1Kd{}
	key, _ := hex.DecodeString("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92")
	usage, _ := hex.DecodeString("0000000155")

	random, err := rfc3961.DeriveRandom(key, usage, etype)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(random); got != "935079d14490a75c3093c4a6e8c3b049c71e6ee705" {
		t.Fatalf("DeriveRandom = %s", got)
	}
	derived, err := rfc3961.DeriveKey(key, usage, etype)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(derived); got != "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd" {
		t.Fatalf("DeriveKey = %s", got)
	}
	if got := rfc3961.RandomToKey(usage); !bytes.Equal(got, usage) {
		t.Fatalf("RandomToKey = %x", got)
	}
	if got := rfc3961.DES3RandomToKey(random); len(got) != etype.GetKeyByteSize() {
		t.Fatalf("DES3RandomToKey length = %d", len(got))
	}
	stringKey, err := rfc3961.DES3StringToKey("password", "ATHENA.MIT.EDUraeburn", etype)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(stringKey); got != "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e" {
		t.Fatalf("DES3StringToKey = %s", got)
	}
	prf, err := rfc3961.PseudoRandom(key, []byte("input"), etype)
	if err != nil {
		t.Fatal(err)
	}
	if len(prf) != etype.GetMessageBlockByteSize() {
		t.Fatalf("PseudoRandom length = %d", len(prf))
	}
}
