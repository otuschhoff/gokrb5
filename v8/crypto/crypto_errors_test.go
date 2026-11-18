package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestEncryptionProfileErrorContext(t *testing.T) {
	t.Parallel()

	profiles := []struct {
		name        string
		profile     etype.EType
		wantNilPair bool
	}{
		{name: "aes128-cts-hmac-sha1-96", profile: Aes128CtsHmacSha96{}, wantNilPair: false},
		{name: "aes256-cts-hmac-sha1-96", profile: Aes256CtsHmacSha96{}, wantNilPair: false},
		{name: "aes128-cts-hmac-sha256-128", profile: Aes128CtsHmacSha256128{}, wantNilPair: false},
		{name: "aes256-cts-hmac-sha384-192", profile: Aes256CtsHmacSha384192{}, wantNilPair: false},
		{name: "des3-cbc-sha1-kd", profile: Des3CbcSha1Kd{}, wantNilPair: true},
		{name: "rc4-hmac", profile: RC4HMAC{}, wantNilPair: false},
	}
	for _, tt := range profiles {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			iv, ciphertext, err := tt.profile.EncryptData([]byte("test-key-marker"), []byte("test-plaintext-marker"))
			if len(iv) != 0 || len(ciphertext) != 0 || (iv == nil) != tt.wantNilPair ||
				(ciphertext == nil) != tt.wantNilPair {
				t.Fatal("encryption failure changed the empty result")
			}
			checkCryptoErrorContext(t, err, tt.name+" encrypt data:", "incorrect keysize")

			plaintext, err := tt.profile.DecryptMessage(nil, nil, 1)
			if plaintext != nil {
				t.Fatal("decryption failure returned plaintext")
			}
			checkCryptoErrorContext(t, err, tt.name+" decrypt message:", "ciphertext is too short")
		})
	}
}

func TestEncryptedDataPreservesEncryptionFailure(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("test-key-marker")}
	ed, err := GetEncryptedData([]byte("test-plaintext-marker"), key, 1, 0)
	if ed.EType != 0 || ed.KVNO != 0 || ed.Cipher != nil {
		t.Fatal("encryption failure returned encrypted data")
	}
	checkCryptoErrorContext(t, err, "encrypt data with enctype ", "aes128-cts-hmac-sha1-96 encrypt message:")
}

func TestStringToKeyPreservesParameterError(t *testing.T) {
	t.Parallel()

	et := Aes128CtsHmacSha96{}
	key, err := et.StringToKey("test-password-marker", "test-salt-marker", "zz")
	if len(key) != 0 {
		t.Fatal("invalid string-to-key parameters returned a key")
	}
	checkCryptoErrorContext(t, err, "aes128-cts-hmac-sha1-96 string-to-key:", "invalid s2kparams length")
}

func TestDeriveRandomPreservesPartialResult(t *testing.T) {
	t.Parallel()

	et := Aes128CtsHmacSha96{}
	result, err := et.DeriveRandom(nil, []byte("kerberos"))
	if !bytes.Equal(result, make([]byte, et.GetKeySeedBitLength()/8)) {
		t.Fatal("derive-random failure changed the returned seed buffer")
	}
	checkCryptoErrorContext(t, err, "aes128-cts-hmac-sha1-96 derive random:", "incorrect keysize")
}

func TestETypeInfo2SaltPresencePreservesSyntaxError(t *testing.T) {
	t.Parallel()

	present, err := etypeInfo2SaltPresence(nil, 0)
	_, isSyntaxError := errors.AsType[asn1.SyntaxError](errors.Unwrap(err))
	if present != nil || !isSyntaxError {
		t.Fatalf("salt detection error = %v; want a wrapped ASN.1 syntax error and no result", err)
	}
	checkCryptoErrorContext(t, err, "decode etype-info2 salt fields:", "sequence truncated")
}

func TestETypeInfo2SaltPresenceRejectsEntryCountMismatch(t *testing.T) {
	t.Parallel()

	present, err := etypeInfo2SaltPresence([]byte{0x30, 0x00}, 1)
	if present != nil || err == nil || err.Error() != "error determining PA-ETYPE-INFO2 salt presence" {
		t.Fatalf("salt detection result = %v, %v; want an entry count mismatch", present, err)
	}
}

func checkCryptoErrorContext(t *testing.T, err error, context, detail string) {
	t.Helper()
	cause := errors.Unwrap(err)
	if err == nil || cause == nil || !strings.HasPrefix(err.Error(), context) || !strings.Contains(cause.Error(), detail) {
		t.Fatalf("error = %v; want context %q and cause containing %q", err, context, detail)
	}
	markers := []string{"test-key-marker", "test-plaintext-marker", "test-password-marker", "test-salt-marker"}
	for _, secret := range markers {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("crypto error exposed input bytes")
		}
	}
}
