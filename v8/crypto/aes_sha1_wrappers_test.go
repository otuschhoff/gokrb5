package crypto

import (
	"bytes"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestAESSHA1WrapperContracts(t *testing.T) {
	tests := []struct {
		name     string
		etype    etype.EType
		key      []byte
		etypeID  int32
		hashID   int32
		keyBytes int
	}{
		{"AES128", Aes128CtsHmacSha96{}, bytes.Repeat([]byte{1}, 16), etypeID.AES128_CTS_HMAC_SHA1_96, 15, 16},
		{"AES256", Aes256CtsHmacSha96{}, bytes.Repeat([]byte{2}, 32), etypeID.AES256_CTS_HMAC_SHA1_96, 16, 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.etype.GetETypeID() != test.etypeID || test.etype.GetHashID() != test.hashID ||
				!hasAESSHA1Metadata(test.etype, test.keyBytes) {
				t.Fatalf("unexpected etype metadata for %s", test.name)
			}

			message := []byte("wrapper contract plaintext")
			encrypted := checkAESSHA1RoundTrips(t, test.etype, test.key, message)
			if test.etype.VerifyIntegrity(test.key, encrypted, message, 42) {
				t.Fatal("invalid integrity input was accepted")
			}
			checksum, err := test.etype.GetChecksumHash(test.key, message, 42)
			if err != nil || !test.etype.VerifyChecksum(test.key, message, checksum, 42) ||
				test.etype.VerifyChecksum(test.key, []byte("changed"), checksum, 42) {
				t.Fatalf("checksum contract failed: %v", err)
			}
			if got := test.etype.RandomToKey(test.key); !bytes.Equal(got, test.key) {
				t.Fatalf("random-to-key = %x", got)
			}
		})
	}
}

func hasAESSHA1Metadata(enctype etype.EType, keyBytes int) bool {
	return enctype.GetKeyByteSize() == keyBytes && enctype.GetKeySeedBitLength() == keyBytes*8 &&
		enctype.GetMessageBlockByteSize() == 1 && enctype.GetConfounderByteSize() == 16 &&
		enctype.GetHMACBitLength() == 96 && enctype.GetCypherBlockBitLength() == 128 &&
		enctype.GetDefaultStringToKeyParams() == "00001000" && enctype.GetHashFunc() != nil
}

func checkAESSHA1RoundTrips(t *testing.T, enctype etype.EType, key, message []byte) []byte {
	t.Helper()
	_, encrypted, err := enctype.EncryptMessage(key, message, 42)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := enctype.DecryptMessage(key, encrypted, 42)
	if err != nil || !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted = %q, %v", decrypted, err)
	}
	_, ciphertext, err := enctype.EncryptData(key, message)
	if err != nil {
		t.Fatal(err)
	}
	if got, ierr := enctype.DecryptData(key, ciphertext); ierr != nil || !bytes.Equal(got, message) {
		t.Fatalf("raw decrypted = %x, %v", got, ierr)
	}
	return encrypted
}

func TestEncryptedDataRoundTripAndErrors(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{3}, 16)}
	message := []byte("encrypted data wrapper")
	ed, err := GetEncryptedData(message, key, 7, 4)
	if err != nil || ed.EType != key.KeyType || ed.KVNO != 4 {
		t.Fatalf("encrypted data = %+v, %v", ed, err)
	}
	decrypted, err := DecryptEncPart(ed, key, 7)
	if err != nil || !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted = %q, %v", decrypted, err)
	}
	if _, err := GetEncryptedData(message, types.EncryptionKey{KeyType: -1, KeyValue: nil}, 7, 0); err == nil {
		t.Fatal("unknown encryption type was accepted")
	}
	if _, err := DecryptMessage(ed.Cipher, types.EncryptionKey{KeyType: -1, KeyValue: nil}, 7); err == nil {
		t.Fatal("unknown decryption type was accepted")
	}
	ed.Cipher[0] ^= 0xff
	if _, err := DecryptEncPart(ed, key, 7); err == nil {
		t.Fatal("tampered encrypted data was accepted")
	}
}
