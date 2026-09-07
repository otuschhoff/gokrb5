package crypto

import (
	"bytes"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

func TestRC4HMACContractAndRoundTrip(t *testing.T) {
	etype := RC4HMAC{}
	if etype.GetETypeID() != etypeID.RC4_HMAC || etype.GetHashID() != chksumtype.KERB_CHECKSUM_HMAC_MD5 {
		t.Fatalf("IDs = %d/%d", etype.GetETypeID(), etype.GetHashID())
	}
	if etype.GetKeyByteSize() != 16 || etype.GetKeySeedBitLength() != 128 || etype.GetHMACBitLength() != 128 ||
		etype.GetMessageBlockByteSize() != 1 || etype.GetConfounderByteSize() != 8 || etype.GetCypherBlockBitLength() != 8 {
		t.Fatal("unexpected RC4-HMAC size contract")
	}
	if etype.GetDefaultStringToKeyParams() != "" || etype.GetHashFunc() == nil {
		t.Fatal("unexpected RC4-HMAC defaults")
	}
	key, err := etype.StringToKey("password", "ignored", "ignored")
	if err != nil || len(key) != etype.GetKeyByteSize() {
		t.Fatalf("StringToKey = %x, %v", key, err)
	}
	if randomKey := etype.RandomToKey([]byte("random material")); len(randomKey) != 16 {
		t.Fatalf("RandomToKey length = %d", len(randomKey))
	}

	plaintext := []byte("RC4 wrapper payload")
	_, ciphertext, err := etype.EncryptData(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := etype.DecryptData(key, ciphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data round trip = %q, %v", decrypted, err)
	}
	_, message, err := etype.EncryptMessage(key, plaintext, 8)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = etype.DecryptMessage(key, message, 8)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("message round trip = %q, %v", decrypted, err)
	}
	derived, err := etype.DeriveKey(key, []byte("usage"))
	if err != nil || len(derived) != 16 {
		t.Fatalf("DeriveKey = %x, %v", derived, err)
	}
	derivedRandom, err := etype.DeriveRandom(key, []byte("usage"))
	if err != nil || len(derivedRandom) != etype.GetKeySeedBitLength()/8 {
		t.Fatalf("DeriveRandom = %x, %v", derivedRandom, err)
	}
	checksum, err := etype.GetChecksumHash(key, plaintext, 8)
	if err != nil || !etype.VerifyChecksum(key, plaintext, checksum, 8) {
		t.Fatalf("checksum = %x, %v", checksum, err)
	}
	checksum[0] ^= 0xff
	if etype.VerifyChecksum(key, plaintext, checksum, 8) || etype.VerifyIntegrity(key, message, nil, 9) {
		t.Fatal("tampered checksum or wrong-usage integrity accepted")
	}
}
