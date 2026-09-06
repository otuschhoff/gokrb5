package crypto

import (
	"bytes"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

func TestRFC8009ETypeContracts(t *testing.T) {
	tests := []struct {
		name       string
		etype      etype.EType
		etypeID    int32
		checksumID int32
		keyBytes   int
		hmacBits   int
	}{
		{name: "AES128 SHA256", etype: Aes128CtsHmacSha256128{}, etypeID: etypeID.AES128_CTS_HMAC_SHA256_128, checksumID: chksumtype.HMAC_SHA256_128_AES128, keyBytes: 16, hmacBits: 128},
		{name: "AES256 SHA384", etype: Aes256CtsHmacSha384192{}, etypeID: etypeID.AES256_CTS_HMAC_SHA384_192, checksumID: chksumtype.HMAC_SHA384_192_AES256, keyBytes: 32, hmacBits: 192},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.etype.GetETypeID() != test.etypeID || test.etype.GetHashID() != test.checksumID {
				t.Fatalf("IDs = %d/%d", test.etype.GetETypeID(), test.etype.GetHashID())
			}
			if test.etype.GetKeyByteSize() != test.keyBytes || test.etype.GetKeySeedBitLength() != test.keyBytes*8 {
				t.Fatalf("key sizes = %d/%d", test.etype.GetKeyByteSize(), test.etype.GetKeySeedBitLength())
			}
			if test.etype.GetMessageBlockByteSize() != 1 || test.etype.GetConfounderByteSize() != 16 || test.etype.GetCypherBlockBitLength() != 128 {
				t.Fatalf("block sizes = %d/%d/%d", test.etype.GetMessageBlockByteSize(), test.etype.GetConfounderByteSize(), test.etype.GetCypherBlockBitLength())
			}
			if test.etype.GetHMACBitLength() != test.hmacBits || test.etype.GetDefaultStringToKeyParams() != "00008000" {
				t.Fatalf("HMAC/S2K = %d/%q", test.etype.GetHMACBitLength(), test.etype.GetDefaultStringToKeyParams())
			}
			if test.etype.GetHashFunc() == nil || test.etype.GetHashFunc()().Size()*8 < test.hmacBits {
				t.Fatal("invalid hash function")
			}

			random := bytes.Repeat([]byte{0x5a}, test.keyBytes)
			key := test.etype.RandomToKey(random)
			if !bytes.Equal(key, random) {
				t.Fatalf("random-to-key = %x", key)
			}

			message := []byte("RFC 8009 checksum contract")
			checksum, err := test.etype.GetChecksumHash(random, message, 42)
			if err != nil {
				t.Fatal(err)
			}
			if !test.etype.VerifyChecksum(random, message, checksum, 42) {
				t.Fatal("valid checksum rejected")
			}
			checksum[0] ^= 0xff
			if test.etype.VerifyChecksum(random, message, checksum, 42) {
				t.Fatal("tampered checksum accepted")
			}
			if test.etype.VerifyChecksum(random[:1], message, checksum, 42) {
				t.Fatal("checksum with invalid key accepted")
			}
			derived, err := test.etype.DeriveRandom(random, []byte("usage"))
			if err != nil {
				t.Fatal(err)
			}
			again, err := test.etype.DeriveRandom(random, []byte("usage"))
			if err != nil {
				t.Fatal(err)
			}
			if len(derived) != test.etype.GetHashFunc()().Size() || !bytes.Equal(derived, again) {
				t.Fatalf("derived random = %x/%x", derived, again)
			}
		})
	}
}
