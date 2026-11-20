package crypto

import (
	"bytes"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

type rfc8009Contract struct {
	name       string
	etype      etype.EType
	etypeID    int32
	checksumID int32
	keyBytes   int
	hmacBits   int
}

func TestRFC8009ETypeContracts(t *testing.T) {
	tests := []rfc8009Contract{
		{
			name: "AES128 SHA256", etype: Aes128CtsHmacSha256128{},
			etypeID: etypeID.AES128_CTS_HMAC_SHA256_128, checksumID: chksumtype.HMAC_SHA256_128_AES128,
			keyBytes: 16, hmacBits: 128,
		},
		{
			name: "AES256 SHA384", etype: Aes256CtsHmacSha384192{},
			etypeID: etypeID.AES256_CTS_HMAC_SHA384_192, checksumID: chksumtype.HMAC_SHA384_192_AES256,
			keyBytes: 32, hmacBits: 192,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkRFC8009Sizes(t, test)
			checkRFC8009Hash(t, test)
			random := bytes.Repeat([]byte{0x5a}, test.keyBytes)
			key := test.etype.RandomToKey(random)
			if !bytes.Equal(key, random) {
				t.Fatalf("random-to-key = %x", key)
			}
			checkRFC8009Checksum(t, test.etype, random)
			checkRFC8009DeriveRandom(t, test.etype, random)
		})
	}
}

func checkRFC8009Sizes(t *testing.T, test rfc8009Contract) {
	t.Helper()
	enctype := test.etype
	if enctype.GetETypeID() != test.etypeID || enctype.GetHashID() != test.checksumID {
		t.Fatalf("IDs = %d/%d", enctype.GetETypeID(), enctype.GetHashID())
	}
	if enctype.GetKeyByteSize() != test.keyBytes || enctype.GetKeySeedBitLength() != test.keyBytes*8 {
		t.Fatalf("key sizes = %d/%d", enctype.GetKeyByteSize(), enctype.GetKeySeedBitLength())
	}
	if enctype.GetMessageBlockByteSize() != 1 || enctype.GetConfounderByteSize() != 16 ||
		enctype.GetCypherBlockBitLength() != 128 {
		t.Fatalf("block sizes = %d/%d/%d",
			enctype.GetMessageBlockByteSize(), enctype.GetConfounderByteSize(), enctype.GetCypherBlockBitLength(),
		)
	}
}

func checkRFC8009Hash(t *testing.T, test rfc8009Contract) {
	t.Helper()
	if test.etype.GetHMACBitLength() != test.hmacBits || test.etype.GetDefaultStringToKeyParams() != "00008000" {
		t.Fatalf("HMAC/S2K = %d/%q", test.etype.GetHMACBitLength(), test.etype.GetDefaultStringToKeyParams())
	}
	if test.etype.GetHashFunc() == nil || test.etype.GetHashFunc()().Size()*8 < test.hmacBits {
		t.Fatal("invalid hash function")
	}
}

func checkRFC8009Checksum(t *testing.T, enctype etype.EType, random []byte) {
	t.Helper()
	message := []byte("RFC 8009 checksum contract")
	checksum, err := enctype.GetChecksumHash(random, message, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !enctype.VerifyChecksum(random, message, checksum, 42) {
		t.Fatal("valid checksum rejected")
	}
	checksum[0] ^= 0xff
	if enctype.VerifyChecksum(random, message, checksum, 42) {
		t.Fatal("tampered checksum accepted")
	}
	if enctype.VerifyChecksum(random[:1], message, checksum, 42) {
		t.Fatal("checksum with invalid key accepted")
	}
}

func checkRFC8009DeriveRandom(t *testing.T, enctype etype.EType, random []byte) {
	t.Helper()
	derived, err := enctype.DeriveRandom(random, []byte("usage"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := enctype.DeriveRandom(random, []byte("usage"))
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != enctype.GetHashFunc()().Size() || !bytes.Equal(derived, again) {
		t.Fatalf("derived random = %x/%x", derived, again)
	}
}
