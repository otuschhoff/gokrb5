package crypto

import (
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
)

func TestGetChksumEtype(t *testing.T) {
	tests := []struct {
		checksumID int32
		etypeID    int32
	}{
		{chksumtype.HMAC_SHA1_96_AES128, Aes128CtsHmacSha96{}.GetETypeID()},
		{chksumtype.HMAC_SHA1_96_AES256, Aes256CtsHmacSha96{}.GetETypeID()},
		{chksumtype.HMAC_SHA256_128_AES128, Aes128CtsHmacSha256128{}.GetETypeID()},
		{chksumtype.HMAC_SHA384_192_AES256, Aes256CtsHmacSha384192{}.GetETypeID()},
		{chksumtype.HMAC_SHA1_DES3_KD, Des3CbcSha1Kd{}.GetETypeID()},
		{chksumtype.KERB_CHECKSUM_HMAC_MD5, RC4HMAC{}.GetETypeID()},
	}
	for _, test := range tests {
		resolved, err := GetChksumEtype(test.checksumID)
		if err != nil {
			t.Fatalf("checksum %d: %v", test.checksumID, err)
		}
		if resolved.GetETypeID() != test.etypeID {
			t.Fatalf("checksum %d resolved to enctype %d, want %d", test.checksumID, resolved.GetETypeID(), test.etypeID)
		}
	}
	if _, err := GetChksumEtype(-1); err == nil {
		t.Fatal("unknown checksum type was accepted")
	}
}
