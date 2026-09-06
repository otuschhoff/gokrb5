package crypto

import (
	"strconv"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
)

func TestEnctypesRejectTruncatedCiphertext(t *testing.T) {
	t.Parallel()
	enctypes := []etype.EType{
		Aes128CtsHmacSha96{},
		Aes256CtsHmacSha96{},
		Aes128CtsHmacSha256128{},
		Aes256CtsHmacSha384192{},
		Des3CbcSha1Kd{},
		RC4HMAC{},
	}
	for _, enctype := range enctypes {
		enctype := enctype
		t.Run(enctypeID(enctype), func(t *testing.T) {
			t.Parallel()
			key := make([]byte, enctype.GetKeyByteSize())
			if _, err := enctype.DecryptMessage(key, []byte{1}, 1); err == nil {
				t.Fatal("truncated ciphertext was accepted")
			}
		})
	}
}

func enctypeID(enctype etype.EType) string {
	return strconv.FormatInt(int64(enctype.GetETypeID()), 10)
}
