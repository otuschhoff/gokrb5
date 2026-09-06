package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestKRBFXCF2RFC6113Vectors(t *testing.T) {
	tests := []struct {
		name   string
		etype  int32
		result string
	}{
		{name: "AES128", etype: etypeID.AES128_CTS_HMAC_SHA1_96, result: "97df97e4b798b29eb31ed7280287a92a"},
		{name: "AES256", etype: etypeID.AES256_CTS_HMAC_SHA1_96, result: "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			et, err := GetEtype(test.etype)
			if err != nil {
				t.Fatal(err)
			}
			key1, err := et.StringToKey("key1", "key1", et.GetDefaultStringToKeyParams())
			if err != nil {
				t.Fatal(err)
			}
			key2, err := et.StringToKey("key2", "key2", et.GetDefaultStringToKeyParams())
			if err != nil {
				t.Fatal(err)
			}
			combined, err := KRBFXCF2(
				types.EncryptionKey{KeyType: test.etype, KeyValue: key1},
				types.EncryptionKey{KeyType: test.etype, KeyValue: key2},
				[]byte("a"),
				[]byte("b"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(combined.KeyValue); got != test.result {
				t.Fatalf("KRB-FX-CF2 result = %s, want %s", got, test.result)
			}
		})
	}
}

func TestKRBFXCF2RFC8009Vectors(t *testing.T) {
	tests := []struct {
		name   string
		etype  int32
		keyLen int
		result string
	}{
		{name: "AES128-SHA256", etype: etypeID.AES128_CTS_HMAC_SHA256_128, keyLen: 16, result: "cd679b7b6e11268185f91e95ffaee9c0"},
		{name: "AES256-SHA384", etype: etypeID.AES256_CTS_HMAC_SHA384_192, keyLen: 32, result: "e9ce8095a99e4107baaabbffab0669ca8eaf295f74f6050f82c3b485e37fbbe9"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key1 := make([]byte, test.keyLen)
			key2 := make([]byte, test.keyLen)
			for i := range key1 {
				key1[i] = byte(i)
				key2[i] = byte(0xff - i)
			}
			combined, err := KRBFXCF2(
				types.EncryptionKey{KeyType: test.etype, KeyValue: key1},
				types.EncryptionKey{KeyType: test.etype, KeyValue: key2},
				[]byte("pepper-one"),
				[]byte("pepper-two"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(combined.KeyValue); got != test.result {
				t.Fatalf("KRB-FX-CF2 result = %s, want %s", got, test.result)
			}
		})
	}
}
