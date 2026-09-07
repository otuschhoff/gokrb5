package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestGetKeyFromPasswordSelectsMatchingETypeInfo2Entry(t *testing.T) {
	entries := types.ETypeInfo2{
		{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "aes256-salt"},
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "aes128-salt"},
	}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, selected, err := GetKeyFromPasswordForETypes("password", types.PrincipalName{}, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("password", "aes128-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, key.KeyType)
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordUsesDefaultForOmittedETypeInfo2Salt(t *testing.T) {
	cname := types.PrincipalName{NameString: []string{"testuser1"}}
	entries := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, selected, err := GetKeyFromPassword("passwordvalue", cname, "TEST.GOKRB5", etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("passwordvalue", cname.GetSalt("TEST.GOKRB5"), selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordPreservesExplicitEmptyETypeInfo2Salt(t *testing.T) {
	cname := types.PrincipalName{NameString: []string{"testuser1"}}
	value, err := hex.DecodeString("300b3009a003020112a1021b00")
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, selected, err := GetKeyFromPassword("passwordvalue", cname, "TEST.GOKRB5", etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("passwordvalue", "", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordUsesKDCPreferenceOrder(t *testing.T) {
	entries := types.ETypeInfo2{
		{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "aes256-salt"},
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "aes128-salt"},
	}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, _, err := GetKeyFromPasswordForETypes("password", types.PrincipalName{}, "EXAMPLE.ORG", []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	}, pas)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, key.KeyType)
}

func TestGetKeyFromPasswordETypeInfo2PrecedesPasswordSalt(t *testing.T) {
	entries := types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "info2-salt"}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value},
		{PADataType: patype.PA_PW_SALT, PADataValue: []byte("password-salt")},
	}
	key, selected, err := GetKeyFromPassword("password", types.PrincipalName{}, "EXAMPLE.ORG", etypeID.AES128_CTS_HMAC_SHA1_96, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("password", "info2-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordUsesETypeInfoOnly(t *testing.T) {
	entries := types.ETypeInfo{{EType: etypeID.DES3_CBC_SHA1_KD, Salt: []byte("legacy-salt")}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO, PADataValue: value}}
	key, selected, err := GetKeyFromPasswordForETypes("password", types.PrincipalName{}, "EXAMPLE.ORG", []int32{etypeID.DES3_CBC_SHA1_KD}, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("password", "legacy-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.DES3_CBC_SHA1_KD, key.KeyType)
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordETypeInfo2PrecedesETypeInfo(t *testing.T) {
	infoValue, err := asn1.Marshal(types.ETypeInfo{{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: []byte("info-salt")}})
	if err != nil {
		t.Fatal(err)
	}
	info2Value, err := asn1.Marshal(types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "info2-salt"}})
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO, PADataValue: infoValue},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2Value},
	}
	key, selected, err := GetKeyFromPasswordForETypes("password", types.PrincipalName{}, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pas)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := selected.StringToKey("password", "info2-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordSkipsUnsupportedRequestedEType(t *testing.T) {
	key, _, err := GetKeyFromPasswordForETypes("password", types.PrincipalName{NameString: []string{"user"}}, "EXAMPLE.ORG", []int32{999, etypeID.AES128_CTS_HMAC_SHA1_96}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, key.KeyType)
}

func TestGetKeyFromPasswordRejectsUnmatchedETypeInfo(t *testing.T) {
	entries := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "aes256-salt"}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = GetKeyFromPasswordForETypes("password", types.PrincipalName{}, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, types.PADataSequence{{
		PADataType:  patype.PA_ETYPE_INFO2,
		PADataValue: value,
	}})
	assert.Error(t, err)
}
