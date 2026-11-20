package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	fixturePassword    = "password"
	fixtureAES256Salt  = "aes256-salt"
	fixtureAthenaSalt  = "ATHENA.MIT.EDUraeburn"
	fixturePianistSalt = "EXAMPLE.COMpianist"
)

func TestGetKeyFromPasswordSelectsMatchingETypeInfo2Entry(t *testing.T) {
	entries := types.ETypeInfo2{
		{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: fixtureAES256Salt, S2KParams: nil},
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "aes128-salt", S2KParams: nil},
	}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	var cname types.PrincipalName
	key, selected, err := GetKeyFromPasswordForETypes(
		fixturePassword, cname, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pas,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey(fixturePassword, "aes128-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, key.KeyType)
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordUsesDefaultForOmittedETypeInfo2Salt(t *testing.T) {
	cname := types.PrincipalName{NameType: 0, NameString: []string{"testuser1"}}
	entries := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: "", S2KParams: nil}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, selected, err := GetKeyFromPassword("passwordvalue", cname, "TEST.GOKRB5", etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey(
		"passwordvalue", cname.GetSalt("TEST.GOKRB5"), selected.GetDefaultStringToKeyParams(),
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordPreservesExplicitEmptyETypeInfo2Salt(t *testing.T) {
	cname := types.PrincipalName{NameType: 0, NameString: []string{"testuser1"}}
	value, err := hex.DecodeString("300b3009a003020112a1021b00")
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	key, selected, err := GetKeyFromPassword("passwordvalue", cname, "TEST.GOKRB5", etypeID.AES256_CTS_HMAC_SHA1_96, pas)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey("passwordvalue", "", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordUsesKDCPreferenceOrder(t *testing.T) {
	entries := types.ETypeInfo2{
		{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: fixtureAES256Salt, S2KParams: nil},
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "aes128-salt", S2KParams: nil},
	}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}}
	var cname types.PrincipalName
	key, _, err := GetKeyFromPasswordForETypes(fixturePassword, cname, "EXAMPLE.ORG", []int32{
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	}, pas)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, key.KeyType)
}

func TestGetKeyFromPasswordETypeInfo2PrecedesPasswordSalt(t *testing.T) {
	entries := types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "info2-salt", S2KParams: nil}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value},
		{PADataType: patype.PA_PW_SALT, PADataValue: []byte("password-salt")},
	}
	var cname types.PrincipalName
	key, selected, err := GetKeyFromPassword(
		fixturePassword, cname, "EXAMPLE.ORG", etypeID.AES128_CTS_HMAC_SHA1_96, pas,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey(fixturePassword, "info2-salt", selected.GetDefaultStringToKeyParams())
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
	var cname types.PrincipalName
	key, selected, err := GetKeyFromPasswordForETypes(
		fixturePassword, cname, "EXAMPLE.ORG", []int32{etypeID.DES3_CBC_SHA1_KD}, pas,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey(fixturePassword, "legacy-salt", selected.GetDefaultStringToKeyParams())
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
	info2Value, err := asn1.Marshal(types.ETypeInfo2{
		{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: "info2-salt", S2KParams: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO, PADataValue: infoValue},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2Value},
	}
	var cname types.PrincipalName
	key, selected, err := GetKeyFromPasswordForETypes(
		fixturePassword, cname, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pas,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected == nil {
		t.Fatal("selected encryption type is nil")
	}
	expected, err := selected.StringToKey(fixturePassword, "info2-salt", selected.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, key.KeyValue)
}

func TestGetKeyFromPasswordSkipsUnsupportedRequestedEType(t *testing.T) {
	cname := types.PrincipalName{NameType: 0, NameString: []string{"user"}}
	key, _, err := GetKeyFromPasswordForETypes(
		fixturePassword, cname, "EXAMPLE.ORG", []int32{999, etypeID.AES128_CTS_HMAC_SHA1_96}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, key.KeyType)
}

func TestGetKeyFromPasswordRejectsUnmatchedETypeInfo(t *testing.T) {
	entries := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Salt: fixtureAES256Salt, S2KParams: nil}}
	value, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var cname types.PrincipalName
	pas := types.PADataSequence{{
		PADataType:  patype.PA_ETYPE_INFO2,
		PADataValue: value,
	}}
	_, _, err = GetKeyFromPasswordForETypes(
		fixturePassword, cname, "EXAMPLE.ORG", []int32{etypeID.AES128_CTS_HMAC_SHA1_96}, pas,
	)
	assert.Error(t, err)
}
