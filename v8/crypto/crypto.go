// Package crypto implements cryptographic functions for Kerberos 5 implementation.
package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3961"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc8009"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type passwordKeyParameters struct {
	etypeID   int32
	salt      string
	saltSet   bool
	s2kParams []byte
}

// GetEtype returns an instances of the required etype struct for the etype ID.
func GetEtype(id int32) (etype.EType, error) {
	switch id {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		var et Aes128CtsHmacSha96
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		var et Aes256CtsHmacSha96
		return et, nil
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		var et Aes256CtsHmacSha384192
		return et, nil
	case etypeID.DES3_CBC_SHA1_KD:
		var et Des3CbcSha1Kd
		return et, nil
	case etypeID.RC4_HMAC:
		var et RC4HMAC
		return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported EType: %d", id)
	}
}

// GetChksumEtype returns an instances of the required etype struct for the checksum ID.
func GetChksumEtype(id int32) (etype.EType, error) {
	switch id {
	case chksumtype.HMAC_SHA1_96_AES128:
		var et Aes128CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA1_96_AES256:
		var et Aes256CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA256_128_AES128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case chksumtype.HMAC_SHA384_192_AES256:
		var et Aes256CtsHmacSha384192
		return et, nil
	case chksumtype.HMAC_SHA1_DES3_KD:
		var et Des3CbcSha1Kd
		return et, nil
	case chksumtype.KERB_CHECKSUM_HMAC_MD5:
		var et RC4HMAC
		return et, nil
	//case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
	//	var et RC4HMAC
	//	return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported checksum type: %d", id)
	}
}

// GetKeyFromPassword generates an encryption key from the principal's password.
func GetKeyFromPassword(passwd string, cname types.PrincipalName, realm string, etypeID int32, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	return GetKeyFromPasswordForETypes(passwd, cname, realm, []int32{etypeID}, pas)
}

// GetKeyFromPasswordForETypes generates an encryption key using the first
// KDC-offered encryption type present in requestedETypeIDs.
func GetKeyFromPasswordForETypes(passwd string, cname types.PrincipalName, realm string, requestedETypeIDs []int32, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey
	if len(requestedETypeIDs) == 0 {
		return key, nil, fmt.Errorf("no encryption types requested")
	}
	requested := make(map[int32]struct{}, len(requestedETypeIDs))
	for _, id := range requestedETypeIDs {
		requested[id] = struct{}{}
	}

	var info2 []passwordKeyParameters
	var info []passwordKeyParameters
	var passwordSalt *string
	var hasETypeInfo bool
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			hasETypeInfo = true
			var entries types.ETypeInfo2
			if err := entries.Unmarshal(pa.PADataValue); err != nil {
				return key, nil, fmt.Errorf("error unmarshalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			saltPresent, err := etypeInfo2SaltPresence(pa.PADataValue)
			if err != nil || len(saltPresent) != len(entries) {
				return key, nil, fmt.Errorf("error determining PA-ETYPE-INFO2 salt presence")
			}
			for i, entry := range entries {
				if _, ok := requested[entry.EType]; ok {
					info2 = append(info2, passwordKeyParameters{etypeID: entry.EType, salt: entry.Salt, saltSet: saltPresent[i], s2kParams: entry.S2KParams})
				}
			}
		case patype.PA_ETYPE_INFO:
			hasETypeInfo = true
			var entries types.ETypeInfo
			if err := entries.Unmarshal(pa.PADataValue); err != nil {
				return key, nil, fmt.Errorf("error unmarshalling PA Data to PA-ETYPE-INFO: %v", err)
			}
			for _, entry := range entries {
				if _, ok := requested[entry.EType]; ok {
					info = append(info, passwordKeyParameters{etypeID: entry.EType, salt: string(entry.Salt), saltSet: true})
				}
			}
		case patype.PA_PW_SALT:
			salt := string(pa.PADataValue)
			passwordSalt = &salt
		}
	}

	parameters, et, found := firstSupportedKeyParameters(info2)
	if !found {
		parameters, et, found = firstSupportedKeyParameters(info)
	}
	if !found && hasETypeInfo {
		return key, nil, fmt.Errorf("KDC did not provide parameters for a requested supported encryption type")
	}
	if !found {
		for _, id := range requestedETypeIDs {
			candidate, err := GetEtype(id)
			if err == nil {
				parameters = passwordKeyParameters{etypeID: id}
				et = candidate
				found = true
				break
			}
		}
	}
	if !found {
		return key, nil, fmt.Errorf("none of the requested encryption types are supported")
	}
	if len(info2) == 0 && len(info) == 0 && passwordSalt != nil {
		parameters.salt = *passwordSalt
		parameters.saltSet = true
	}
	sk2p := et.GetDefaultStringToKeyParams()
	if len(parameters.s2kParams) == 4 {
		sk2p = hex.EncodeToString(parameters.s2kParams)
	}
	if !parameters.saltSet {
		parameters.salt = cname.GetSalt(realm)
	}
	k, err := et.StringToKey(passwd, parameters.salt, sk2p)
	if err != nil {
		return key, et, fmt.Errorf("error deriving key from string: %+v", err)
	}
	key = types.EncryptionKey{
		KeyType:  parameters.etypeID,
		KeyValue: k,
	}
	return key, et, nil
}

func etypeInfo2SaltPresence(data []byte) ([]bool, error) {
	type rawEntry struct {
		EType int32         `asn1:"explicit,tag:0"`
		Salt  asn1.RawValue `asn1:"optional"`
	}
	var entries []rawEntry
	if _, err := asn1.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	present := make([]bool, len(entries))
	for i, entry := range entries {
		present[i] = entry.Salt.Class == asn1.ClassContextSpecific && entry.Salt.Tag == 1
	}
	return present, nil
}

func firstSupportedKeyParameters(parameters []passwordKeyParameters) (passwordKeyParameters, etype.EType, bool) {
	for _, parameters := range parameters {
		et, err := GetEtype(parameters.etypeID)
		if err == nil {
			return parameters, et, true
		}
	}
	return passwordKeyParameters{}, nil, false
}

// KRBFXCF2 combines two protocol keys using KRB-FX-CF2 from RFC 6113.
// The result uses the enctype of key1.
func KRBFXCF2(key1, key2 types.EncryptionKey, pepper1, pepper2 []byte) (types.EncryptionKey, error) {
	et1, err := GetEtype(key1.KeyType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("error getting first key enctype: %w", err)
	}
	et2, err := GetEtype(key2.KeyType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("error getting second key enctype: %w", err)
	}
	seedBytes := et1.GetKeySeedBitLength() / 8
	if seedBytes == 0 || et1.GetKeySeedBitLength()%8 != 0 {
		return types.EncryptionKey{}, fmt.Errorf("invalid key seed length for enctype %d", key1.KeyType)
	}
	prf1, err := krbFXPRFPlus(key1.KeyValue, pepper1, seedBytes, et1)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("error expanding first key: %w", err)
	}
	prf2, err := krbFXPRFPlus(key2.KeyValue, pepper2, seedBytes, et2)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("error expanding second key: %w", err)
	}
	for i := range prf1 {
		prf1[i] ^= prf2[i]
	}
	return types.EncryptionKey{KeyType: key1.KeyType, KeyValue: et1.RandomToKey(prf1)}, nil
}

func krbFXPRFPlus(key, pepper []byte, length int, et etype.EType) ([]byte, error) {
	out := make([]byte, 0, length)
	for counter := byte(1); len(out) < length; counter++ {
		if counter == 0 {
			return nil, fmt.Errorf("PRF+ output exceeds 255 iterations")
		}
		input := make([]byte, 1, len(pepper)+1)
		input[0] = counter
		input = append(input, pepper...)
		block, err := krbFXPseudoRandom(key, input, et)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out[:length], nil
}

func krbFXPseudoRandom(key, input []byte, et etype.EType) ([]byte, error) {
	switch et.GetETypeID() {
	case etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA384_192:
		return rfc8009.DeriveRandom(key, input, et)
	default:
		return rfc3961.PseudoRandom(key, input, et)
	}
}

// GetEncryptedData encrypts the data provided and returns and EncryptedData type.
// Pass a usage value of zero to use the key provided directly rather than deriving one.
func GetEncryptedData(plainBytes []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return ed, fmt.Errorf("error getting etype: %v", err)
	}
	_, b, err := et.EncryptMessage(key.KeyValue, plainBytes, usage)
	if err != nil {
		return ed, err
	}

	ed = types.EncryptedData{
		EType:  key.KeyType,
		Cipher: b,
		KVNO:   kvno,
	}
	return ed, nil
}

// DecryptEncPart decrypts the EncryptedData.
func DecryptEncPart(ed types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	return DecryptMessage(ed.Cipher, key, usage)
}

// DecryptMessage decrypts the ciphertext and verifies the integrity.
func DecryptMessage(ciphertext []byte, key types.EncryptionKey, usage uint32) ([]byte, error) {
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting: %v", err)
	}
	b, err := et.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %v", err)
	}
	return b, nil
}
