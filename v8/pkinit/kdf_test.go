package pkinit

import (
	"encoding/hex"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

func TestDeriveReplyKeyRFC8636SHA256(t *testing.T) {
	client := principal("SU.SE", nametype.KRB_NT_PRINCIPAL, "lha")
	server := principal("SU.SE", nametype.KRB_NT_PRINCIPAL, "krbtgt", "SU.SE")
	key, err := DeriveReplyKey(
		KDFAlgorithmID{ID: OIDKDFSHA256},
		make([]byte, 256),
		client,
		server,
		bytesOf(0xaa, 10),
		bytesOf(0xbb, 9),
		etypeID.AES256_CTS_HMAC_SHA1_96,
	)
	require.NoError(t, err)
	require.Equal(t, "77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5", hex.EncodeToString(key.KeyValue))
}

func TestDeriveLegacyReplyKeyRFC4556Set1(t *testing.T) {
	key, err := DeriveLegacyReplyKey(make([]byte, 256), nil, nil, etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	require.Equal(t, "5ee50d675c809fe59e4a7762c54b65837547eafb159bd8cdc75ffca5911e4c41", hex.EncodeToString(key.KeyValue))
}

func TestDeriveReplyKeyRejectsUnknownKDF(t *testing.T) {
	_, err := DeriveReplyKey(KDFAlgorithmID{ID: []int{1, 2, 3}}, nil, KRB5PrincipalName{}, KRB5PrincipalName{}, nil, nil, etypeID.AES256_CTS_HMAC_SHA1_96)
	require.ErrorContains(t, err, "unsupported PKINIT KDF OID")
}

func bytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}
	return b
}

func principal(realm string, nameType int32, components ...string) KRB5PrincipalName {
	return KRB5PrincipalName{
		Realm: realm,
		PrincipalName: types.PrincipalName{
			NameType:   nameType,
			NameString: components,
		},
	}
}
