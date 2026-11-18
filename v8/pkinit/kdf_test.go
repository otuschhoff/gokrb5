package pkinit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
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

func TestCounterKDFBlockBoundaries(t *testing.T) {
	t.Parallel()

	first := sha256.Sum256([]byte("\x00\x00\x00\x01secretinfo"))
	second := sha256.Sum256([]byte("\x00\x00\x00\x02secretinfo"))
	var expected [2 * sha256.Size]byte
	copy(expected[:], first[:])
	copy(expected[sha256.Size:], second[:])

	tests := []struct {
		name   string
		length int
	}{
		{name: "empty", length: 0},
		{name: "partial first block", length: sha256.Size - 1},
		{name: "exact first block", length: sha256.Size},
		{name: "partial second block", length: sha256.Size + 1},
		{name: "exact second block", length: len(expected)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seed, err := counterKDF(sha256.New, []byte("secret"), []byte("info"), tt.length)
			if err != nil {
				t.Fatal(err)
			}
			if seed == nil || !bytes.Equal(seed, expected[:tt.length]) {
				t.Fatalf("seed = %x, want %x", seed, expected[:tt.length])
			}
		})
	}
}

func TestCounterKDFRejectsOversizedOutput(t *testing.T) {
	t.Parallel()

	// This exceeds the counter range on 64-bit platforms and the rounded
	// slice capacity on 32-bit platforms. Neither path should allocate.
	seed, err := counterKDF(sha256.New, nil, nil, math.MaxInt)
	if seed != nil || err == nil || err.Error() != "PKINIT KDF output is too long" {
		t.Fatalf("counterKDF returned %d bytes and %v, want an output length error", len(seed), err)
	}
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
