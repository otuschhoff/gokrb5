package crypto

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/crypto/common"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3962"
)

func mustCryptoUint32(t *testing.T, value int64) uint32 {
	t.Helper()
	if value < 0 || uint64(value) > uint64(math.MaxUint32) { // #nosec G115 -- negative branch checked before conversion.
		t.Fatalf("iteration count %d exceeds uint32 range", value)
	}
	return uint32(value) // #nosec G115 -- bounded above.
}

func TestAes128CtsHmacSha196_StringToKey(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 3962 Appendix B
	b, _ := hex.DecodeString("1234567878563412")
	s := string(b)
	b, _ = hex.DecodeString("f09d849e")
	s2 := string(b)
	tests := []struct {
		iterations int64
		phrase     string
		salt       string
		pbkdf2     string
		key        string
	}{
		{1, fixturePassword, fixtureAthenaSalt, "cdedb5281bb2f801565a1122b2563515", "42263c6e89f4fc28b8df68ee09799f15"},
		{2, fixturePassword, fixtureAthenaSalt, "01dbee7f4a9e243e988b62c73cda935d", "c651bf29e2300ac27fa469d693bdda13"},
		{1200, fixturePassword, fixtureAthenaSalt, "5c08eb61fdf71e4e4ec3cf6ba1f5512b", "4c01cd46d632d01e6dbe230a01ed642a"},
		{5, fixturePassword, s, "d1daa78615f287e6a1c8b120d7062a49", "e9b23d52273747dd5c35cb55be619d8e"},
		{
			1200,
			"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"pass phrase equals block size",
			"139c30c0966bc32ba55fdbf212530ac9",
			"59d1bb789a828b1aa54ef9c2883f69ed",
		},
		{
			1200,
			"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			"pass phrase exceeds block size",
			"9ccad6d468770cd51b10e6a68721be61",
			"cb8005dc5f90179a7f02104c0018751d",
		},
		{50, s2, fixturePianistSalt, "6b9cf26d45455a43a5b8bb276a403b39", "f149c1f2e154a73452d43e7fe62a56e5"},
	}
	var e Aes128CtsHmacSha96
	for i, test := range tests {

		pbkdf2 := rfc3962.StringToPBKDF2(test.phrase, test.salt, test.iterations, e)
		assert.Equal(t, test.pbkdf2, hex.EncodeToString(pbkdf2), "PBKDF2 not as expected")
		k, err := e.StringToKey(test.phrase, test.salt, common.IterationsToS2Kparams(mustCryptoUint32(t, test.iterations)))
		if err != nil {
			t.Errorf("error in processing string to key for test %d: %v", i, err)
		}
		assert.Equal(t, test.key, hex.EncodeToString(k), "String to Key not as expected")

	}
}
