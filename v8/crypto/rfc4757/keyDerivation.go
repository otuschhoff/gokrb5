package rfc4757

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	// #nosec G506 -- RFC 4757 specifies MD4 for legacy string-to-key.
	"golang.org/x/crypto/md4"
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 4757.
func StringToKey(secret string) ([]byte, error) {
	b := make([]byte, len(secret)*2)
	for i, r := range secret {
		u := fmt.Sprintf("%04x", r)
		c, err := hex.DecodeString(u)
		if err != nil {
			return []byte{}, errors.New("character could not be encoded")
		}
		// Swap round the two bytes to make little endian as we put into byte slice
		b[2*i] = c[1]
		b[2*i+1] = c[0]
	}
	r := bytes.NewReader(b)
	h := md4.New() // #nosec G406 -- RFC 4757 section 2 fixes the password-to-key digest.
	_, err := io.Copy(h, r)
	if err != nil {
		return []byte{}, err
	}
	return h.Sum(nil), nil
}

func deriveKeys(key, checksum []byte, usage uint32) ([]byte, []byte, []byte) {
	var k1 []byte
	var k2 []byte
	var k3 []byte
	k1 = key
	k2 = HMAC(k1, UsageToMSMsgType(usage))
	k3 = HMAC(k2, checksum)
	return k1, k2, k3
}
