// Package rfc4757 provides encryption and checksum methods as specified in RFC 4757
package rfc4757

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4" // #nosec G503 -- RFC 4757 compatibility; RFC 8429 deprecates the enctype.
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
)

// EncryptData encrypts the data provided using methods specific to the etype provided as defined in RFC 4757.
func EncryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}
	rc4Cipher, err := rc4.NewCipher(key) // #nosec G405 -- RFC 4757 wire cipher, not a general-purpose default.
	if err != nil {
		return []byte{}, fmt.Errorf("error creating RC4 cipher: %w", err)
	}
	ed := make([]byte, len(data))
	copy(ed, data)
	rc4Cipher.XORKeyStream(ed, ed)
	rc4Cipher.Reset()
	return ed, nil
}

// DecryptData decrypts the data provided using the methods specific to the etype provided as defined in RFC 4757.
func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	return EncryptData(key, data, e)
}

// EncryptMessage encrypts the message provided using the methods specific to the etype provided as defined in RFC 4757.
// The encrypted data is concatenated with its RC4 header containing integrity checksum and confounder to create an encrypted message.
func EncryptMessage(key, data []byte, usage uint32, _ bool, e etype.EType) ([]byte, error) {
	confounder := make([]byte, e.GetConfounderByteSize()) // size = 8
	_, err := rand.Read(confounder)
	if err != nil {
		return []byte{}, fmt.Errorf("error generating confounder: %w", err)
	}
	k1 := key
	k2 := HMAC(k1, UsageToMSMsgType(usage))
	confounder = append(confounder, data...)
	chksum := HMAC(k2, confounder)
	k3 := HMAC(k2, chksum)

	ed, err := EncryptData(k3, confounder, e)
	if err != nil {
		return []byte{}, fmt.Errorf("error encrypting data: %w", err)
	}

	chksum = append(chksum, ed...)
	return chksum, nil
}

// DecryptMessage decrypts the message provided using the methods specific to the etype provided as defined in RFC 4757.
// The integrity of the message is also verified.
// The export-weakened RC4-HMAC-EXP variant is not implemented; the flag is retained for compatibility and ignored.
func DecryptMessage(key, data []byte, usage uint32, _ bool, e etype.EType) ([]byte, error) {
	checksumSize := e.GetHMACBitLength() / 8
	if checksumSize <= 0 || len(data) < checksumSize+e.GetConfounderByteSize() {
		return nil, errors.New("ciphertext is too short")
	}
	checksum := data[:checksumSize]
	ct := data[checksumSize:]
	_, k2, k3 := deriveKeys(key, checksum, usage)

	pt, err := DecryptData(k3, ct, e)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting data: %w", err)
	}

	if !VerifyIntegrity(k2, pt, data, e) {
		return []byte{}, errors.New("integrity checksum incorrect")
	}
	if len(pt) < e.GetConfounderByteSize() {
		return nil, errors.New("decrypted plaintext is shorter than the confounder")
	}
	return pt[e.GetConfounderByteSize():], nil
}

// VerifyIntegrity checks the integrity checksum of the data matches that calculated from the decrypted data.
func VerifyIntegrity(key, pt, data []byte, e etype.EType) bool {
	checksumSize := e.GetHMACBitLength() / 8
	if checksumSize <= 0 || len(data) < checksumSize {
		return false
	}
	chksum := HMAC(key, pt)
	return hmac.Equal(chksum, data[:checksumSize])
}
