package rfc4757

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RFC 4757 defines the legacy RC4-HMAC checksums with MD5.
)

// Checksum returns a hash of the data in accordance with RFC 4757
func Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	// Create hashing key
	s := []byte("signaturekey\x00")
	mac := hmac.New(md5.New, key)
	mac.Write(s)
	Ksign := mac.Sum(nil)

	h := md5.New() // #nosec G401 -- RFC 4757 section 4 fixes this digest inside the keyed checksum.
	// Hash writes cannot fail; hash the encoded usage before the data.
	h.Write(UsageToMSMsgType(usage))
	h.Write(data)
	tmp := h.Sum(nil)

	// Generate HMAC
	mac = hmac.New(md5.New, Ksign)
	mac.Write(tmp)
	return mac.Sum(nil), nil
}

// HMAC returns a keyed MD5 checksum of the data
func HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
