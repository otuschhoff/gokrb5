package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
)

/*
https://msdn.microsoft.com/en-us/library/cc237955.aspx

The Key Usage Value MUST be KERB_NON_KERB_CKSUM_SALT (17) [MS-KILE] (section 3.1.5.9).

Server Signature (SignatureType = 0x00000006)
https://msdn.microsoft.com/en-us/library/cc237957.aspx

KDC Signature (SignatureType = 0x00000007)
https://msdn.microsoft.com/en-us/library/dd357117.aspx
*/

// SignatureData implements https://msdn.microsoft.com/en-us/library/cc237955.aspx
type SignatureData struct {
	SignatureType     uint32 // A 32-bit unsigned integer value in little-endian format that defines the cryptographic system used to calculate the checksum. This MUST be one of the following checksum types: KERB_CHECKSUM_HMAC_MD5 (signature size = 16), HMAC_SHA1_96_AES128 (signature size = 12), HMAC_SHA1_96_AES256 (signature size = 12).
	Signature         []byte // Size depends on the type. See comment above.
	RODCIdentifier    uint16 // A 16-bit unsigned integer value in little-endian format that contains the first 16 bits of the key version number ([MS-KILE] section 3.1.5.8) when the KDC is an RODC. When the KDC is not an RODC, this field does not exist.
	HasRODCIdentifier bool
}

const (
	signatureTypeLength  = 4
	rodcIdentifierLength = 2
)

func signatureLength(signatureType uint32) (int, error) {
	switch signatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		return 16, nil
	case uint32(chksumtype.HMAC_SHA1_96_AES128), uint32(chksumtype.HMAC_SHA1_96_AES256):
		return 12, nil
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		return 16, nil
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		return 24, nil
	default:
		return 0, fmt.Errorf("unsupported PAC signature type %d", signatureType)
	}
}

// Marshal returns the PAC_SIGNATURE_DATA encoding.
func (k SignatureData) Marshal() ([]byte, error) {
	length, err := signatureLength(k.SignatureType)
	if err != nil {
		return nil, err
	}
	if len(k.Signature) != length {
		return nil, fmt.Errorf("PAC signature length is %d, expected %d", len(k.Signature), length)
	}
	size := signatureTypeLength + length
	if k.HasRODCIdentifier || k.RODCIdentifier != 0 {
		size += rodcIdentifierLength
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, k.SignatureType)
	copy(b[signatureTypeLength:], k.Signature)
	if k.HasRODCIdentifier || k.RODCIdentifier != 0 {
		binary.LittleEndian.PutUint16(b[signatureTypeLength+length:], k.RODCIdentifier)
	}
	return b, nil
}

// Unmarshal bytes into the SignatureData struct
func (k *SignatureData) Unmarshal(b []byte) ([]byte, error) {
	var err error
	k.SignatureType, err = readPACUint32(bytes.NewReader(b), "PAC signature type")
	if err != nil {
		return nil, err
	}

	length, err := signatureLength(k.SignatureType)
	if err != nil {
		return nil, err
	}
	end := signatureTypeLength + length
	if end > len(b) {
		return nil, fmt.Errorf("invalid PAC signature data length %d", len(b))
	}
	tail := b[end:]
	if len(tail) != 0 && len(tail) != rodcIdentifierLength {
		return nil, fmt.Errorf("invalid PAC signature data length %d", len(b))
	}
	k.Signature = bytes.Clone(b[signatureTypeLength:end])
	if len(tail) == rodcIdentifierLength {
		k.RODCIdentifier = binary.LittleEndian.Uint16(tail)
		k.HasRODCIdentifier = true
	} else {
		k.RODCIdentifier = 0
		k.HasRODCIdentifier = false
	}

	zeroed := bytes.Clone(b)
	clear(zeroed[signatureTypeLength:end])
	return zeroed, nil
}
