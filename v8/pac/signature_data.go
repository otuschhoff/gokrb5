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
	// SignatureType identifies the checksum algorithm and determines the signature size.
	SignatureType uint32
	Signature     []byte
	// RODCIdentifier holds the first 16 bits of the key version number for an RODC (MS-KILE 3.1.5.8).
	// The field is absent from the wire encoding when the KDC is not an RODC.
	RODCIdentifier    uint16
	HasRODCIdentifier bool
}

const (
	signatureTypeLength  = 4
	rodcIdentifierLength = 2
	hmacMD5Length        = 16
	hmacSHA196Length     = 12
	hmacSHA256128Length  = 16
	hmacSHA384192Length  = 24
)

func signatureLength(signatureType uint32) (int, error) {
	switch signatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		return hmacMD5Length, nil
	case uint32(chksumtype.HMAC_SHA1_96_AES128), uint32(chksumtype.HMAC_SHA1_96_AES256):
		return hmacSHA196Length, nil
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		return hmacSHA256128Length, nil
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		return hmacSHA384192Length, nil
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
