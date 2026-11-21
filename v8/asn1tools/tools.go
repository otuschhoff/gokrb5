// Package asn1tools provides tools for managing ASN1 marshaled data.
package asn1tools

import (
	"github.com/jcmturner/gofork/encoding/asn1"
)

const (
	longFormBit         = 0x80
	shortLengthMask     = longFormBit - 1
	octetRadix          = 256
	longFormBytesOffset = 2 // After the single identifier octet and the first length octet.
)

// MarshalLengthBytes returns the ASN.1 length encoding for l, or nil if l is negative.
//
// The short form uses one octet for lengths from 0 through 127. Its high bit
// is clear, and the remaining bits give the length.
//
// In the definite long form, the high bit of the first octet is set. The
// remaining bits give the number of following octets, which encode the length
// in base 256, most significant octet first.
func MarshalLengthBytes(l int) []byte {
	if l < 0 {
		return nil
	}
	if l <= shortLengthMask {
		return []byte{byte(l)} // #nosec G115 -- bounded to [0,127].
	}
	var b []byte
	p := 1
	for i := 1; i < 127; {
		value := (l % (p * octetRadix)) / p
		b = append([]byte{byte(value)}, b...) // #nosec G115 -- value is exactly 0..255.
		p *= octetRadix
		l -= l % p
		if l <= 0 {
			break
		}
	}
	first := byte(longFormBit + len(b)) // #nosec G115 -- b is shorter than the ASN.1 limit of 126 octets.
	return append([]byte{first}, b...)
}

// GetLengthFromASN returns the length of a slice of ASN1 encoded bytes from the ASN1 length header it contains.
func GetLengthFromASN(b []byte) int {
	length, _, ok := parseLengthHeader(b)
	if !ok {
		return 0
	}
	return length
}

// GetNumberBytesInLengthHeader returns the number of bytes in the ASn1 header that indicate the length.
func GetNumberBytesInLengthHeader(b []byte) int {
	_, headerBytes, ok := parseLengthHeader(b)
	if !ok {
		return 0
	}
	return headerBytes
}

func parseLengthHeader(b []byte) (int, int, bool) {
	var length int

	if len(b) < longFormBytesOffset {
		return 0, 0, false
	}
	if b[1]&longFormBit == 0 {
		return int(b[1]), 1, true
	}
	lengthBytes := int(b[1] & shortLengthMask)
	if lengthBytes == 0 || lengthBytes > len(b)-longFormBytesOffset {
		return 0, 0, false
	}
	maximum := int(^uint(0) >> 1)
	for _, value := range b[longFormBytesOffset : longFormBytesOffset+lengthBytes] {
		if length > (maximum-int(value))/octetRadix {
			return 0, 0, false
		}
		length = length*octetRadix + int(value)
	}
	return length, 1 + lengthBytes, true
}

// AddASNAppTag adds an ASN1 encoding application tag value to the raw bytes provided.
func AddASNAppTag(b []byte, tag int) []byte {
	r := asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        tag,
		Bytes:      b,
		FullBytes:  nil,
	}
	ab, _ := asn1.Marshal(r)
	return ab
}

/*
// The Marshal method of golang's asn1 package does not enable you to define wrapping the output in an application tag.
// This method adds that wrapping tag.
func AddASNAppTag(b []byte, tag int) []byte {
	// The ASN1 wrapping consists of 2 bytes:
	// 1st byte -> Identifier Octet - Application Tag
	// 2nd byte -> The length (this will be the size indicated in the input bytes + 2 for the additional bytes we add here.
	// Application Tag:
	// Bits 8 and 7 are 01 for the application class. Bit 6 is 1 for a constructed value.
	// Bits 5 through 1 hold the application tag number from RFC 4120.
	// Therefore the value of the byte is an integer = ( Application tag value + 96 )
	//b = append(MarshalLengthBytes(int(b[1])+2), b...)
	b = append(MarshalLengthBytes(len(b)), b...)
	b = append([]byte{byte(96 + tag)}, b...)
	return b
}
*/
