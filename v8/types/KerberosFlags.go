package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.8

import (
	"github.com/jcmturner/gofork/encoding/asn1"
)

const (
	kerberosFlagBytes = 4
	bitsPerByte       = 8
	kerberosFlagBits  = kerberosFlagBytes * bitsPerByte
)

// NewKrbFlags returns an ASN1 BitString struct of the right size for KrbFlags.
func NewKrbFlags() asn1.BitString {
	return asn1.BitString{Bytes: make([]byte, kerberosFlagBytes), BitLength: kerberosFlagBits}
}

// SetFlags sets the flags of an ASN1 BitString.
func SetFlags(f *asn1.BitString, j []int) {
	for _, i := range j {
		SetFlag(f, i)
	}
}

// SetFlag sets a flag in an ASN1 BitString.
func SetFlag(f *asn1.BitString, i int) {
	if f == nil || i < 0 || i >= kerberosFlagBits {
		return
	}
	extendKrbFlags(f)
	f.Bytes[i/bitsPerByte] |= krbFlagMask(i)
}

// UnsetFlags unsets flags in an ASN1 BitString.
func UnsetFlags(f *asn1.BitString, j []int) {
	for _, i := range j {
		UnsetFlag(f, i)
	}
}

// UnsetFlag unsets a flag in an ASN1 BitString.
func UnsetFlag(f *asn1.BitString, i int) {
	if f == nil || i < 0 || i >= kerberosFlagBits {
		return
	}
	extendKrbFlags(f)
	f.Bytes[i/bitsPerByte] &^= krbFlagMask(i)
}

// IsFlagSet tests if a flag is set in the ASN1 BitString.
func IsFlagSet(f *asn1.BitString, i int) bool {
	if f == nil || i < 0 || i >= len(f.Bytes)*bitsPerByte {
		return false
	}
	return f.Bytes[i/bitsPerByte]&krbFlagMask(i) != 0
}

func extendKrbFlags(f *asn1.BitString) {
	for len(f.Bytes) < kerberosFlagBytes {
		f.Bytes = append(f.Bytes, 0)
		f.BitLength = len(f.Bytes) * bitsPerByte
	}
}

func krbFlagMask(i int) byte {
	return 1 << (bitsPerByte - 1 - i%bitsPerByte)
}
