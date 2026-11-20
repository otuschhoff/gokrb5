package gssapi

import "github.com/jcmturner/gofork/encoding/asn1"

// GSS-API context flags assigned numbers.
const (
	ContextFlagDeleg         = 1
	ContextFlagMutual        = 2
	ContextFlagReplay        = 4
	ContextFlagSequence      = 8
	ContextFlagConf          = 16
	ContextFlagInteg         = 32
	ContextFlagAnon          = 64
	ContextFlagDCEStyle      = 0x1000
	ContextFlagExtendedError = 0x4000
)

// ContextFlags flags for GSSAPI
// DEPRECATED - do not use
type ContextFlags asn1.BitString

// NewContextFlags creates a new ContextFlags instance
// DEPRECATED - do not use
func NewContextFlags() ContextFlags {
	const bitLength = 32
	var c ContextFlags
	c.BitLength = bitLength
	c.Bytes = make([]byte, bitLength/bitsPerByte)
	return c
}
