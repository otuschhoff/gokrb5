package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
)

const (
	// NTLMSupCredLMOWF indicates that the LM OWF member is present and valid.
	NTLMSupCredLMOWF uint32 = 31
	// NTLMSupCredNTOWF indicates that the NT OWF member is present and valid.
	NTLMSupCredNTOWF uint32 = 30

	ntlmOWFLength = 16
)

// NTLMSupplementalCred implements https://msdn.microsoft.com/en-us/library/cc237949.aspx
type NTLMSupplementalCred struct {
	Version uint32 // A 32-bit unsigned integer that defines the credential version.This field MUST be 0x00000000.
	Flags   uint32
	// LMPassword is the 16-byte LM OWF. It must be ignored when the L flag is not set.
	LMPassword []byte
	// NTPassword is the 16-byte NT OWF. It must be ignored when the N flag is not set.
	NTPassword []byte
}

// Unmarshal converts the bytes provided into a NTLMSupplementalCred.
func (c *NTLMSupplementalCred) Unmarshal(b []byte) error {
	var err error
	r := bytes.NewReader(b)
	c.Version, err = readPACUint32(r, "supplemental credential version")
	if err != nil {
		return err
	}
	if c.Version != 0 {
		return errors.New("NTLMSupplementalCred version is not zero")
	}
	c.Flags, err = readPACUint32(r, "supplemental credential flags")
	if err != nil {
		return err
	}
	if isFlagSet(c.Flags, NTLMSupCredLMOWF) {
		c.LMPassword, err = readPACBytes(r, ntlmOWFLength, "supplemental LM credential")
		if err != nil {
			return err
		}
	}
	if isFlagSet(c.Flags, NTLMSupCredNTOWF) {
		c.NTPassword, err = readPACBytes(r, ntlmOWFLength, "supplemental NT credential")
		if err != nil {
			return err
		}
	}
	return nil
}

// isFlagSet numbers bits from the most significant bit of each little-endian byte.
func isFlagSet(f uint32, i uint32) bool {
	const (
		bitsPerByte    = 8
		flagsByteCount = 4
	)
	b := int(i / bitsPerByte)
	p := bitsPerByte - 1 - i%bitsPerByte
	var fb [flagsByteCount]byte
	binary.LittleEndian.PutUint32(fb[:], f)
	return fb[b]&(1<<p) != 0
}

// SECPKGSupplementalCred implements https://msdn.microsoft.com/en-us/library/cc237956.aspx
type SECPKGSupplementalCred struct {
	PackageName    mstypes.RPCUnicodeString
	CredentialSize uint32
	Credentials    []uint8 `ndr:"pointer,conformant"` // Is a ptr. Size is the value of CredentialSize
}

// Unmarshal converts the bytes provided into a SECPKGSupplementalCred.
func (c *SECPKGSupplementalCred) Unmarshal(b []byte) error {
	var err error
	dec := ndr.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(c)
	if err != nil {
		err = fmt.Errorf("error unmarshaling SECPKGSupplementalCred: %w", err)
	}
	return err
}
