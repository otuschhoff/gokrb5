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
)

// NTLMSupplementalCred implements https://msdn.microsoft.com/en-us/library/cc237949.aspx
type NTLMSupplementalCred struct {
	Version    uint32 // A 32-bit unsigned integer that defines the credential version.This field MUST be 0x00000000.
	Flags      uint32
	LMPassword []byte // A 16-element array of unsigned 8-bit integers that define the LM OWF. The LMPassword member MUST be ignored if the L flag is not set in the Flags member.
	NTPassword []byte // A 16-element array of unsigned 8-bit integers that define the NT OWF. The NTPassword member MUST be ignored if the N flag is not set in the Flags member.
}

// Unmarshal converts the bytes provided into a NTLMSupplementalCred.
func (c *NTLMSupplementalCred) Unmarshal(b []byte) error {
	var err error
	r := mstypes.NewReader(bytes.NewReader(b))
	c.Version, err = r.Uint32()
	if err != nil {
		return err
	}
	if c.Version != 0 {
		err = errors.New("NTLMSupplementalCred version is not zero")
		return err
	}
	c.Flags, err = r.Uint32()
	if err != nil {
		return err
	}
	if isFlagSet(c.Flags, NTLMSupCredLMOWF) {
		c.LMPassword, err = r.ReadBytes(16)
		if err != nil {
			return err
		}
	}
	if isFlagSet(c.Flags, NTLMSupCredNTOWF) {
		c.NTPassword, err = r.ReadBytes(16)
		if err != nil {
			return err
		}
	}
	return err
}

// isFlagSet tests if a flag is set in the uint32 little endian flag
func isFlagSet(f uint32, i uint32) bool {
	// Which byte?
	b := int(i / 8)
	// Which bit in byte
	p := uint(7 - (int(i) - 8*b))
	fb := make([]byte, 4)
	binary.LittleEndian.PutUint32(fb, f)
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
