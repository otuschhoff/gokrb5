package gssapi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const authenticatorChecksumBindingLength = 16

// AuthenticatorChecksumExtension is an RFC 4121 checksum extension.
type AuthenticatorChecksumExtension struct {
	Type uint32
	Data []byte
}

// AuthenticatorChecksum is the RFC 4121 checksum carried by a Kerberos
// authenticator. Deleg contains an encoded KRB-CRED when delegation is used.
type AuthenticatorChecksum struct {
	Bnd              [authenticatorChecksumBindingLength]byte
	Flags            uint32
	DelegationOption uint16
	Deleg            []byte
	Exts             []AuthenticatorChecksumExtension
}

// NewAuthenticatorChecksum creates a checksum for the requested context flags.
func NewAuthenticatorChecksum(bindings *ChannelBindings, flags ...int) AuthenticatorChecksum {
	checksum := AuthenticatorChecksum{}
	if bindings != nil {
		checksum.Bnd = bindings.MD5Hash()
	}
	for _, flag := range flags {
		checksum.Flags |= uint32(flag)
	}
	return checksum
}

// Marshal encodes an RFC 4121 authenticator checksum.
func (c AuthenticatorChecksum) Marshal() ([]byte, error) {
	if len(c.Deleg) > int(^uint16(0)) {
		return nil, errors.New("delegated KRB-CRED exceeds 65535 bytes")
	}
	if len(c.Deleg) > 0 && c.Flags&ContextFlagDeleg == 0 {
		return nil, errors.New("delegated KRB-CRED requires the delegation flag")
	}
	b := make([]byte, 24, 28+len(c.Deleg))
	binary.LittleEndian.PutUint32(b[0:4], authenticatorChecksumBindingLength)
	copy(b[4:20], c.Bnd[:])
	binary.LittleEndian.PutUint32(b[20:24], c.Flags)
	if c.Flags&ContextFlagDeleg != 0 {
		b = appendUint16LE(b, c.DelegationOption)
		b = appendUint16LE(b, uint16(len(c.Deleg)))
		b = append(b, c.Deleg...)
	}
	for _, extension := range c.Exts {
		b = appendUint32LE(b, extension.Type)
		b = appendUint32LE(b, uint32(len(extension.Data)))
		b = append(b, extension.Data...)
	}
	return b, nil
}

func appendUint16LE(b []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(b, encoded[:]...)
}

// Unmarshal decodes an RFC 4121 authenticator checksum.
func (c *AuthenticatorChecksum) Unmarshal(b []byte) error {
	if len(b) < 24 {
		return errors.New("authenticator checksum is shorter than 24 bytes")
	}
	if length := binary.LittleEndian.Uint32(b[0:4]); length != authenticatorChecksumBindingLength {
		return fmt.Errorf("authenticator checksum channel-binding length is %d, want 16", length)
	}
	copy(c.Bnd[:], b[4:20])
	c.Flags = binary.LittleEndian.Uint32(b[20:24])
	c.DelegationOption = 0
	c.Deleg = nil
	c.Exts = nil
	offset := 24
	if c.Flags&ContextFlagDeleg != 0 {
		if len(b)-offset < 4 {
			return errors.New("authenticator checksum delegation header is truncated")
		}
		c.DelegationOption = binary.LittleEndian.Uint16(b[offset : offset+2])
		length := int(binary.LittleEndian.Uint16(b[offset+2 : offset+4]))
		offset += 4
		if length > len(b)-offset {
			return errors.New("authenticator checksum delegated KRB-CRED is truncated")
		}
		c.Deleg = append([]byte(nil), b[offset:offset+length]...)
		offset += length
	}
	for offset < len(b) {
		if len(b)-offset < 8 {
			return errors.New("authenticator checksum extension header is truncated")
		}
		typeID := binary.LittleEndian.Uint32(b[offset : offset+4])
		length := int(binary.LittleEndian.Uint32(b[offset+4 : offset+8]))
		offset += 8
		if length > len(b)-offset {
			return errors.New("authenticator checksum extension data is truncated")
		}
		c.Exts = append(c.Exts, AuthenticatorChecksumExtension{Type: typeID, Data: append([]byte(nil), b[offset:offset+length]...)})
		offset += length
	}
	return nil
}
