package gssapi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	authenticatorChecksumBindingLength = 16
	authenticatorChecksumHeaderLen     = 4 + authenticatorChecksumBindingLength + 4
	delegationHeaderLen                = 2 + 2
	checksumExtensionHeaderLen         = 4 + 4
)

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
	var checksum AuthenticatorChecksum
	if bindings != nil {
		checksum.Bnd = bindings.MD5Hash()
	}
	for _, flag := range flags {
		if flag >= 0 && uint64(flag) <= uint64(^uint32(0)) {
			checksum.Flags |= uint32(flag) // #nosec G115 -- range checked above.
		}
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
	b := make([]byte, authenticatorChecksumHeaderLen, authenticatorChecksumHeaderLen+delegationHeaderLen+len(c.Deleg))
	binary.LittleEndian.PutUint32(b[0:4], authenticatorChecksumBindingLength)
	copy(b[4:20], c.Bnd[:])
	binary.LittleEndian.PutUint32(b[20:authenticatorChecksumHeaderLen], c.Flags)
	if c.Flags&ContextFlagDeleg != 0 {
		b = appendUint16LE(b, c.DelegationOption)
		delegLength, err := gssUint16Length("delegation", len(c.Deleg))
		if err != nil {
			return nil, err
		}
		b = appendUint16LE(b, delegLength)
		b = append(b, c.Deleg...)
	}
	for _, extension := range c.Exts {
		b = appendUint32LE(b, extension.Type)
		length, err := gssUint32Length("checksum extension", len(extension.Data))
		if err != nil {
			return nil, err
		}
		b = appendUint32LE(b, length)
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
	if len(b) < authenticatorChecksumHeaderLen {
		return errors.New("authenticator checksum is shorter than 24 bytes")
	}
	if length := binary.LittleEndian.Uint32(b[0:4]); length != authenticatorChecksumBindingLength {
		return fmt.Errorf("authenticator checksum channel-binding length is %d, want 16", length)
	}
	copy(c.Bnd[:], b[4:20])
	c.Flags = binary.LittleEndian.Uint32(b[20:authenticatorChecksumHeaderLen])
	c.DelegationOption = 0
	c.Deleg = nil
	c.Exts = nil
	offset := authenticatorChecksumHeaderLen
	if c.Flags&ContextFlagDeleg != 0 {
		if len(b)-offset < delegationHeaderLen {
			return errors.New("authenticator checksum delegation header is truncated")
		}
		c.DelegationOption = binary.LittleEndian.Uint16(b[offset : offset+2])
		length := int(binary.LittleEndian.Uint16(b[offset+2 : offset+delegationHeaderLen]))
		offset += delegationHeaderLen
		if length > len(b)-offset {
			return errors.New("authenticator checksum delegated KRB-CRED is truncated")
		}
		c.Deleg = append([]byte(nil), b[offset:offset+length]...)
		offset += length
	}
	for offset < len(b) {
		if len(b)-offset < checksumExtensionHeaderLen {
			return errors.New("authenticator checksum extension header is truncated")
		}
		typeID := binary.LittleEndian.Uint32(b[offset : offset+4])
		length := int(binary.LittleEndian.Uint32(b[offset+4 : offset+checksumExtensionHeaderLen]))
		offset += checksumExtensionHeaderLen
		if length > len(b)-offset {
			return errors.New("authenticator checksum extension data is truncated")
		}
		c.Exts = append(c.Exts, AuthenticatorChecksumExtension{
			Type: typeID,
			Data: append([]byte(nil), b[offset:offset+length]...),
		})
		offset += length
	}
	return nil
}
