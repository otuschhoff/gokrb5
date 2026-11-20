package pac

import (
	"encoding/binary"
	"fmt"
)

const (
	// PACWasRequested indicates the PAC was requested when the ticket was issued (MS-PAC 2.10).
	PACWasRequested uint32 = 1 << 0
	// PACWasGivenImplicitly indicates the PAC was included without being requested (MS-PAC 2.10).
	PACWasGivenImplicitly uint32 = 1 << 1
	pacAttributesFlagBits uint32 = 2
	pacAttributesLength          = 8
)

// AttributesInfo describes how the PAC was requested by the client.
type AttributesInfo struct {
	FlagsLength uint32
	Flags       uint32
}

// Unmarshal decodes a PAC_ATTRIBUTES_INFO buffer.
func (a *AttributesInfo) Unmarshal(b []byte) error {
	if len(b) != pacAttributesLength {
		return fmt.Errorf("%w: PAC_ATTRIBUTES_INFO is %d bytes, want 8", ErrPACMalformed, len(b))
	}
	a.FlagsLength = binary.LittleEndian.Uint32(b[0:4])
	if a.FlagsLength != pacAttributesFlagBits {
		return fmt.Errorf("%w: PAC_ATTRIBUTES_INFO flags length is %d, want 2", ErrPACMalformed, a.FlagsLength)
	}
	a.Flags = binary.LittleEndian.Uint32(b[4:8])
	if a.Flags & ^(PACWasRequested|PACWasGivenImplicitly) != 0 {
		return fmt.Errorf("%w: PAC_ATTRIBUTES_INFO contains unknown flags %#x", ErrPACMalformed, a.Flags)
	}
	return nil
}

// Marshal encodes a PAC_ATTRIBUTES_INFO buffer.
func (a AttributesInfo) Marshal() ([]byte, error) {
	if a.FlagsLength == 0 {
		a.FlagsLength = pacAttributesFlagBits
	}
	if a.FlagsLength != pacAttributesFlagBits {
		return nil, fmt.Errorf("PAC_ATTRIBUTES_INFO flags length is %d, want 2", a.FlagsLength)
	}
	if a.Flags & ^(PACWasRequested|PACWasGivenImplicitly) != 0 {
		return nil, fmt.Errorf("PAC_ATTRIBUTES_INFO contains unknown flags %#x", a.Flags)
	}
	b := make([]byte, pacAttributesLength)
	binary.LittleEndian.PutUint32(b[0:4], a.FlagsLength)
	binary.LittleEndian.PutUint32(b[4:8], a.Flags)
	return b, nil
}
