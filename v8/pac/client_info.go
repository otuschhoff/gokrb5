package pac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/jcmturner/rpc/v2/mstypes"
)

const (
	clientInfoNameLengthOffset = 8
	clientInfoHeaderSize       = 10
	utf16CodeUnitSize          = 2
)

// ClientInfo is the PAC_CLIENT_INFO buffer defined by [MS-PAC].
//
// [MS-PAC]: https://msdn.microsoft.com/en-us/library/cc237951.aspx
type ClientInfo struct {
	ClientID   mstypes.FileTime // Authentication time of the initial TGT.
	NameLength uint16           // Byte length of the UTF-16LE name on the wire.
	Name       string           // Client account name.
}

// Unmarshal decodes a PAC_CLIENT_INFO buffer.
func (k *ClientInfo) Unmarshal(b []byte) error {
	if len(b) < clientInfoHeaderSize {
		return fmt.Errorf("%w: PAC_CLIENT_INFO is %d bytes, want at least %d", ErrPACMalformed, len(b), clientInfoHeaderSize)
	}
	k.ClientID.LowDateTime = binary.LittleEndian.Uint32(b[:4])
	k.ClientID.HighDateTime = binary.LittleEndian.Uint32(b[4:clientInfoNameLengthOffset])
	k.NameLength = binary.LittleEndian.Uint16(b[clientInfoNameLengthOffset:clientInfoHeaderSize])
	name := b[clientInfoHeaderSize:]
	if k.NameLength%utf16CodeUnitSize != 0 || len(name) != int(k.NameLength) {
		return fmt.Errorf("%w: invalid PAC_CLIENT_INFO name length %d", ErrPACMalformed, k.NameLength)
	}
	units := make([]uint16, len(name)/utf16CodeUnitSize)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(name[i*utf16CodeUnitSize:])
	}
	k.Name = string(utf16.Decode(units))
	return nil
}

// Marshal encodes the PAC_CLIENT_INFO buffer, deriving the wire length from Name.
func (k ClientInfo) Marshal() ([]byte, error) {
	units := utf16.Encode([]rune(k.Name))
	if len(units) > math.MaxUint16/utf16CodeUnitSize {
		return nil, errors.New("PAC_CLIENT_INFO name is too long")
	}
	nameBytes := len(units) * utf16CodeUnitSize
	length, err := pacUint16FromInt("PAC_CLIENT_INFO name length", nameBytes)
	if err != nil {
		return nil, err
	}
	b := make([]byte, clientInfoHeaderSize+nameBytes)
	binary.LittleEndian.PutUint32(b[:4], k.ClientID.LowDateTime)
	binary.LittleEndian.PutUint32(b[4:clientInfoNameLengthOffset], k.ClientID.HighDateTime)
	binary.LittleEndian.PutUint16(b[clientInfoNameLengthOffset:clientInfoHeaderSize], length)
	name := b[clientInfoHeaderSize:]
	for i, unit := range units {
		binary.LittleEndian.PutUint16(name[i*utf16CodeUnitSize:], unit)
	}
	return b, nil
}
