package pac

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/jcmturner/rpc/v2/mstypes"
)

// ClientInfo implements https://msdn.microsoft.com/en-us/library/cc237951.aspx
type ClientInfo struct {
	ClientID   mstypes.FileTime // A FILETIME structure in little-endian format that contains the Kerberos initial ticket-granting ticket TGT authentication time
	NameLength uint16           // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the Name field.
	Name       string           // An array of 16-bit Unicode characters in little-endian format that contains the client's account name.
}

// Unmarshal bytes into the ClientInfo struct
func (k *ClientInfo) Unmarshal(b []byte) (err error) {
	if len(b) < 10 {
		return fmt.Errorf("%w: PAC_CLIENT_INFO is %d bytes, want at least 10", ErrPACMalformed, len(b))
	}
	k.ClientID.LowDateTime = binary.LittleEndian.Uint32(b[0:4])
	k.ClientID.HighDateTime = binary.LittleEndian.Uint32(b[4:8])
	k.NameLength = binary.LittleEndian.Uint16(b[8:10])
	if k.NameLength%2 != 0 || len(b) != 10+int(k.NameLength) {
		return fmt.Errorf("%w: invalid PAC_CLIENT_INFO name length %d", ErrPACMalformed, k.NameLength)
	}
	units := make([]uint16, int(k.NameLength)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[10+i*2:])
	}
	k.Name = string(utf16.Decode(units))
	return nil
}

// Marshal returns the PAC_CLIENT_INFO encoding.
func (k ClientInfo) Marshal() ([]byte, error) {
	units := utf16.Encode([]rune(k.Name))
	if len(units)*2 > math.MaxUint16 {
		return nil, fmt.Errorf("PAC_CLIENT_INFO name is too long")
	}
	b := make([]byte, 10+len(units)*2)
	binary.LittleEndian.PutUint32(b[0:4], k.ClientID.LowDateTime)
	binary.LittleEndian.PutUint32(b[4:8], k.ClientID.HighDateTime)
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(units)*2))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(b[10+i*2:], unit)
	}
	return b, nil
}
