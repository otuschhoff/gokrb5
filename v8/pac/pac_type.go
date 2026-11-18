package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"

	"github.com/otuschhoff/gokrb5/v8/types"
)

// ErrPACMalformed indicates that a PAC has an invalid buffer table or range.
var ErrPACMalformed = errors.New("PAC is malformed")

func pacUint32FromInt(name string, value int) (uint32, error) {
	if value < 0 || uint64(value) > uint64(math.MaxUint32) { // #nosec G115 -- nonnegative branch required before conversion is checked.
		return 0, fmt.Errorf("%w: %s %d exceeds uint32 range", ErrPACMalformed, name, value)
	}
	return uint32(value), nil // #nosec G115 -- bounded above by MaxUint32.
}

func pacUint32FromInt32(name string, value int32) (uint32, error) {
	if value < 0 {
		return 0, fmt.Errorf("%w: %s %d cannot be negative", ErrPACMalformed, name, value)
	}
	return uint32(value), nil // #nosec G115 -- nonnegative checked above.
}

func pacUint16FromInt(name string, value int) (uint16, error) {
	if value < 0 || value > math.MaxUint16 {
		return 0, fmt.Errorf("%w: %s %d exceeds uint16 range", ErrPACMalformed, name, value)
	}
	return uint16(value), nil // #nosec G115 -- bounded above by MaxUint16.
}

func pacUint32ToInt32(name string, value uint32) (int32, error) {
	if value > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %s %d exceeds int32 range", ErrPACMalformed, name, value)
	}
	return int32(value), nil // #nosec G115 -- bounded by MaxInt32 above.
}

func pacUint32ToInt(name string, value uint32) (int, error) {
	if uint64(value) > uint64(maxInt()) { // #nosec G115 -- nonnegative platform int bound.
		return 0, fmt.Errorf("%w: %s %d exceeds platform int range", ErrPACMalformed, name, value)
	}
	return int(value), nil // #nosec G115 -- bounded by platform max int above.
}

func pacIntFromUint64(name string, value uint64) (int, error) {
	if value > uint64(maxInt()) { // #nosec G115 -- maxInt is nonnegative.
		return 0, fmt.Errorf("%w: %s %d exceeds platform int range", ErrPACMalformed, name, value)
	}
	return int(value), nil // #nosec G115 -- bounded above by platform max int.
}

func copyPACRange(data []byte, offset, size uint64) ([]byte, error) {
	end := offset + size
	if end < offset {
		return nil, fmt.Errorf("%w: range at %d with size %d overflows", ErrPACMalformed, offset, size)
	}
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("%w: range [%d:%d] exceeds data size %d", ErrPACMalformed, offset, end, len(data))
	}
	start, err := pacIntFromUint64("range offset", offset)
	if err != nil {
		return nil, err
	}
	stop, err := pacIntFromUint64("range end", end)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), data[start:stop]...), nil
}

const (
	infoTypeKerbValidationInfo     uint32 = 1
	infoTypeCredentials            uint32 = 2
	infoTypePACServerSignatureData uint32 = 6
	infoTypePACKDCSignatureData    uint32 = 7
	infoTypePACClientInfo          uint32 = 10
	infoTypeS4UDelegationInfo      uint32 = 11
	infoTypeUPNDNSInfo             uint32 = 12
	infoTypePACClientClaimsInfo    uint32 = 13
	infoTypePACDeviceInfo          uint32 = 14
	infoTypePACDeviceClaimsInfo    uint32 = 15
	infoTypePACTicketChecksum      uint32 = 16
	infoTypePACAttributesInfo      uint32 = 17
	infoTypePACRequestor           uint32 = 18
	infoTypePACFullChecksum        uint32 = 19
)

// PACType implements: https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers           uint32
	Version            uint32
	Buffers            []InfoBuffer
	Data               []byte
	KerbValidationInfo *KerbValidationInfo
	CredentialsInfo    *CredentialsInfo
	ServerChecksum     *SignatureData
	KDCChecksum        *SignatureData
	ClientInfo         *ClientInfo
	S4UDelegationInfo  *S4UDelegationInfo
	UPNDNSInfo         *UPNDNSInfo
	ClientClaimsInfo   *ClientClaimsInfo
	DeviceInfo         *DeviceInfo
	DeviceClaimsInfo   *DeviceClaimsInfo
	TicketChecksum     *SignatureData
	AttributesInfo     *AttributesInfo
	Requestor          *Requestor
	FullChecksum       *SignatureData
	ZeroSigData        []byte
}

// InfoBuffer implements the PAC Info Buffer: https://msdn.microsoft.com/en-us/library/cc237954.aspx
type InfoBuffer struct {
	ULType       uint32 // A 32-bit unsigned integer in little-endian format that describes the type of data present in the buffer contained at Offset.
	CBBufferSize uint32 // A 32-bit unsigned integer in little-endian format that contains the size, in bytes, of the buffer in the PAC located at Offset.
	Offset       uint64 // A 64-bit unsigned integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the PACTYPE structure. The data offset MUST be a multiple of eight. The following sections specify the format of each type of element.
}

// Unmarshal bytes into the PACType struct
func (pac *PACType) Unmarshal(b []byte) error {
	if len(b) < 8 {
		return fmt.Errorf("%w: header is %d bytes, want at least 8", ErrPACMalformed, len(b))
	}
	pac.Data = b
	pac.ZeroSigData = bytes.Clone(b)
	pac.CBuffers = binary.LittleEndian.Uint32(b[:4])
	pac.Version = binary.LittleEndian.Uint32(b[4:8])
	if pac.Version != 0 {
		return fmt.Errorf("%w: unsupported version %d", ErrPACMalformed, pac.Version)
	}
	maxBuffers, err := pacUint32FromInt("table capacity", (len(b)-8)/16)
	if err != nil {
		return err
	}
	if pac.CBuffers > maxBuffers {
		return fmt.Errorf("%w: buffer count %d exceeds table capacity %d", ErrPACMalformed, pac.CBuffers, maxBuffers)
	}
	buf := make([]InfoBuffer, int(pac.CBuffers))
	if _, err := binary.Decode(b[8:], binary.LittleEndian, buf); err != nil {
		return fmt.Errorf("%w: decode buffer table: %w", ErrPACMalformed, err)
	}
	pac.Buffers = buf
	return nil
}

func (pac *PACType) validateInfoBuffers() error {
	if uint64(pac.CBuffers) != uint64(len(pac.Buffers)) {
		return fmt.Errorf("%w: declared buffer count %d does not match table length %d", ErrPACMalformed, pac.CBuffers, len(pac.Buffers))
	}
	headerEnd := uint64(8) + uint64(len(pac.Buffers))*16
	if headerEnd > uint64(len(pac.Data)) {
		return fmt.Errorf("%w: buffer table ends at %d beyond PAC size %d", ErrPACMalformed, headerEnd, len(pac.Data))
	}
	for i, buf := range pac.Buffers {
		if buf.Offset%8 != 0 {
			return fmt.Errorf("%w: buffer %d offset %d is not 8-byte aligned", ErrPACMalformed, i, buf.Offset)
		}
		end := buf.Offset + uint64(buf.CBBufferSize)
		if end < buf.Offset {
			return fmt.Errorf("%w: buffer %d range overflows", ErrPACMalformed, i)
		}
		if buf.Offset < headerEnd {
			return fmt.Errorf("%w: buffer %d starts at %d inside header ending at %d", ErrPACMalformed, i, buf.Offset, headerEnd)
		}
		if end > uint64(len(pac.Data)) {
			return fmt.Errorf("%w: buffer %d ends at %d beyond PAC size %d", ErrPACMalformed, i, end, len(pac.Data))
		}
		if buf.CBBufferSize == 0 {
			continue
		}
		for j := 0; j < i; j++ {
			other := pac.Buffers[j]
			if other.CBBufferSize == 0 {
				continue
			}
			otherEnd := other.Offset + uint64(other.CBBufferSize)
			if buf.Offset < otherEnd && other.Offset < end {
				return fmt.Errorf("%w: buffers %d and %d overlap", ErrPACMalformed, j, i)
			}
		}
	}
	return nil
}

// ProcessPACInfoBuffers processes the PAC Info Buffers.
// https://msdn.microsoft.com/en-us/library/cc237954.aspx
func (pac *PACType) ProcessPACInfoBuffers(key types.EncryptionKey, l *log.Logger) error {
	return pac.ProcessPACInfoBuffersWithCredentialKey(key, types.EncryptionKey{}, l)
}

// ProcessPACInfoBuffersWithCredentialKey processes PAC buffers and decrypts
// PAC_CREDENTIAL_INFO with the PKINIT AS reply key when one is provided.
func (pac *PACType) ProcessPACInfoBuffersWithCredentialKey(key, credentialKey types.EncryptionKey, _ *log.Logger) error {
	if err := pac.validateInfoBuffers(); err != nil {
		return err
	}
	pac.resetInfoBuffers()
	pac.ZeroSigData = append(pac.ZeroSigData[:0], pac.Data...)
	seenKnown := make(map[uint32]struct{})
	for _, buf := range pac.Buffers {
		if isKnownPACBuffer(buf.ULType) {
			if _, ok := seenKnown[buf.ULType]; ok {
				return fmt.Errorf("%w: duplicate buffer type %d", ErrPACMalformed, buf.ULType)
			}
			seenKnown[buf.ULType] = struct{}{}
		}
		p, err := copyPACRange(pac.Data, buf.Offset, uint64(buf.CBBufferSize))
		if err != nil {
			return err
		}
		if err := pac.processInfoBuffer(buf, p, credentialKey); err != nil {
			return err
		}
	}

	if ok, err := pac.verify(key); !ok {
		return err
	}

	return nil
}

func (pac *PACType) resetInfoBuffers() {
	pac.KerbValidationInfo = nil
	pac.CredentialsInfo = nil
	pac.ServerChecksum = nil
	pac.KDCChecksum = nil
	pac.ClientInfo = nil
	pac.S4UDelegationInfo = nil
	pac.UPNDNSInfo = nil
	pac.ClientClaimsInfo = nil
	pac.DeviceInfo = nil
	pac.DeviceClaimsInfo = nil
	pac.TicketChecksum = nil
	pac.AttributesInfo = nil
	pac.Requestor = nil
	pac.FullChecksum = nil
}

func (pac *PACType) verify(key types.EncryptionKey) (bool, error) {
	if err := pac.Verify(key, VerifyOptions{}); err != nil {
		return false, err
	}
	return true, nil
}

func isKnownPACBuffer(typeID uint32) bool {
	switch typeID {
	case infoTypeKerbValidationInfo, infoTypeCredentials, infoTypePACServerSignatureData,
		infoTypePACKDCSignatureData, infoTypePACClientInfo, infoTypeS4UDelegationInfo,
		infoTypeUPNDNSInfo, infoTypePACClientClaimsInfo, infoTypePACDeviceInfo,
		infoTypePACDeviceClaimsInfo, infoTypePACTicketChecksum, infoTypePACAttributesInfo,
		infoTypePACRequestor, infoTypePACFullChecksum:
		return true
	default:
		return false
	}
}
