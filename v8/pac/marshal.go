package pac

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	pacAlignment  = 8
	maxPACBuffers = 4096
)

type pacBuffer struct {
	typeID uint32
	data   []byte
}

// SignOptions controls optional PAC signatures. TicketData must be the DER
// EncTicketPart encoded with the PAC authorization-data value replaced by one
// zero byte, as required by MS-PAC.
type SignOptions struct {
	IncludeFullChecksum bool
	TicketData          []byte
}

// Marshal rebuilds the PAC deterministically while preserving every buffer's
// payload. Simple Phase 4 buffers are re-encoded from their typed values.
func (pac *PACType) Marshal() ([]byte, error) {
	buffers, err := pac.marshalBuffers()
	if err != nil {
		return nil, err
	}
	return marshalPACBuffers(pac.Version, buffers)
}

func (pac *PACType) marshalBuffers() ([]pacBuffer, error) {
	if pac.Version != 0 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrPACMalformed, pac.Version)
	}
	if len(pac.Buffers) == 0 || len(pac.Buffers) > maxPACBuffers {
		return nil, fmt.Errorf("%w: invalid buffer count %d", ErrPACMalformed, len(pac.Buffers))
	}
	buffers := make([]pacBuffer, 0, len(pac.Buffers))
	seen := make(map[uint32]struct{}, len(pac.Buffers))
	for _, info := range pac.Buffers {
		if _, ok := seen[info.ULType]; ok {
			return nil, fmt.Errorf("%w: duplicate buffer type %d", ErrPACMalformed, info.ULType)
		}
		seen[info.ULType] = struct{}{}
		payload, err := pac.marshalBufferPayload(info)
		if err != nil {
			return nil, err
		}
		payload, err = pac.marshalBufferValue(info.ULType, payload)
		if err != nil {
			return nil, fmt.Errorf("marshal PAC buffer type %d: %w", info.ULType, err)
		}
		buffers = append(buffers, pacBuffer{typeID: info.ULType, data: payload})
	}
	return buffers, nil
}

func (pac *PACType) marshalBufferValue(typeID uint32, original []byte) ([]byte, error) {
	var typed []byte
	var err error
	switch typeID {
	case infoTypePACServerSignatureData:
		return marshalOptionalSignature(pac.ServerChecksum, original)
	case infoTypePACKDCSignatureData:
		return marshalOptionalSignature(pac.KDCChecksum, original)
	case infoTypePACTicketChecksum:
		return marshalOptionalSignature(pac.TicketChecksum, original)
	case infoTypePACFullChecksum:
		return marshalOptionalSignature(pac.FullChecksum, original)
	case infoTypePACAttributesInfo:
		if pac.AttributesInfo != nil {
			typed, err = pac.AttributesInfo.Marshal()
		}
	case infoTypePACRequestor:
		if pac.Requestor != nil {
			typed, err = pac.Requestor.Marshal()
		}
	case infoTypePACClientInfo:
		if pac.ClientInfo != nil {
			typed, err = pac.ClientInfo.Marshal()
		}
	case infoTypeUPNDNSInfo:
		if pac.UPNDNSInfo != nil {
			typed, err = pac.UPNDNSInfo.Marshal()
		}
	}
	if err != nil || typed != nil {
		return typed, err
	}
	return original, nil
}

func (pac *PACType) marshalBufferPayload(info InfoBuffer) ([]byte, error) {
	end := info.Offset + uint64(info.CBBufferSize)
	if end < info.Offset || end > uint64(len(pac.Data)) {
		return nil, fmt.Errorf("%w: buffer type %d is out of bounds", ErrPACMalformed, info.ULType)
	}
	start, err := pacIntFromUint64("buffer offset", info.Offset)
	if err != nil {
		return nil, err
	}
	stop, err := pacIntFromUint64("buffer end", end)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), pac.Data[start:stop]...), nil
}

func marshalOptionalSignature(signature *SignatureData, original []byte) ([]byte, error) {
	if signature == nil {
		return original, nil
	}
	return signature.Marshal()
}

func marshalPACBuffers(version uint32, buffers []pacBuffer) ([]byte, error) {
	headerSize := 8 + len(buffers)*16
	if headerSize < 0 {
		return nil, fmt.Errorf("%w: PAC header size overflows", ErrPACMalformed)
	}
	headerLength := uint64(headerSize) // #nosec G115 -- nonnegative checked above.
	offset := alignPAC(headerLength)
	for _, buffer := range buffers {
		if uint64(len(buffer.data)) > math.MaxUint32 || offset > math.MaxUint64-uint64(len(buffer.data))-pacAlignment+1 {
			return nil, fmt.Errorf("%w: PAC is too large", ErrPACMalformed)
		}
		offset = alignPAC(offset + uint64(len(buffer.data)))
		if offset > uint64(maxInt()) { // #nosec G115 -- maxInt is nonnegative.
			return nil, fmt.Errorf("%w: PAC is too large", ErrPACMalformed)
		}
	}
	allocation, err := pacIntFromUint64("PAC allocation", offset)
	if err != nil {
		return nil, err
	}
	data := make([]byte, allocation)
	bufferCount, err := pacUint32FromInt("buffer count", len(buffers))
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(data, bufferCount)
	binary.LittleEndian.PutUint32(data[4:], version)
	offset = alignPAC(headerLength)
	for i, buffer := range buffers {
		entry := 8 + i*16
		binary.LittleEndian.PutUint32(data[entry:], buffer.typeID)
		bufferLength, err := pacUint32FromInt("buffer length", len(buffer.data))
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(data[entry+4:], bufferLength)
		binary.LittleEndian.PutUint64(data[entry+8:], offset)
		bufferOffset, err := pacIntFromUint64("buffer offset", offset)
		if err != nil {
			return nil, err
		}
		copy(data[bufferOffset:], buffer.data)
		offset = alignPAC(offset + uint64(len(buffer.data)))
	}
	return data, nil
}

func alignPAC(value uint64) uint64 {
	return (value + pacAlignment - 1) &^ (pacAlignment - 1)
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

// Sign rebuilds and signs a PAC using the service and KDC keys.
func (pac *PACType) Sign(serverKey, kdcKey types.EncryptionKey, signOptions ...SignOptions) ([]byte, error) {
	if len(signOptions) > 1 {
		return nil, fmt.Errorf("Sign accepts at most one SignOptions value")
	}
	options := SignOptions{}
	if len(signOptions) == 1 {
		options = signOptions[0]
	}
	buffers, err := pac.marshalBuffers()
	if err != nil {
		return nil, err
	}
	serverType, err := checksumTypeForKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("server key: %w", err)
	}
	kdcType, err := checksumTypeForKey(kdcKey)
	if err != nil {
		return nil, fmt.Errorf("KDC key: %w", err)
	}
	buffers, err = setSignatureBuffer(buffers, infoTypePACServerSignatureData, serverType)
	if err != nil {
		return nil, err
	}
	buffers, err = setSignatureBuffer(buffers, infoTypePACKDCSignatureData, kdcType)
	if err != nil {
		return nil, err
	}
	includeFull := options.IncludeFullChecksum || findBuffer(buffers, infoTypePACFullChecksum) >= 0
	if includeFull {
		buffers, err = setSignatureBuffer(buffers, infoTypePACFullChecksum, kdcType)
		if err != nil {
			return nil, err
		}
	}
	if options.TicketData != nil {
		buffers, err = setSignatureBuffer(buffers, infoTypePACTicketChecksum, kdcType)
		if err != nil {
			return nil, err
		}
	}
	data, err := marshalPACBuffers(pac.Version, buffers)
	if err != nil {
		return nil, err
	}
	if options.TicketData != nil {
		if ierr := writeChecksum(data, buffers, infoTypePACTicketChecksum, kdcKey, options.TicketData); ierr != nil {
			return nil, ierr
		}
	}
	if includeFull {
		if ierr := writeChecksum(data, buffers, infoTypePACFullChecksum, kdcKey, data); ierr != nil {
			return nil, ierr
		}
	}
	if ierr := writeChecksum(data, buffers, infoTypePACServerSignatureData, serverKey, data); ierr != nil {
		return nil, ierr
	}
	serverSignature, err := signatureBytes(data, buffers, infoTypePACServerSignatureData)
	if err != nil {
		return nil, err
	}
	if err := writeChecksum(data, buffers, infoTypePACKDCSignatureData, kdcKey, serverSignature); err != nil {
		return nil, err
	}
	return data, nil
}

func checksumTypeForKey(key types.EncryptionKey) (uint32, error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return 0, err
	}
	if len(key.KeyValue) != etype.GetKeyByteSize() {
		return 0, fmt.Errorf("key length is %d, expected %d", len(key.KeyValue), etype.GetKeyByteSize())
	}
	return pacUint32FromInt32("checksum type", etype.GetHashID())
}

func setSignatureBuffer(buffers []pacBuffer, typeID, signatureType uint32) ([]pacBuffer, error) {
	length, err := signatureLength(signatureType)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 4+length)
	binary.LittleEndian.PutUint32(payload, signatureType)
	index := findBuffer(buffers, typeID)
	if index >= 0 {
		buffers[index].data = payload
		return buffers, nil
	}
	return append(buffers, pacBuffer{typeID: typeID, data: payload}), nil
}

func findBuffer(buffers []pacBuffer, typeID uint32) int {
	for i := range buffers {
		if buffers[i].typeID == typeID {
			return i
		}
	}
	return -1
}

func signatureBytes(data []byte, buffers []pacBuffer, typeID uint32) ([]byte, error) {
	index := findBuffer(buffers, typeID)
	if index < 0 {
		return nil, fmt.Errorf("PAC buffer type %d is missing", typeID)
	}
	header := 8 + index*16
	offset := binary.LittleEndian.Uint64(data[header+8:])
	length := binary.LittleEndian.Uint32(data[header+4:])
	start, err := pacIntFromUint64("signature offset", offset)
	if err != nil {
		return nil, err
	}
	lengthInt, err := pacUint32ToInt("signature length", length)
	if err != nil {
		return nil, err
	}
	if lengthInt < 4 || start > len(data)-lengthInt {
		return nil, fmt.Errorf("PAC signature range exceeds data")
	}
	return data[start+4 : start+lengthInt], nil
}

func writeChecksum(data []byte, buffers []pacBuffer, typeID uint32, key types.EncryptionKey, input []byte) error {
	signature, err := signatureBytes(data, buffers, typeID)
	if err != nil {
		return err
	}
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	checksum, err := etype.GetChecksumHash(key.KeyValue, input, keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		return err
	}
	if len(checksum) != len(signature) {
		return fmt.Errorf("checksum length is %d, expected %d", len(checksum), len(signature))
	}
	copy(signature, checksum)
	return nil
}
