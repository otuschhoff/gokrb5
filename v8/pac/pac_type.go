package pac

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/jcmturner/rpc/v2/mstypes"
)

// ErrPACMalformed indicates that a PAC has an invalid buffer table or range.
var ErrPACMalformed = errors.New("PAC is malformed")

func copyPACRange(data []byte, offset, size uint64) ([]byte, error) {
	end := offset + size
	if end < offset {
		return nil, fmt.Errorf("%w: range at %d with size %d overflows", ErrPACMalformed, offset, size)
	}
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("%w: range [%d:%d] exceeds data size %d", ErrPACMalformed, offset, end, len(data))
	}
	return append([]byte(nil), data[int(offset):int(end)]...), nil
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
	ZeroSigData        []byte
}

// InfoBuffer implements the PAC Info Buffer: https://msdn.microsoft.com/en-us/library/cc237954.aspx
type InfoBuffer struct {
	ULType       uint32 // A 32-bit unsigned integer in little-endian format that describes the type of data present in the buffer contained at Offset.
	CBBufferSize uint32 // A 32-bit unsigned integer in little-endian format that contains the size, in bytes, of the buffer in the PAC located at Offset.
	Offset       uint64 // A 64-bit unsigned integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the PACTYPE structure. The data offset MUST be a multiple of eight. The following sections specify the format of each type of element.
}

// Unmarshal bytes into the PACType struct
func (pac *PACType) Unmarshal(b []byte) (err error) {
	if len(b) < 8 {
		return fmt.Errorf("%w: header is %d bytes, want at least 8", ErrPACMalformed, len(b))
	}
	pac.Data = b
	zb := make([]byte, len(b))
	copy(zb, b)
	pac.ZeroSigData = zb
	r := mstypes.NewReader(bytes.NewReader(b))
	pac.CBuffers, err = r.Uint32()
	if err != nil {
		return
	}
	pac.Version, err = r.Uint32()
	if err != nil {
		return
	}
	maxBuffers := uint32((len(b) - 8) / 16)
	if pac.CBuffers > maxBuffers {
		return fmt.Errorf("%w: buffer count %d exceeds table capacity %d", ErrPACMalformed, pac.CBuffers, maxBuffers)
	}
	buf := make([]InfoBuffer, int(pac.CBuffers))
	for i := range buf {
		buf[i].ULType, err = r.Uint32()
		if err != nil {
			return
		}
		buf[i].CBBufferSize, err = r.Uint32()
		if err != nil {
			return
		}
		buf[i].Offset, err = r.Uint64()
		if err != nil {
			return
		}
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
	if err := pac.validateInfoBuffers(); err != nil {
		return err
	}
	for _, buf := range pac.Buffers {
		p, err := copyPACRange(pac.Data, buf.Offset, uint64(buf.CBBufferSize))
		if err != nil {
			return err
		}
		switch buf.ULType {
		case infoTypeKerbValidationInfo:
			if pac.KerbValidationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k KerbValidationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing KerbValidationInfo: %v", err)
			}
			pac.KerbValidationInfo = &k
		case infoTypeCredentials:
			// Currently PAC parsing is only useful on the service side in gokrb5
			// The CredentialsInfo are only useful when gokrb5 has implemented RFC4556 and only applied on the client side.
			// Skipping CredentialsInfo - will be revisited under RFC4556 implementation.
			continue
			//if pac.CredentialsInfo != nil {
			//	//Must ignore subsequent buffers of this type
			//	continue
			//}
			//var k CredentialsInfo
			//err := k.Unmarshal(p, key) // The encryption key used is the AS reply key only available to the client.
			//if err != nil {
			//	return fmt.Errorf("error processing CredentialsInfo: %v", err)
			//}
			//pac.CredentialsInfo = &k
		case infoTypePACServerSignatureData:
			if pac.ServerChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("error processing ServerChecksum: %v", err)
			}
			pac.ServerChecksum = &k
		case infoTypePACKDCSignatureData:
			if pac.KDCChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("error processing KDCChecksum: %v", err)
			}
			pac.KDCChecksum = &k
		case infoTypePACClientInfo:
			if pac.ClientInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing ClientInfo: %v", err)
			}
			pac.ClientInfo = &k
		case infoTypeS4UDelegationInfo:
			if pac.S4UDelegationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k S4UDelegationInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process S4U_DelegationInfo: %v", err)
				continue
			}
			pac.S4UDelegationInfo = &k
		case infoTypeUPNDNSInfo:
			if pac.UPNDNSInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k UPNDNSInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process UPN_DNSInfo: %v", err)
				continue
			}
			pac.UPNDNSInfo = &k
		case infoTypePACClientClaimsInfo:
			if pac.ClientClaimsInfo != nil || len(p) < 1 {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process ClientClaimsInfo: %v", err)
				continue
			}
			pac.ClientClaimsInfo = &k
		case infoTypePACDeviceInfo:
			if pac.DeviceInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceInfo: %v", err)
				continue
			}
			pac.DeviceInfo = &k
		case infoTypePACDeviceClaimsInfo:
			if pac.DeviceClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceClaimsInfo: %v", err)
				continue
			}
			pac.DeviceClaimsInfo = &k
		}
	}

	if ok, err := pac.verify(key); !ok {
		return err
	}

	return nil
}

func (pac *PACType) verify(key types.EncryptionKey) (bool, error) {
	if pac.KerbValidationInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}
	if pac.ServerChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}
	if pac.KDCChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}
	if pac.ClientInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a ClientInfo")
	}
	etype, err := crypto.GetChksumEtype(int32(pac.ServerChecksum.SignatureType))
	if err != nil {
		return false, err
	}
	if ok := etype.VerifyChecksum(key.KeyValue,
		pac.ZeroSigData,
		pac.ServerChecksum.Signature,
		keyusage.KERB_NON_KERB_CKSUM_SALT); !ok {
		return false, errors.New("PAC service checksum verification failed")
	}

	return true, nil
}
