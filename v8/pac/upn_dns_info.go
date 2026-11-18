package pac

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/jcmturner/rpc/v2/mstypes"
)

// UPNDNSInfo implements https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPNDNSInfo struct {
	UPNLength           uint16 // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           uint16 // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
	SamNameLength       uint16
	SamNameOffset       uint16
	SIDLength           uint16
	SIDOffset           uint16
	UPN                 string
	DNSDomain           string
	SAMAccountName      string
	ObjectSID           *mstypes.RPCSID
}

const (
	// UPNDNSInfoFlagNoUPNAttribute indicates the UPN_DNS_INFO buffer carries no UPN attribute (MS-KILE 2.2.4).
	UPNDNSInfoFlagNoUPNAttribute uint32 = 1 << 0
	// UPNDNSInfoFlagExtended indicates the UPN_DNS_INFO buffer carries the extended form (MS-KILE 2.2.4).
	UPNDNSInfoFlagExtended uint32 = 1 << 1
)

// Unmarshal bytes into the UPN_DNSInfo struct
func (k *UPNDNSInfo) Unmarshal(b []byte) error {
	var err error
	if len(b) < 12 {
		return fmt.Errorf("%w: UPN_DNS_INFO is %d bytes, want at least 12", ErrPACMalformed, len(b))
	}
	k.UPNLength = binary.LittleEndian.Uint16(b[0:2])
	k.UPNOffset = binary.LittleEndian.Uint16(b[2:4])
	k.DNSDomainNameLength = binary.LittleEndian.Uint16(b[4:6])
	k.DNSDomainNameOffset = binary.LittleEndian.Uint16(b[6:8])
	k.Flags = binary.LittleEndian.Uint32(b[8:12])
	headerLength := uint16(12)
	if k.Flags&UPNDNSInfoFlagExtended != 0 {
		if len(b) < 20 {
			return fmt.Errorf("%w: extended UPN_DNS_INFO is %d bytes, want at least 20", ErrPACMalformed, len(b))
		}
		headerLength = 20
		k.SamNameLength = binary.LittleEndian.Uint16(b[12:14])
		k.SamNameOffset = binary.LittleEndian.Uint16(b[14:16])
		k.SIDLength = binary.LittleEndian.Uint16(b[16:18])
		k.SIDOffset = binary.LittleEndian.Uint16(b[18:20])
	} else {
		k.SamNameLength, k.SamNameOffset, k.SIDLength, k.SIDOffset = 0, 0, 0, 0
		k.SAMAccountName, k.ObjectSID = "", nil
	}
	type field struct {
		name           string
		offset, length uint16
	}
	fields := []field{{"UPN", k.UPNOffset, k.UPNLength}, {"DNS domain", k.DNSDomainNameOffset, k.DNSDomainNameLength}}
	if k.Flags&UPNDNSInfoFlagExtended != 0 {
		fields = append(fields, field{"SAM account name", k.SamNameOffset, k.SamNameLength}, field{"SID", k.SIDOffset, k.SIDLength})
	}
	for i, current := range fields {
		if current.offset < headerLength || int(current.offset)+int(current.length) > len(b) {
			return fmt.Errorf("%w: UPN_DNS_INFO %s range is invalid", ErrPACMalformed, current.name)
		}
		for _, previous := range fields[:i] {
			currentStart, currentEnd := int(current.offset), int(current.offset)+int(current.length)
			previousStart, previousEnd := int(previous.offset), int(previous.offset)+int(previous.length)
			if current.length != 0 && previous.length != 0 && currentStart < previousEnd && previousStart < currentEnd {
				return fmt.Errorf("%w: UPN_DNS_INFO %s overlaps %s", ErrPACMalformed, current.name, previous.name)
			}
		}
	}
	k.UPN, err = decodeUPNDNSString(b, k.UPNOffset, k.UPNLength, "UPN")
	if err != nil {
		return err
	}
	k.DNSDomain, err = decodeUPNDNSString(b, k.DNSDomainNameOffset, k.DNSDomainNameLength, "DNS domain")
	if err != nil {
		return err
	}
	if k.Flags&UPNDNSInfoFlagExtended != 0 {
		k.SAMAccountName, err = decodeUPNDNSString(b, k.SamNameOffset, k.SamNameLength, "SAM account name")
		if err != nil {
			return err
		}
		sidBytes := b[int(k.SIDOffset) : int(k.SIDOffset)+int(k.SIDLength)]
		var requestor Requestor
		if ierr := requestor.Unmarshal(sidBytes); ierr != nil {
			return fmt.Errorf("UPN_DNS_INFO SID: %w", ierr)
		}
		k.ObjectSID = &requestor.SID
	}
	return err
}

// Marshal returns the UPN_DNS_INFO encoding.
func (k *UPNDNSInfo) Marshal() ([]byte, error) {
	upn := encodeUPNDNSString(k.UPN)
	domain := encodeUPNDNSString(k.DNSDomain)
	extended := k.Flags&UPNDNSInfoFlagExtended != 0
	sam := []byte(nil)
	sid := []byte(nil)
	headerLength := 12
	if extended {
		headerLength = 20
		sam = encodeUPNDNSString(k.SAMAccountName)
		if k.ObjectSID == nil {
			return nil, fmt.Errorf("extended UPN_DNS_INFO has no object SID")
		}
		var err error
		sid, err = (Requestor{SID: *k.ObjectSID}).Marshal()
		if err != nil {
			return nil, fmt.Errorf("UPN_DNS_INFO SID: %w", err)
		}
	}
	fields := [][]byte{upn, domain}
	if extended {
		fields = append(fields, sam, sid)
	}
	offsets, size, err := upnDNSOffsets(headerLength, fields)
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)
	if err := writeUPNDNSHeader(b, k.Flags, fields, offsets); err != nil {
		return nil, err
	}
	for i, field := range fields {
		copy(b[int(offsets[i]):], field)
	}
	return b, nil
}

func upnDNSOffsets(headerLength int, fields [][]byte) ([]uint16, int, error) {
	offsets := make([]uint16, len(fields))
	size := alignUPNDNS(headerLength)
	for i, field := range fields {
		if len(field) > math.MaxUint16 || size > math.MaxUint16 || size+len(field) > math.MaxUint16 {
			return nil, 0, fmt.Errorf("UPN_DNS_INFO is too large")
		}
		offset, err := pacUint16FromInt("UPN_DNS_INFO offset", size)
		if err != nil {
			return nil, 0, err
		}
		offsets[i] = offset
		size = alignUPNDNS(size + len(field))
	}
	return offsets, size, nil
}

func writeUPNDNSHeader(b []byte, flags uint32, fields [][]byte, offsets []uint16) error {
	for i := 0; i < len(fields); i += 2 {
		length, err := pacUint16FromInt("UPN_DNS_INFO field length", len(fields[i]))
		if err != nil {
			return err
		}
		base := 0
		if i == 2 {
			base = 12
		}
		binary.LittleEndian.PutUint16(b[base:base+2], length)
		binary.LittleEndian.PutUint16(b[base+2:base+4], offsets[i])
		if i+1 < len(fields) {
			length, err = pacUint16FromInt("UPN_DNS_INFO field length", len(fields[i+1]))
			if err != nil {
				return err
			}
			binary.LittleEndian.PutUint16(b[base+4:base+6], length)
			binary.LittleEndian.PutUint16(b[base+6:base+8], offsets[i+1])
		}
	}
	binary.LittleEndian.PutUint32(b[8:12], flags)
	return nil
}

func decodeUPNDNSString(b []byte, offset, length uint16, name string) (string, error) {
	if length%2 != 0 {
		return "", fmt.Errorf("%w: %s length %d is not valid UTF-16", ErrPACMalformed, name, length)
	}
	units := make([]uint16, int(length)/2)
	for i := range units {
		start := int(offset) + i*2
		units[i] = binary.LittleEndian.Uint16(b[start : start+2])
	}
	for i := 0; i < len(units); i++ {
		if units[i] >= 0xd800 && units[i] <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: %s contains an unpaired UTF-16 surrogate", ErrPACMalformed, name)
			}
			i++
		} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
			return "", fmt.Errorf("%w: %s contains an unpaired UTF-16 surrogate", ErrPACMalformed, name)
		}
	}
	return string(utf16.Decode(units)), nil
}

func encodeUPNDNSString(value string) []byte {
	units := utf16.Encode([]rune(value))
	b := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(b[i*2:], unit)
	}
	return b
}

func alignUPNDNS(value int) int {
	return (value + 7) &^ 7
}
