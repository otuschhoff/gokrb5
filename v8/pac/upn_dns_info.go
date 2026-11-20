package pac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/jcmturner/rpc/v2/mstypes"
)

// UPNDNSInfo implements https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPNDNSInfo struct {
	// UPNLength is the UPN field's length in bytes.
	UPNLength uint16
	// UPNOffset is the UPN field's byte offset from the start of the structure.
	UPNOffset           uint16
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

	upnDNSHeaderLength         = 12
	upnDNSExtendedHeaderLength = 20
	upnDNSFieldAlignment       = 8
)

// Unmarshal decodes a UPN_DNS_INFO buffer.
func (k *UPNDNSInfo) Unmarshal(b []byte) error {
	headerLength, err := k.readUPNDNSHeader(b)
	if err != nil {
		return err
	}
	if err = k.validateUPNDNSRanges(len(b), headerLength); err != nil {
		return err
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
		return k.decodeUPNDNSExtension(b)
	}
	return nil
}

// Marshal returns the UPN_DNS_INFO encoding.
func (k *UPNDNSInfo) Marshal() ([]byte, error) {
	upn := encodeUPNDNSString(k.UPN)
	domain := encodeUPNDNSString(k.DNSDomain)
	extended := k.Flags&UPNDNSInfoFlagExtended != 0
	sam := []byte(nil)
	sid := []byte(nil)
	headerLength := upnDNSHeaderLength
	if extended {
		headerLength = upnDNSExtendedHeaderLength
		sam = encodeUPNDNSString(k.SAMAccountName)
		if k.ObjectSID == nil {
			return nil, errors.New("extended UPN_DNS_INFO has no object SID")
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

func (k *UPNDNSInfo) decodeUPNDNSExtension(b []byte) error {
	var err error
	k.SAMAccountName, err = decodeUPNDNSString(b, k.SamNameOffset, k.SamNameLength, "SAM account name")
	if err != nil {
		return err
	}
	sidBytes := b[int(k.SIDOffset) : int(k.SIDOffset)+int(k.SIDLength)]
	var requestor Requestor
	if err := requestor.Unmarshal(sidBytes); err != nil {
		return fmt.Errorf("UPN_DNS_INFO SID: %w", err)
	}
	k.ObjectSID = &requestor.SID
	return nil
}

func (k *UPNDNSInfo) readUPNDNSHeader(b []byte) (uint16, error) {
	if len(b) < upnDNSHeaderLength {
		return 0, fmt.Errorf("%w: UPN_DNS_INFO is %d bytes, want at least %d",
			ErrPACMalformed, len(b), upnDNSHeaderLength)
	}
	k.UPNLength = binary.LittleEndian.Uint16(b[0:2])
	k.UPNOffset = binary.LittleEndian.Uint16(b[2:4])
	k.DNSDomainNameLength = binary.LittleEndian.Uint16(b[4:6])
	k.DNSDomainNameOffset = binary.LittleEndian.Uint16(b[6:8])
	k.Flags = binary.LittleEndian.Uint32(b[8:12])
	if k.Flags&UPNDNSInfoFlagExtended == 0 {
		k.SamNameLength, k.SamNameOffset, k.SIDLength, k.SIDOffset = 0, 0, 0, 0
		k.SAMAccountName, k.ObjectSID = "", nil
		return upnDNSHeaderLength, nil
	}
	if len(b) < upnDNSExtendedHeaderLength {
		return 0, fmt.Errorf("%w: extended UPN_DNS_INFO is %d bytes, want at least %d",
			ErrPACMalformed, len(b), upnDNSExtendedHeaderLength)
	}
	k.SamNameLength = binary.LittleEndian.Uint16(b[upnDNSHeaderLength:14])
	k.SamNameOffset = binary.LittleEndian.Uint16(b[14:16])
	k.SIDLength = binary.LittleEndian.Uint16(b[16:18])
	k.SIDOffset = binary.LittleEndian.Uint16(b[18:upnDNSExtendedHeaderLength])
	return upnDNSExtendedHeaderLength, nil
}

type upnDNSFieldRange struct {
	name           string
	offset, length uint16
}

func (r upnDNSFieldRange) end() int {
	return int(r.offset) + int(r.length)
}

func (r upnDNSFieldRange) overlaps(other upnDNSFieldRange) bool {
	return r.length != 0 && other.length != 0 && int(r.offset) < other.end() && int(other.offset) < r.end()
}

func (k *UPNDNSInfo) validateUPNDNSRanges(size int, headerLength uint16) error {
	fields := []upnDNSFieldRange{
		{name: "UPN", offset: k.UPNOffset, length: k.UPNLength},
		{name: "DNS domain", offset: k.DNSDomainNameOffset, length: k.DNSDomainNameLength},
	}
	if k.Flags&UPNDNSInfoFlagExtended != 0 {
		fields = append(fields,
			upnDNSFieldRange{name: "SAM account name", offset: k.SamNameOffset, length: k.SamNameLength},
			upnDNSFieldRange{name: "SID", offset: k.SIDOffset, length: k.SIDLength},
		)
	}
	for i, current := range fields {
		if current.offset < headerLength || current.end() > size {
			return fmt.Errorf("%w: UPN_DNS_INFO %s range is invalid", ErrPACMalformed, current.name)
		}
		for _, previous := range fields[:i] {
			if current.overlaps(previous) {
				return fmt.Errorf("%w: UPN_DNS_INFO %s overlaps %s", ErrPACMalformed, current.name, previous.name)
			}
		}
	}
	return nil
}

func upnDNSOffsets(headerLength int, fields [][]byte) ([]uint16, int, error) {
	offsets := make([]uint16, len(fields))
	size := alignUPNDNS(headerLength)
	for i, field := range fields {
		if len(field) > math.MaxUint16 || size > math.MaxUint16 || size+len(field) > math.MaxUint16 {
			return nil, 0, errors.New("UPN_DNS_INFO is too large")
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
	const fieldsPerHeaderPart = 2
	for i := 0; i < len(fields); i += fieldsPerHeaderPart {
		length, err := pacUint16FromInt("UPN_DNS_INFO field length", len(fields[i]))
		if err != nil {
			return err
		}
		base := 0
		if i == fieldsPerHeaderPart {
			base = upnDNSHeaderLength
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
	if length%utf16CodeUnitSize != 0 {
		return "", fmt.Errorf("%w: %s length %d is not valid UTF-16", ErrPACMalformed, name, length)
	}
	units := make([]uint16, int(length)/utf16CodeUnitSize)
	for i := range units {
		start := int(offset) + i*utf16CodeUnitSize
		units[i] = binary.LittleEndian.Uint16(b[start : start+utf16CodeUnitSize])
	}
	if !hasPairedUTF16Surrogates(units) {
		return "", fmt.Errorf("%w: %s contains an unpaired UTF-16 surrogate", ErrPACMalformed, name)
	}
	return string(utf16.Decode(units)), nil
}

func hasPairedUTF16Surrogates(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		if units[i] >= 0xd800 && units[i] <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return false
			}
			i++
		} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
			return false
		}
	}
	return true
}

func encodeUPNDNSString(value string) []byte {
	units := utf16.Encode([]rune(value))
	b := make([]byte, len(units)*utf16CodeUnitSize)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(b[i*utf16CodeUnitSize:], unit)
	}
	return b
}

func alignUPNDNS(value int) int {
	return (value + upnDNSFieldAlignment - 1) &^ (upnDNSFieldAlignment - 1)
}
