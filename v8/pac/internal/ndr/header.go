package ndr

import (
	"encoding/binary"
	"fmt"
)

/*
Serialization Version 1
https://msdn.microsoft.com/en-us/library/cc243563.aspx

Common Header - https://msdn.microsoft.com/en-us/library/cc243890.aspx
8 bytes in total:
- First byte - Version: Must equal 1
- Second byte -  1st 4 bits: Endianess (0=Big; 1=Little); 2nd 4 bits: Character Encoding (0=ASCII; 1=EBCDIC)
- 3rd - Floating point representation (This does not seem to be the case in examples for Microsoft test sources)
- 4th - Common Header Length: Must equal 8
- 5th - 8th - Filler: MUST be set to 0xcccccccc on marshaling, and SHOULD be ignored during unmarshaling.

Private Header - https://msdn.microsoft.com/en-us/library/cc243919.aspx
8 bytes in total:
- First 4 bytes - The length of a serialized top-level type in the octet stream.
  It MUST include the padding length and exclude the header itself.
- Second 4 bytes - Filler: MUST be set to 0 (zero) during marshaling, and SHOULD be ignored during unmarshaling.
*/

const (
	protocolVersion   uint8  = 1
	commonHeaderBytes uint16 = 8
	headerFillerBytes        = 4
	headerNibbleBits         = 4
	headerNibbleMask         = 0xF
	bigEndian                = 0
	littleEndian             = 1
	ascii             uint8  = 0
	ebcdic            uint8  = 1
	ieee              uint8  = 0
	vax               uint8  = 1
	cray              uint8  = 2
	ibm               uint8  = 3
)

// CommonHeader implements the NDR common header: https://msdn.microsoft.com/en-us/library/cc243889.aspx
type CommonHeader struct {
	Version             uint8
	Endianness          binary.ByteOrder
	CharacterEncoding   uint8
	FloatRepresentation uint8
	HeaderLength        uint16
	Filler              []byte
}

// PrivateHeader implements the NDR private header: https://msdn.microsoft.com/en-us/library/cc243919.aspx
type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             []byte
}

func (dec *Decoder) readCommonHeader() error {
	// Version
	vb, err := dec.r.ReadByte()
	if err != nil {
		return Malformed{EText: "could not read first byte of common header for version", cause: err}
	}
	dec.ch.Version = vb
	if dec.ch.Version != protocolVersion {
		text := fmt.Sprintf("byte stream does not indicate a RPC Type serialization of version %v", protocolVersion)
		return Malformed{EText: text, cause: nil}
	}
	if encodingErr := dec.readCommonHeaderEncoding(); encodingErr != nil {
		return encodingErr
	}
	lb, err := dec.readBytes(SizeUint16)
	if err != nil {
		return Errorf("could not read common header length: %w", err)
	}
	dec.ch.HeaderLength = dec.ch.Endianness.Uint16(lb)
	if dec.ch.HeaderLength != commonHeaderBytes {
		return Malformed{EText: "common header does not indicate a valid length", cause: nil}
	}
	dec.ch.Filler, err = dec.readBytes(headerFillerBytes)
	if err != nil {
		return Errorf("could not read common header filler: %w", err)
	}
	return nil
}

func (dec *Decoder) readCommonHeaderEncoding() error {
	eb, err := dec.r.ReadByte()
	if err != nil {
		return Malformed{EText: "could not read second byte of common header for endianness", cause: err}
	}
	endian := eb >> headerNibbleBits
	if endian != bigEndian && endian != littleEndian {
		return Malformed{EText: "common header does not indicate a valid endianness", cause: nil}
	}
	dec.ch.CharacterEncoding = eb & headerNibbleMask
	if dec.ch.CharacterEncoding != ascii && dec.ch.CharacterEncoding != ebcdic {
		return Malformed{EText: "common header does not indicate a valid character encoding", cause: nil}
	}
	switch endian {
	case littleEndian:
		dec.ch.Endianness = binary.LittleEndian
	case bigEndian:
		dec.ch.Endianness = binary.BigEndian
	}
	return nil
}

func (dec *Decoder) readPrivateHeader() error {
	// The next 8 bytes after the common header comprise the RPC type marshalling private header for constructed types.
	err := binary.Read(dec.r, dec.ch.Endianness, &dec.ph.ObjectBufferLength)
	if err != nil {
		return Malformed{EText: "could not read private header object buffer length", cause: err}
	}
	if dec.ph.ObjectBufferLength%8 != 0 {
		return Malformed{EText: "object buffer length not a multiple of 8", cause: nil}
	}
	// Filler bytes
	dec.ph.Filler, err = dec.readBytes(headerFillerBytes)
	if err != nil {
		return Errorf("could not read private header filler: %w", err)
	}
	return nil
}
