package ndr

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// TestCommonHeaderCharacterization pins accepted byte-order/character-encoding
// combinations, metadata publication, and malformed header rejections.
func TestCommonHeaderCharacterization(t *testing.T) {
	for name, test := range map[string]struct {
		flags    byte
		length   uint16
		order    binary.ByteOrder
		encoding uint8
		wantErr  string
	}{
		"big endian ASCII":      {0x00, 8, binary.BigEndian, ascii, ""},
		"little endian ASCII":   {0x10, 8, binary.LittleEndian, ascii, ""},
		"big endian EBCDIC":     {0x01, 8, binary.BigEndian, ebcdic, ""},
		"little endian EBCDIC":  {0x11, 8, binary.LittleEndian, ebcdic, ""},
		"invalid endianness":    {0x20, 8, nil, 0, "common header does not indicate a valid endianness"},
		"invalid encoding":      {0x02, 8, nil, 0, "common header does not indicate a valid character encoding"},
		"invalid header length": {0x10, 7, binary.LittleEndian, ascii, "common header does not indicate a valid length"},
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte{protocolVersion, test.flags, 0, 0, 0, 0, 0, 0}
			binary.ByteOrder(binary.BigEndian).PutUint16(b[2:4], test.length)
			if test.order == binary.LittleEndian {
				binary.LittleEndian.PutUint16(b[2:4], test.length)
			}
			dec := NewDecoder(bytes.NewReader(b))
			err := dec.readCommonHeader()
			if test.wantErr != "" {
				if err == nil || err.Error() == "" || !bytes.Contains([]byte(err.Error()), []byte(test.wantErr)) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if dec.ch.Version != protocolVersion || dec.ch.Endianness != test.order || dec.ch.CharacterEncoding != test.encoding {
				t.Fatalf("header = %+v", dec.ch)
			}
		})
	}
}

func TestCommonHeaderReadFailures(t *testing.T) {
	for name, body := range map[string][]byte{
		"missing version": nil,
		"missing flags":   {protocolVersion},
		"short length":    {protocolVersion, 0x10, 0, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(bytes.NewReader(body))
			if err := dec.readCommonHeader(); err == nil {
				t.Fatal("truncated header was accepted")
			}
		})
	}
}

func TestMultidimensionalVaryingArrayCharacterization(t *testing.T) {
	body := append(littleEndianWords(1, 1, 0, 2), littleEndianWords(10, 20)...)
	dec := NewDecoder(bytes.NewReader(body))
	dec.ch.Endianness = binary.LittleEndian
	var got [][]uint32
	var deferred []deferedPtr
	if err := dec.fillMultiDimensionalVaryingArray(reflect.ValueOf(&got).Elem(), 2, "", &deferred); err != nil {
		t.Fatal(err)
	}
	want := [][]uint32{{0, 0}, {10, 20}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded = %#v, want %#v", got, want)
	}
}

func TestMultidimensionalVaryingArrayErrors(t *testing.T) {
	for name, test := range map[string]struct {
		body []byte
		want string
	}{
		"truncated offset": {littleEndianWords(1)[:2], "could not read offset of dimension 1"},
		"truncated count":  {littleEndianWords(1, 1)[:6], "could not read size of dimension 1"},
		"bounds":           {littleEndianWords(0, 9, 0, 1), "could not fill index"},
		"product":          {littleEndianWords(0, 20, 0, 20), "exceeds NDR input size"},
	} {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(bytes.NewReader(test.body))
			dec.ch.Endianness = binary.LittleEndian
			var got [][]uint32
			var deferred []deferedPtr
			err := dec.fillMultiDimensionalVaryingArray(reflect.ValueOf(&got).Elem(), 2, "", &deferred)
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMultidimensionalConformantVaryingArrayCharacterization(t *testing.T) {
	body := append(littleEndianWords(0, 2, 1, 2), littleEndianWords(10, 20, 30, 40)...)
	dec := NewDecoder(bytes.NewReader(body))
	dec.ch.Endianness = binary.LittleEndian
	dec.conformantMax = []uint32{2, 3}
	var got [][]uint32
	var deferred []deferedPtr
	if err := dec.fillMultiDimensionalConformantVaryingArray(reflect.ValueOf(&got).Elem(), 2, "", &deferred); err != nil {
		t.Fatal(err)
	}
	want := [][]uint32{{0, 10, 20}, {0, 30, 40}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded = %#v, want %#v", got, want)
	}
}

func TestMultidimensionalConformantVaryingArrayErrors(t *testing.T) {
	for name, test := range map[string]struct {
		max  []uint32
		body []byte
		want string
	}{
		"missing max":      {[]uint32{2}, littleEndianWords(0, 2, 0, 2), "max count is less"},
		"max less offset":  {[]uint32{2, 2}, littleEndianWords(3, 1, 0, 1), "max count is less"},
		"truncated offset": {[]uint32{2, 2}, littleEndianWords(1)[:2], "could not read offset of dimension 1"},
		"truncated count":  {[]uint32{2, 2}, littleEndianWords(0, 1)[:6], "could not read actual count of dimension 1"},
	} {
		t.Run(name, func(t *testing.T) {
			dec := NewDecoder(bytes.NewReader(test.body))
			dec.ch.Endianness = binary.LittleEndian
			dec.conformantMax = test.max
			var got [][]uint32
			var deferred []deferedPtr
			err := dec.fillMultiDimensionalConformantVaryingArray(reflect.ValueOf(&got).Elem(), 2, "", &deferred)
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestConformantScanCharacterization(t *testing.T) {
	type wire struct {
		Count    uint32
		Text     string   `ndr:"conformant"`
		Matrix   [][]byte `ndr:"conformant"`
		Ignored  []byte
		Embedded struct {
			Values []uint16 `ndr:"conformant"`
		}
		Pointer *[]byte `ndr:"conformant,pointer"`
	}
	dec := NewDecoder(bytes.NewReader(nil))
	if err := dec.conformantScan(reflect.ValueOf(wire{}), ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec.conformantMax, []uint32{0, 0, 0, 0}) {
		t.Fatalf("maximum slots = %v", dec.conformantMax)
	}
}
