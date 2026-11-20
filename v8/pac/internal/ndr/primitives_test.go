package ndr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"
)

type primitiveRecord struct {
	Bool    bool
	Uint8   uint8
	Uint16  uint16
	Uint32  uint32
	Uint64  uint64
	Int8    int8
	Int16   int16
	Int32   int32
	Int64   int64
	Float32 float32
	Float64 float64
}

func TestDecodePrimitiveRecord(t *testing.T) {
	tests := []struct {
		name  string
		order binary.ByteOrder
	}{
		{name: "little endian", order: binary.LittleEndian},
		{name: "big endian", order: binary.BigEndian},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := marshalPrimitiveRecord(test.order)
			var got primitiveRecord
			if err := NewDecoder(bytes.NewReader(input)).Decode(&got); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			want := primitiveRecord{
				Bool:    true,
				Uint8:   0x7f,
				Uint16:  0x1234,
				Uint32:  0x12345678,
				Uint64:  0x0123456789abcdef,
				Int8:    126,
				Int16:   1234,
				Int32:   12345678,
				Int64:   1234567890123456789,
				Float32: 1.25,
				Float64: -2.5,
			}
			if got != want {
				t.Fatalf("Decode() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestDecodeSignedExtrema(t *testing.T) {
	t.Parallel()

	orders := []struct {
		name  string
		order binary.ByteOrder
	}{
		{name: "little endian", order: binary.LittleEndian},
		{name: "big endian", order: binary.BigEndian},
	}
	for _, tt := range orders {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := marshalPrimitiveRecord(tt.order)
			input[40] = 0x80
			tt.order.PutUint16(input[42:44], 0x8000)
			tt.order.PutUint32(input[44:48], 0x80000000)
			tt.order.PutUint64(input[48:56], 0x8000000000000000)

			var got primitiveRecord
			if err := NewDecoder(bytes.NewReader(input)).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Int8 != math.MinInt8 || got.Int16 != math.MinInt16 ||
				got.Int32 != math.MinInt32 || got.Int64 != math.MinInt64 {
				t.Fatalf("signed fields decoded as %d, %d, %d, %d", got.Int8, got.Int16, got.Int32, got.Int64)
			}
		})
	}
}

func TestDecodePrimitiveRecordRejectsEveryTruncatedPrefix(t *testing.T) {
	input := marshalPrimitiveRecord(binary.LittleEndian)
	for length := range len(input) {
		var got primitiveRecord
		err := NewDecoder(bytes.NewReader(input[:length])).Decode(&got)
		_, malformed := errors.AsType[Malformed](err)
		hasTruncation := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if !malformed || !hasTruncation {
			t.Fatalf("Decode(%d bytes) = %v, want malformed input retaining a truncation cause", length, err)
		}
	}
}

func TestDecodeArraysAndString(t *testing.T) {
	var fixed struct{ Value [4]uint8 }
	var conformant struct {
		Value []uint32 `ndr:"conformant"`
	}
	var varying struct {
		Value []uint32 `ndr:"varying"`
	}
	var conformantVarying struct {
		Value []uint32 `ndr:"conformant,varying"`
	}
	var text struct{ Value string }

	tests := []struct {
		name  string
		body  []byte
		value any
	}{
		{
			name:  "fixed array",
			body:  []byte{1, 2, 3, 4},
			value: &fixed,
		},
		{
			name:  "conformant array",
			body:  littleEndianWords(3, 10, 20, 30),
			value: &conformant,
		},
		{
			name:  "varying array",
			body:  littleEndianWords(0, 3, 10, 20, 30),
			value: &varying,
		},
		{
			name:  "conformant varying array",
			body:  littleEndianWords(3, 0, 3, 10, 20, 30),
			value: &conformantVarying,
		},
		{
			name:  "varying string",
			body:  append(littleEndianWords(0, 3), 'O', 0, 'K', 0, 0, 0),
			value: &text,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decodeTestBody(t, test.body, test.value)
		})
	}

	if fixed.Value != [4]uint8{1, 2, 3, 4} {
		t.Fatalf("fixed array = %v", fixed.Value)
	}
	checkDecodedUint32Array(t, tests[1].name, conformant.Value)
	checkDecodedUint32Array(t, tests[2].name, varying.Value)
	checkDecodedUint32Array(t, tests[3].name, conformantVarying.Value)
	if got := text.Value; got != "OK" {
		t.Fatalf("string = %q, want OK", got)
	}
}

func decodeTestBody(t *testing.T, body []byte, target any) {
	t.Helper()

	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(target); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
}

func checkDecodedUint32Array(t *testing.T, name string, got []uint32) {
	t.Helper()

	if len(got) != 3 || got[0] != 10 || got[1] != 20 || got[2] != 30 {
		t.Fatalf("%s = %v", name, got)
	}
}

func TestDecodeRejectsInvalidArrayCounts(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "varying count exceeds input", body: littleEndianWords(0, 1000)},
		{name: "actual count exceeds conformant maximum", body: littleEndianWords(1, 0, 2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value struct {
				Value []uint32 `ndr:"conformant,varying"`
			}
			if err := NewDecoder(bytes.NewReader(wrapNDRBody(test.body))).Decode(&value); err == nil {
				t.Fatal("Decode() accepted invalid array counts")
			}
		})
	}
}

func TestCharacterAndTagHelpers(t *testing.T) {
	decoder := NewDecoder(bytes.NewReader([]byte{'A'}))
	character, err := decoder.readChar()
	if err != nil || character != 'A' {
		t.Fatalf("readChar = %q, %v", character, err)
	}
	if _, err := decoder.readChar(); err == nil {
		t.Fatal("readChar accepted exhausted input")
	}

	tag := appendTag(reflect.StructTag(`ndr:"conformant"`), "varying")
	parsed := parseTags(tag)
	if !parsed.HasValue(TagConformant) || !parsed.HasValue(TagVarying) {
		t.Fatalf("appended tag = %q", tag)
	}
}

func TestDecodeRejectsMalformedConformantStringArray(t *testing.T) {
	body := littleEndianWords(2, 2, 0, 2, 0, 2)
	body = append(body, 'A', 0, 0, 0, 'B', 0, 0, 0)
	var value struct {
		Strings []string `ndr:"conformant"`
	}
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&value); err == nil {
		t.Fatalf("malformed string array was accepted: %#v", value.Strings)
	}
}

func marshalPrimitiveRecord(order binary.ByteOrder) []byte {
	data := make([]byte, 72)
	data[0] = protocolVersion
	if order == binary.LittleEndian {
		data[1] = 0x10
	}
	order.PutUint16(data[2:4], commonHeaderBytes)
	order.PutUint32(data[8:12], 56)
	order.PutUint32(data[16:20], 1)
	data[20] = 1
	data[21] = 0x7f
	order.PutUint16(data[22:24], 0x1234)
	order.PutUint32(data[24:28], 0x12345678)
	order.PutUint64(data[32:40], 0x0123456789abcdef)
	data[40] = 126
	order.PutUint16(data[42:44], 1234)
	order.PutUint32(data[44:48], 12345678)
	order.PutUint64(data[48:56], 1234567890123456789)
	order.PutUint32(data[56:60], math.Float32bits(1.25))
	order.PutUint64(data[64:72], math.Float64bits(-2.5))
	return data
}

func littleEndianWords(values ...uint32) []byte {
	data := make([]byte, len(values)*4)
	for index, value := range values {
		binary.LittleEndian.PutUint32(data[index*4:], value)
	}
	return data
}

func wrapNDRBody(body []byte) []byte {
	const (
		headerLength    = 16
		objectAlignment = 8
	)
	objectLength := uint64(len(body)) + SizePtr
	alignedLength := (objectLength + objectAlignment - 1) &^ (objectAlignment - 1)
	if alignedLength > math.MaxUint32 || alignedLength > math.MaxInt-headerLength {
		panic("NDR test object length exceeds wire or platform range")
	}
	data := make([]byte, headerLength+int(alignedLength))
	data[0] = protocolVersion
	data[1] = 0x10
	binary.LittleEndian.PutUint16(data[2:4], commonHeaderBytes)
	binary.LittleEndian.PutUint32(data[8:12], uint32(alignedLength)) // #nosec G115 -- checked against MaxUint32 above.
	binary.LittleEndian.PutUint32(data[headerLength:headerLength+SizePtr], 1)
	copy(data[headerLength+SizePtr:], body)
	return data
}
