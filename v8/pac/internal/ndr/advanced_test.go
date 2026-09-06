package ndr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
)

type decoderUnion struct {
	Tag    uint16  `ndr:"unionTag,encapsulated"`
	Number uint32  `ndr:"unionField"`
	Bytes  [4]byte `ndr:"unionField"`
}

func (decoderUnion) SwitchFunc(discriminant interface{}) string {
	if discriminant.(uint16) == 1 {
		return "Number"
	}
	return "Bytes"
}

type nonEncapsulatedDecoderUnion struct {
	Tag    uint16 `ndr:"unionTag"`
	Number uint32 `ndr:"unionField"`
}

func (nonEncapsulatedDecoderUnion) SwitchFunc(interface{}) string { return "Number" }

type invalidDecoderUnion struct {
	Tag   uint16 `ndr:"unionTag,encapsulated"`
	Value uint32 `ndr:"unionField"`
}

type parentSizedBytes []byte

func (parentSizedBytes) Size(parent interface{}) int {
	return int(reflect.ValueOf(parent).FieldByName("Length").Uint())
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestDecodeRejectsMalformedHeaders(t *testing.T) {
	valid := wrapNDRBody(nil)
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "invalid version", mutate: func(data []byte) []byte { data[0] = 2; return data }},
		{name: "invalid endianness", mutate: func(data []byte) []byte { data[1] = 0x20; return data }},
		{name: "invalid common header length", mutate: func(data []byte) []byte { data[2] = 7; return data }},
		{name: "unaligned object length", mutate: func(data []byte) []byte { data[8] = 1; return data }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(append([]byte(nil), valid...))
			if err := NewDecoder(bytes.NewReader(data)).Decode(&struct{}{}); err == nil {
				t.Fatal("Decode() accepted malformed header")
			}
		})
	}
	for length := 0; length < 20; length++ {
		if err := NewDecoder(bytes.NewReader(valid[:length])).Decode(&struct{}{}); err == nil {
			t.Fatalf("Decode() accepted %d-byte header", length)
		}
	}
}

func TestDecodeReaderFailureAndUnsupportedTarget(t *testing.T) {
	if err := NewDecoder(failingReader{}).Decode(&struct{}{}); err == nil {
		t.Fatal("reader failure was not returned")
	}
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(nil))).Decode(&map[string]string{}); err == nil {
		t.Fatal("unsupported target type was accepted")
	}
	var value struct{ Flag bool }
	if err := NewDecoder(bytes.NewReader(wrapNDRBody([]byte{0}))).Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Flag {
		t.Fatal("zero NDR boolean decoded as true")
	}
	if _, err := io.ReadAll(failingReader{}); err == nil {
		t.Fatal("failing reader did not fail")
	}
}

func TestDecodeMultidimensionalArrays(t *testing.T) {
	t.Run("fixed", func(t *testing.T) {
		body := make([]byte, 12)
		for index := 0; index < 6; index++ {
			binary.LittleEndian.PutUint16(body[index*2:], uint16(index+1))
		}
		var got struct{ Values [2][3]uint16 }
		if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&got); err != nil {
			t.Fatal(err)
		}
		want := [2][3]uint16{{1, 2, 3}, {4, 5, 6}}
		if got.Values != want {
			t.Fatalf("fixed array = %v, want %v", got.Values, want)
		}
	})

	tests := []struct {
		name string
		tag  reflect.StructTag
		body []byte
	}{
		{
			name: "conformant",
			tag:  `ndr:"conformant"`,
			body: littleEndianWords(2, 3, 1, 2, 3, 4, 5, 6),
		},
		{
			name: "varying",
			tag:  `ndr:"varying"`,
			body: littleEndianWords(0, 2, 0, 3, 1, 2, 3, 4, 5, 6),
		},
		{
			name: "conformant varying",
			tag:  `ndr:"conformant,varying"`,
			body: littleEndianWords(2, 3, 0, 2, 0, 3, 1, 2, 3, 4, 5, 6),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := reflect.New(reflect.StructOf([]reflect.StructField{{
				Name: "Values",
				Type: reflect.TypeOf([][]uint32{}),
				Tag:  test.tag,
			}}))
			if err := NewDecoder(bytes.NewReader(wrapNDRBody(test.body))).Decode(value.Interface()); err != nil {
				t.Fatal(err)
			}
			got := value.Elem().Field(0).Interface().([][]uint32)
			want := [][]uint32{{1, 2, 3}, {4, 5, 6}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("array = %v, want %v", got, want)
			}
		})
	}
}

func TestDecodePointerAndConformantString(t *testing.T) {
	var pointer struct {
		Value uint32 `ndr:"pointer"`
	}
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(littleEndianWords(1, 0x12345678)))).Decode(&pointer); err != nil {
		t.Fatal(err)
	}
	if pointer.Value != 0x12345678 {
		t.Fatalf("pointer value = %#x", pointer.Value)
	}

	var nilPointer struct {
		Value uint32 `ndr:"pointer"`
	}
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(littleEndianWords(0)))).Decode(&nilPointer); err != nil {
		t.Fatal(err)
	}
	if nilPointer.Value != 0 {
		t.Fatalf("nil pointer value = %#x", nilPointer.Value)
	}

	body := append(littleEndianWords(3, 0, 3), 'O', 0, 'K', 0, 0, 0)
	var text struct {
		Value string `ndr:"conformant"`
	}
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&text); err != nil {
		t.Fatal(err)
	}
	if text.Value != "OK" {
		t.Fatalf("conformant string = %q", text.Value)
	}
}

func TestDecodeUnions(t *testing.T) {
	var encapsulated decoderUnion
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body, 1)
	binary.LittleEndian.PutUint32(body[4:], 0x12345678)
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&encapsulated); err != nil {
		t.Fatal(err)
	}
	if encapsulated.Number != 0x12345678 || encapsulated.Bytes != [4]byte{} {
		t.Fatalf("encapsulated union = %+v", encapsulated)
	}

	var nonEncapsulated nonEncapsulatedDecoderUnion
	body = make([]byte, 8)
	binary.LittleEndian.PutUint16(body, 1)
	binary.LittleEndian.PutUint16(body[2:], 1)
	binary.LittleEndian.PutUint32(body[4:], 0x87654321)
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&nonEncapsulated); err != nil {
		t.Fatal(err)
	}
	if nonEncapsulated.Number != 0x87654321 {
		t.Fatalf("non-encapsulated union = %+v", nonEncapsulated)
	}

	var invalid invalidDecoderUnion
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(make([]byte, 8)))).Decode(&invalid); err == nil {
		t.Fatal("union without SwitchFunc was accepted")
	}
}

func TestDecodePipeAndParentSizedRawBytes(t *testing.T) {
	var pipe struct {
		Values []uint32 `ndr:"pipe"`
	}
	body := littleEndianWords(2, 1, 2, 1, 3, 0)
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&pipe); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pipe.Values, []uint32{1, 2, 3}) {
		t.Fatalf("pipe = %v", pipe.Values)
	}

	var raw struct {
		Length uint32
		Value  parentSizedBytes
	}
	body = append(littleEndianWords(3), 1, 2, 3)
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.Value, parentSizedBytes{1, 2, 3}) {
		t.Fatalf("raw bytes = %v", raw.Value)
	}
}

func TestDecodeRejectsInvalidPipe(t *testing.T) {
	for _, body := range [][]byte{
		littleEndianWords(1000),
		littleEndianWords(2, 1),
		littleEndianWords(1, 1, 1000),
	} {
		var value struct {
			Values []uint32 `ndr:"pipe"`
		}
		if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&value); err == nil {
			t.Fatalf("invalid pipe accepted: %v", body)
		}
	}
}
