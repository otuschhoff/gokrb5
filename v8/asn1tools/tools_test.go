package asn1tools

import (
	"bytes"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
)

func TestMarshalLengthBytes(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{length: -1, want: nil},
		{length: 0, want: []byte{0}},
		{length: 127, want: []byte{127}},
		{length: 128, want: []byte{0x81, 0x80}},
		{length: 256, want: []byte{0x82, 0x01, 0x00}},
		{length: 65535, want: []byte{0x82, 0xff, 0xff}},
	}
	for _, test := range tests {
		if got := MarshalLengthBytes(test.length); !bytes.Equal(got, test.want) {
			t.Errorf("MarshalLengthBytes(%d) = %x, want %x", test.length, got, test.want)
		}
	}
}

func TestASNLengthHeader(t *testing.T) {
	tests := []struct {
		name       string
		encoded    []byte
		wantLength int
		wantHeader int
	}{
		{name: "short", encoded: []byte{0x30, 0x7f}, wantLength: 127, wantHeader: 1},
		{name: "long one byte", encoded: []byte{0x30, 0x81, 0x80}, wantLength: 128, wantHeader: 2},
		{name: "long two bytes", encoded: []byte{0x30, 0x82, 0x01, 0x00}, wantLength: 256, wantHeader: 3},
		{name: "missing header", encoded: []byte{0x30}},
		{name: "indefinite", encoded: []byte{0x30, 0x80}},
		{name: "truncated long form", encoded: []byte{0x30, 0x82, 0x01}},
		{name: "oversized long form", encoded: append([]byte{0x30, 0x89}, bytes.Repeat([]byte{0xff}, 9)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := GetLengthFromASN(test.encoded); got != test.wantLength {
				t.Errorf("GetLengthFromASN() = %d, want %d", got, test.wantLength)
			}
			if got := GetNumberBytesInLengthHeader(test.encoded); got != test.wantHeader {
				t.Errorf("GetNumberBytesInLengthHeader() = %d, want %d", got, test.wantHeader)
			}
		})
	}
}

func TestAddASNAppTag(t *testing.T) {
	payload, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	encoded := AddASNAppTag(payload, 14)
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || raw.Class != asn1.ClassApplication || !raw.IsCompound || raw.Tag != 14 || !bytes.Equal(raw.Bytes, payload) {
		t.Fatalf("application wrapper = %#v, trailing bytes = %x", raw, rest)
	}
}
