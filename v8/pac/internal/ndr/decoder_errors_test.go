package ndr

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
	"testing"
	"testing/iotest"
)

func TestDecoderRetainsReaderFailure(t *testing.T) {
	cause := errors.New("injected NDR reader failure")
	var value struct{ Value uint32 }
	err := NewDecoder(iotest.ErrReader(cause)).Decode(&value)
	if !errors.Is(err, cause) {
		t.Fatalf("Decode error = %v, want original reader failure", err)
	}
}

func TestDecoderRetainsTruncatedHeaderCauses(t *testing.T) {
	data := wrapNDRBody(littleEndianWords(1))
	for length := range len(data) {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			var value struct{ Value uint32 }
			err := NewDecoder(bytes.NewReader(data[:length])).Decode(&value)
			_, malformed := errors.AsType[Malformed](err)
			if !malformed || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Fatalf("truncated stream lost classification or cause: %v", err)
			}
		})
	}
}

func TestDecoderRejectsInvalidTargets(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target any
	}{
		{name: "nil", target: nil},
		{name: "typed nil", target: (*uint32)(nil)},
		{name: "value", target: uint32(1)},
		{name: "invalid reflection", target: reflect.Value{}},
		{name: "unexported field", target: new(struct{ private uint32 })},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := NewDecoder(bytes.NewReader(wrapNDRBody(littleEndianWords(1)))).Decode(tt.target)
			if err == nil {
				t.Fatal("invalid target accepted")
			}
		})
	}
}

func TestDecoderRejectsGoPointerReferent(t *testing.T) {
	t.Parallel()

	const original = uint32(37)
	value := original
	target := &value
	data := wrapNDRBody(littleEndianWords(99))
	err := NewDecoder(bytes.NewReader(data)).Decode(&target)
	malformed, ok := errors.AsType[Malformed](err)
	if !ok || malformed.EText != "could not decode: unsupported type" {
		t.Fatalf("Decode error = %v, want malformed unsupported type", err)
	}
	if target != &value || value != original {
		t.Fatal("Decode modified the unsupported pointer target")
	}
}

func TestDecoderMalformedRetainsTruncationCause(t *testing.T) {
	for _, tt := range []struct {
		name  string
		data  []byte
		cause error
	}{
		{name: "empty value", data: nil, cause: io.EOF},
		{name: "partial value", data: []byte{1, 2}, cause: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var value struct{ Value uint32 }
			data := wrapNDRBody(tt.data)
			err := NewDecoder(bytes.NewReader(data[:20+len(tt.data)])).Decode(&value)
			var malformed Malformed
			if !errors.Is(err, tt.cause) || !errors.As(err, &malformed) {
				t.Fatalf("malformed cause = %v", err)
			}
		})
	}
}
