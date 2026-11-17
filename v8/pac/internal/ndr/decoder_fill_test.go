package ndr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
)

type fillAlias uint32

func newFillDecoder(data []byte) *Decoder {
	dec := NewDecoder(bytes.NewReader(data))
	dec.ch.Endianness = binary.LittleEndian
	return dec
}

type (
	fillNested     struct{ Value uint32 }
	fillOuter      struct{ Nested fillNested }
	fillPrivate    struct{ private uint32 }
	fillRaw        struct{ Value fixedRawBytes }
	fillRawPointer struct {
		Value fixedRawBytes `ndr:"pointer"`
	}
)

func TestFillScalarFailures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target any
	}{
		{name: "bool", target: new(bool)},
		{name: "uint8", target: new(uint8)},
		{name: "uint16", target: new(uint16)},
		{name: "uint32", target: new(uint32)},
		{name: "uint64", target: new(uint64)},
		{name: "int8", target: new(int8)},
		{name: "int16", target: new(int16)},
		{name: "int32", target: new(int32)},
		{name: "int64", target: new(int64)},
		{name: "float32", target: new(float32)},
		{name: "float64", target: new(float64)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dec := newFillDecoder(nil)
			var deferred []deferedPtr
			err := dec.fill(tt.target, "", &deferred)
			want := "could not fill " + tt.name + ": EOF"
			if tt.name != "bool" && tt.name != "uint8" {
				want = fmt.Sprintf("could not fill %s: cannot read %d bytes from 0 remaining NDR bytes: EOF",
					tt.name, reflect.TypeOf(tt.target).Elem().Size())
			}
			if err == nil || err.Error() != want || !errors.Is(err, io.EOF) {
				t.Fatalf("fill = %v, want %q wrapping EOF", err, want)
			}
		})
	}
}

func TestFillPreservesReflectionAliases(t *testing.T) {
	t.Run("defined scalar still panics on assignment", func(t *testing.T) {
		var value fillAlias
		dec := newFillDecoder(littleEndianWords(7))
		var deferred []deferedPtr
		defer func() {
			want := "reflect.Set: value of type uint32 is not assignable to type ndr.fillAlias"
			if got := fmt.Sprint(recover()); got != want {
				t.Fatalf("panic = %q, want %q", got, want)
			}
			if dec.r.Buffered() != 0 || value != 0 {
				t.Fatal("alias assignment changed read timing or destination")
			}
		}()
		_ = dec.fill(&value, "", &deferred)
	})
	t.Run("settable reflect value updates original", func(t *testing.T) {
		var value uint32
		dec := newFillDecoder(littleEndianWords(7))
		var deferred []deferedPtr
		if err := dec.fill(reflect.ValueOf(&value).Elem(), "", &deferred); err != nil || value != 7 {
			t.Fatalf("fill = %v, value = %d", err, value)
		}
	})
}

func TestFillErrorTracker(t *testing.T) {
	for _, tt := range []struct {
		name    string
		target  any
		data    []byte
		tag     reflect.StructTag
		want    string
		current []string
		cause   error
	}{
		{
			name: "nested scalar", target: new(fillOuter),
			want: "could not fill struct field(root/fillOuter/Nested/fillNested/Value): " +
				"could not fill struct field(root/fillOuter/Nested/fillNested/Value): " +
				"could not fill uint32: cannot read 4 bytes from 0 remaining NDR bytes: EOF",
			current: []string{"root", "fillOuter", "Nested", "fillNested", "Value"}, cause: io.EOF,
		},
		{
			name: "private field before field push", target: new(fillPrivate),
			want: "NDR field private cannot be set", current: []string{"root", "fillPrivate"},
		},
		{
			name: "pointer", target: new(uint32), tag: `ndr:"pointer"`,
			want:    "could not process struct field(root): could not read pointer: cannot read 4 bytes from 0 remaining NDR bytes: EOF",
			current: []string{"root"}, cause: io.EOF,
		},
		{
			name: "raw pointer", target: new(fillRawPointer),
			want: "could not process struct field(root/fillRawPointer/Value): " +
				"could not read pointer: cannot read 4 bytes from 0 remaining NDR bytes: EOF",
			current: []string{"root", "fillRawPointer", "Value"}, cause: io.EOF,
		},
		{
			name: "raw bytes", target: new(fillRaw), data: []byte{1},
			want: "could not fill raw bytes struct field(root/fillRaw/Value): " +
				"cannot read 3 bytes from 1 remaining NDR bytes: unexpected EOF",
			current: []string{"root", "fillRaw", "Value"}, cause: io.ErrUnexpectedEOF,
		},
		{
			name: "raw slice", target: new(fixedRawBytes),
			want: "could not fill raw bytes struct field(root): size tag not available", current: []string{"root"},
		},
		{
			name: "unsupported", target: new(complex64),
			want: "unsupported type", current: []string{"root"},
		},
		{
			name: "fixed array", target: new([1]uint32),
			want: "could not fill uni-dimensional fixed array: could not fill index 0 of fixed array: " +
				"could not fill uint32: cannot read 4 bytes from 0 remaining NDR bytes: EOF",
			current: []string{"root"}, cause: io.EOF,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dec := newFillDecoder(tt.data)
			dec.current = []string{"root"}
			var deferred []deferedPtr
			err := dec.fill(tt.target, tt.tag, &deferred)
			if err == nil || err.Error() != tt.want || !reflect.DeepEqual(dec.current, tt.current) {
				t.Fatalf("fill = %v, tracker = %v; want %q, %v", err, dec.current, tt.want, tt.current)
			}
			if tt.cause != nil && !errors.Is(err, tt.cause) {
				t.Fatalf("fill lost cause %v: %v", tt.cause, err)
			}
			if value, ok := tt.target.(*fillPrivate); ok && value.private != 0 {
				t.Fatal("private field changed")
			}
		})
	}
}

type fillUnion struct {
	Tag      uint16 `ndr:"unionTag,encapsulated"`
	Skipped  uint32 `ndr:"unionField"`
	Selected uint32 `ndr:"unionField"`
	Tail     uint32
}

func (fillUnion) SwitchFunc(any) string { return "Selected" }

type fillEmptyUnion struct {
	Tag   uint16 `ndr:"unionTag,encapsulated"`
	Value uint32 `ndr:"unionField"`
}

func (fillEmptyUnion) SwitchFunc(any) string { return "" }

func TestFillUnionSelectionAndTracker(t *testing.T) {
	value := fillUnion{Skipped: 99}
	dec := newFillDecoder(littleEndianWords(1, 7, 8))
	dec.current = []string{"root"}
	var deferred []deferedPtr
	if err := dec.fill(&value, "", &deferred); err != nil {
		t.Fatal(err)
	}
	if value.Skipped != 99 || value.Selected != 7 || value.Tail != 8 {
		t.Fatalf("union = %+v", value)
	}
	if !reflect.DeepEqual(dec.current, []string{"root"}) || dec.r.Buffered() != 0 {
		t.Fatalf("tracker = %v, remaining = %d", dec.current, dec.r.Buffered())
	}
}

func TestFillUnionSelectionFailureContract(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target any
		typ    string
		reason string
	}{
		{
			name: "missing selector", target: new(invalidDecoderUnion), typ: "invalidDecoderUnion",
			reason: "struct does not implement union interface",
		},
		{
			name: "empty selection", target: new(fillEmptyUnion), typ: "fillEmptyUnion",
			reason: "the union select function did not return a string for the name of the field to fill",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dec := newFillDecoder(littleEndianWords(1, 7))
			var deferred []deferedPtr
			err := dec.fill(tt.target, "", &deferred)
			want := "could not determine selected union value field for " + tt.typ +
				" with discriminat tag %!s(uint16=1): " + tt.reason
			if err == nil || err.Error() != want || errors.Unwrap(err) != nil {
				t.Fatalf("fill = %v, want unwrapped %q", err, want)
			}
			if !reflect.DeepEqual(dec.current, []string{tt.typ, "Value"}) || dec.r.Buffered() != 6 {
				t.Fatalf("tracker = %v, remaining = %d", dec.current, dec.r.Buffered())
			}
		})
	}
}

func TestFillSliceDispatchPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target any
		data   []byte
		tag    reflect.StructTag
		want   any
		left   int
	}{
		{
			name: "raw before pipe and string tags", target: new(fixedRawBytes),
			data: []byte{1, 2, 3, 9}, tag: `ndr:"size:3,pipe,varying,conformant"`,
			want: fixedRawBytes{1, 2, 3}, left: 1,
		},
		{
			name: "pointer before raw", target: new(fixedRawBytes),
			data: littleEndianWords(0, 9), tag: `ndr:"pointer,pipe"`, want: fixedRawBytes(nil), left: 4,
		},
		{
			name: "pipe before string array", target: new([]string),
			data: littleEndianWords(0, 9), tag: `ndr:"pipe,varying,conformant"`, want: []string{}, left: 4,
		},
		{
			name: "string array before varying array", target: new([]string),
			data: littleEndianWords(0, 1, 0, 2, 0x0041), tag: `ndr:"varying"`, want: []string{"A"},
		},
		{
			name: "substring elements use varying array", target: new([]uint16),
			data: littleEndianWords(0, 2, 0x0041), tag: subStringArrayTag, want: []uint16{65, 0},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dec := newFillDecoder(tt.data)
			dec.conformantMax = []uint32{1, 2}
			var deferred []deferedPtr
			if err := dec.fill(tt.target, tt.tag, &deferred); err != nil {
				t.Fatal(err)
			}
			if got := reflect.ValueOf(tt.target).Elem().Interface(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("value = %#v, want %#v", got, tt.want)
			}
			if dec.r.Buffered() != tt.left || len(deferred) != 0 {
				t.Fatalf("remaining = %d, deferred = %v", dec.r.Buffered(), deferred)
			}
		})
	}
}

func TestFillDeferredRawPointerOrder(t *testing.T) {
	var value struct {
		Raw  fixedRawBytes `ndr:"pointer,pipe"`
		Tail uint32
	}
	dec := newFillDecoder(append(littleEndianWords(1, 7), 1, 2, 3))
	dec.current = []string{"root"}
	if err := dec.process(&value, ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value.Raw, []byte{1, 2, 3}) || value.Tail != 7 || dec.r.Buffered() != 0 {
		t.Fatalf("decoded = %+v, remaining = %d", value, dec.r.Buffered())
	}
	if !reflect.DeepEqual(dec.current, []string{"root"}) {
		t.Fatalf("tracker = %v", dec.current)
	}
}

func TestFillConformantStringFailure(t *testing.T) {
	var value string
	dec := newFillDecoder(nil)
	dec.conformantMax = []uint32{1}
	var deferred []deferedPtr
	err := dec.fill(&value, `ndr:"conformant"`, &deferred)
	want := "could not fill with conformant varying string: could not read offset of uni-dimensional conformant varying array: " +
		"cannot read 4 bytes from 0 remaining NDR bytes: EOF"
	if err == nil || err.Error() != want || !errors.Is(err, io.EOF) {
		t.Fatalf("fill = %v, want %q wrapping EOF", err, want)
	}
}
