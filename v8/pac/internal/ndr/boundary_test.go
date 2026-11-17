package ndr

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestTruncatedAlignmentRecordsError(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{1, 2}))
	if _, err := dec.readUint8(); err != nil {
		t.Fatal(err)
	}
	dec.ensureAlignment(4)
	if !errors.Is(dec.resourceErr, io.EOF) {
		t.Fatalf("alignment error = %v, want EOF", dec.resourceErr)
	}
}

func TestTruncatedUnionDiscriminantRecordsError(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{1}))
	dec.isUnion(reflect.ValueOf(uint32(1)), `ndr:"unionTag"`)
	if !errors.Is(dec.resourceErr, io.EOF) {
		t.Fatalf("union discriminant error = %v, want EOF", dec.resourceErr)
	}
}

func TestDecodeThreeDimensionalConformantArray(t *testing.T) {
	var got struct {
		Values [][][]uint32 `ndr:"conformant"`
	}
	body := littleEndianWords(2, 2, 2, 1, 2, 3, 4, 5, 6, 7, 8)
	if err := NewDecoder(bytes.NewReader(wrapNDRBody(body))).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := [][][]uint32{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}}
	if !reflect.DeepEqual(got.Values, want) {
		t.Fatalf("three dimensional values = %v, want %v", got.Values, want)
	}
}

func FuzzDecodeArrays(f *testing.F) {
	f.Add(append([]byte{0}, littleEndianWords(2, 2, 1, 2, 3, 4)...))
	f.Add(append([]byte{0}, littleEndianWords(0, 2)...))
	f.Add(append([]byte{1}, littleEndianWords(0, 2, 0, 2, 1, 2, 3, 4)...))
	f.Add(append([]byte{2}, littleEndianWords(2, 3, 1, 1, 1, 2, 10, 20)...))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		values := []any{
			new(struct {
				Values [][]uint32 `ndr:"conformant"`
			}),
			new(struct {
				Values [][]uint32 `ndr:"varying"`
			}),
			new(struct {
				Values [][]uint32 `ndr:"conformant,varying"`
			}),
			new(struct{ Values [0][2]uint32 }),
			new(struct{ Values [2][0]uint32 }),
		}
		_ = NewDecoder(bytes.NewReader(wrapNDRBody(data[1:]))).Decode(values[int(data[0])%len(values)])
	})
}
