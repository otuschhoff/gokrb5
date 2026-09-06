package ndr

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

type fixedRawBytes []byte

func (fixedRawBytes) Size(interface{}) int { return 3 }

type invalidSizeBytes []byte

func (invalidSizeBytes) Size(interface{}) string { return "three" }

func TestDimensionHelpers(t *testing.T) {
	if got, err := intFromTag(``, "dimensions"); err != nil || got != 1 {
		t.Fatalf("default dimension = %d, %v", got, err)
	}
	if got, err := intFromTag(`ndr:"dimensions:3"`, "dimensions"); err != nil || got != 3 {
		t.Fatalf("tagged dimension = %d, %v", got, err)
	}
	if _, err := intFromTag(`ndr:"dimensions:invalid"`, "dimensions"); err == nil {
		t.Fatal("invalid dimension was accepted")
	}

	array := [2][3]uint16{}
	lengths, elementType := parseDimensions(reflect.ValueOf(array))
	if !reflect.DeepEqual(lengths, []int{2, 3}) || elementType.Kind() != reflect.Uint16 {
		t.Fatalf("array dimensions = %v, %v", lengths, elementType)
	}
	lengths, elementType = parseDimensions(reflect.ValueOf(&array))
	if !reflect.DeepEqual(lengths, []int{2, 3}) || elementType.Kind() != reflect.Uint16 {
		t.Fatalf("pointer dimensions = %v, %v", lengths, elementType)
	}
	if lengths, elementType = parseDimensions(reflect.ValueOf(1)); lengths != nil || elementType != nil {
		t.Fatalf("scalar dimensions = %v, %v", lengths, elementType)
	}
	if dimensions, base := sliceDimensions(reflect.TypeOf(&[][]uint32{})); dimensions != 2 || base.Kind() != reflect.Uint32 {
		t.Fatalf("slice dimensions = %d, %v", dimensions, base)
	}

	value := reflect.MakeSlice(reflect.TypeOf([][]uint8{}), 2, 2)
	makeSubSlices(value, []int{3})
	if value.Index(0).Len() != 3 || value.Index(1).Len() != 3 {
		t.Fatalf("sub-slice lengths = %d, %d", value.Index(0).Len(), value.Index(1).Len())
	}
	permutations := multiDimensionalIndexPermutations([]int{2, 3})
	if len(permutations) != 6 || !reflect.DeepEqual(permutations[0], []int{0, 0}) {
		t.Fatalf("index permutations = %v", permutations)
	}
}

func TestDimensionResourceLimits(t *testing.T) {
	decoder := NewDecoder(bytes.NewReader(make([]byte, 10)))
	if err := decoder.validateDimensions([]int{2, 3}); err != nil {
		t.Fatalf("valid dimensions rejected: %v", err)
	}
	for _, dimensions := range [][]int{{-1}, {11}, {4, 4}} {
		if err := decoder.validateDimensions(dimensions); err == nil {
			t.Fatalf("invalid dimensions accepted: %v", dimensions)
		}
	}

	decoder.conformantMax = []uint32{3}
	if got := decoder.precedingMax(); got != 3 || decoder.resourceErr != nil {
		t.Fatalf("preceding maximum = %d, %v", got, decoder.resourceErr)
	}
	if got := decoder.precedingMax(); got != 0 || decoder.resourceErr == nil {
		t.Fatalf("missing maximum = %d, %v", got, decoder.resourceErr)
	}
	decoder.resourceErr = nil
	decoder.conformantMax = []uint32{11}
	if got := decoder.precedingMax(); got != 0 || decoder.resourceErr == nil {
		t.Fatalf("oversized maximum = %d, %v", got, decoder.resourceErr)
	}
}

func TestTagHelpers(t *testing.T) {
	tag := reflect.StructTag(`ndr:"pointer,conformant,size:4"`)
	parsed := parseTags(tag)
	if !parsed.HasValue(TagPointer) || !parsed.HasValue(TagConformant) || parsed.Map["size"] != "4" {
		t.Fatalf("parsed tags = %+v", parsed)
	}
	parsed.delete(TagPointer)
	parsed.delete("size")
	if parsed.HasValue(TagPointer) {
		t.Fatal("tag value was not deleted")
	}
	roundTrip := parseTags(parsed.StructTag())
	if !roundTrip.HasValue(TagConformant) || roundTrip.HasValue(TagPointer) || len(roundTrip.Map) != 0 {
		t.Fatalf("round-tripped tags = %+v", roundTrip)
	}
}

func TestStringAndRawByteHelpers(t *testing.T) {
	if got := uint16SliceToString([]uint16{'O', 'K', 0}); got != "OK" {
		t.Fatalf("terminated string = %q", got)
	}
	if got := uint16SliceToString([]uint16{'O', 'K'}); got != "OK" {
		t.Fatalf("unterminated string = %q", got)
	}
	if got := uint16SliceToString(nil); got != "" {
		t.Fatalf("empty string = %q", got)
	}

	parent := reflect.ValueOf(struct{}{})
	if size, err := rawBytesSize(parent, reflect.ValueOf(fixedRawBytes{})); err != nil || size != 3 {
		t.Fatalf("raw byte size = %d, %v", size, err)
	}
	if _, err := rawBytesSize(parent, reflect.ValueOf([]byte{})); err == nil {
		t.Fatal("missing Size method was accepted")
	}
	if _, err := rawBytesSize(parent, reflect.ValueOf(invalidSizeBytes{})); err == nil {
		t.Fatal("non-integer Size result was accepted")
	}

	value := fixedRawBytes{}
	decoder := NewDecoder(bytes.NewReader([]byte{1, 2, 3}))
	if err := decoder.readRawBytes(reflect.ValueOf(&value).Elem(), `ndr:"size:3"`); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, fixedRawBytes{1, 2, 3}) {
		t.Fatalf("raw bytes = %v", value)
	}
	for _, tag := range []reflect.StructTag{``, `ndr:"size:invalid"`, `ndr:"size:4"`} {
		decoder := NewDecoder(bytes.NewReader([]byte{1, 2, 3}))
		if err := decoder.readRawBytes(reflect.ValueOf(&value).Elem(), tag); err == nil {
			t.Fatalf("invalid raw byte tag %q was accepted", tag)
		}
	}
}

func TestMalformedError(t *testing.T) {
	err := Errorf("invalid field %d", 7)
	if got := err.Error(); !strings.Contains(got, "malformed NDR stream") || !strings.Contains(got, "invalid field 7") {
		t.Fatalf("error = %q", got)
	}
}
