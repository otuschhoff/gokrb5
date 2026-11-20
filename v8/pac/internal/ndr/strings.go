package ndr

import (
	"fmt"
	"reflect"
)

const (
	subStringArrayTag   = `ndr:"varying,X-subStringArray"`
	subStringArrayValue = "X-subStringArray"
)

func uint16SliceToString(a []uint16) string {
	if a == nil {
		return ""
	}
	length := len(a)
	if length > 0 && a[length-1] == 0 {
		length--
	}
	s := make([]rune, length)
	for i := range length {
		s[i] = rune(a[i])
	}
	return string(s)
}

func (dec *Decoder) readVaryingString(def *[]deferedPtr) (string, error) {
	a := new([]uint16)
	v := reflect.ValueOf(a)
	var t reflect.StructTag
	err := dec.fillUniDimensionalVaryingArray(v.Elem(), t, def)
	if err != nil {
		return "", err
	}
	s := uint16SliceToString(*a)
	return s, nil
}

func (dec *Decoder) readConformantVaryingString(def *[]deferedPtr) (string, error) {
	a := new([]uint16)
	v := reflect.ValueOf(a)
	var t reflect.StructTag
	err := dec.fillUniDimensionalConformantVaryingArray(v.Elem(), t, def)
	if err != nil {
		return "", err
	}
	s := uint16SliceToString(*a)
	return s, nil
}

func (dec *Decoder) readStringsArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagConformant) {
		// Per-dimension maximum counts, consumed from the stream but unused.
		for range d {
			_ = dec.precedingMax()
		}
		// common max size
		_ = dec.precedingMax()
	}
	tag = reflect.StructTag(subStringArrayTag)
	err := dec.fillVaryingArray(v, tag, def)
	if err != nil {
		return fmt.Errorf("could not read string array: %w", err)
	}
	return nil
}
