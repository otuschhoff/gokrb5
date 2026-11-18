// Package ndr provides the ability to unmarshal NDR encoded byte steams into Go data structures
package ndr

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Struct tag values
const (
	TagConformant = "conformant"
	TagVarying    = "varying"
	TagPointer    = "pointer"
	TagPipe       = "pipe"
)

// Decoder unmarshals NDR byte stream data into a Go struct representation
type Decoder struct {
	r             *bufio.Reader // source of the data
	size          int           // initial size of bytes in buffer
	ch            CommonHeader  // NDR common header
	ph            PrivateHeader // NDR private header
	conformantMax []uint32      // conformant max values that were moved to the beginning of the structure
	s             interface{}   // pointer to the structure being populated
	current       []string      // keeps track of the current field being populated
	resourceErr   error
	initErr       error
}

type deferedPtr struct {
	v   reflect.Value
	tag reflect.StructTag
}

// NewDecoder creates a new instance of a NDR Decoder.
func NewDecoder(r io.Reader) *Decoder {
	dec := new(Decoder)
	b, err := io.ReadAll(r)
	if err != nil {
		dec.initErr = err
	}
	dec.size = len(b)
	bufferSize := dec.size
	if bufferSize < int(commonHeaderBytes) {
		bufferSize = int(commonHeaderBytes)
	}
	dec.r = bufio.NewReaderSize(bytes.NewReader(b), bufferSize)
	if dec.initErr == nil {
		_, dec.initErr = dec.r.Peek(dec.size)
	}
	return dec
}

// Decode unmarshals the NDR encoded bytes into the pointer of a struct provided.
func (dec *Decoder) Decode(s interface{}) error {
	target := getReflectValue(s)
	if !target.IsValid() || !target.CanSet() {
		return Errorf("NDR decode target must be a non-nil pointer or settable reflect.Value")
	}
	if dec.initErr != nil {
		return fmt.Errorf("could not read NDR input: %w", dec.initErr)
	}
	dec.s = s
	err := dec.readCommonHeader()
	if err != nil {
		return err
	}
	err = dec.readPrivateHeader()
	if err != nil {
		return err
	}
	_, err = dec.r.Discard(4) // The next 4 bytes are an RPC unique pointer referent. We just skip these.
	if err != nil {
		return Errorf("unable to process byte stream: %w", err)
	}

	return dec.process(s, reflect.StructTag(""))
}

func (dec *Decoder) process(s interface{}, tag reflect.StructTag) error {
	// Scan for conformant fields as their max counts are moved to the beginning
	// http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagfcjh_37
	err := dec.scanConformantArrays(s, tag)
	if err != nil {
		return err
	}
	// Recursively fill the struct fields
	var localDef []deferedPtr
	err = dec.fill(s, tag, &localDef)
	if err != nil {
		return Errorf("could not decode: %w", err)
	}
	if dec.resourceErr != nil {
		return dec.resourceErr
	}
	// Read any deferred referents associated with pointers
	for _, p := range localDef {
		err = dec.process(p.v, p.tag)
		if err != nil {
			return fmt.Errorf("could not decode deferred referent: %w", err)
		}
	}
	return nil
}

// scanConformantArrays scans the structure for embedded conformant fields and captures the maximum element counts for
// dimensions of the array that are moved to the beginning of the structure.
func (dec *Decoder) scanConformantArrays(s interface{}, tag reflect.StructTag) error {
	err := dec.conformantScan(s, tag)
	if err != nil {
		return fmt.Errorf("failed to scan for embedded conformant arrays: %w", err)
	}
	for i := range dec.conformantMax {
		dec.conformantMax[i], err = dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not read preceding conformant max count index %d: %w", i, err)
		}
	}
	return nil
}

// conformantScan inspects the structure's fields for whether they are conformant.
func (dec *Decoder) conformantScan(s interface{}, tag reflect.StructTag) error {
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagPointer) {
		return nil
	}
	v := getReflectValue(s)
	if v.Kind() != reflect.Struct {
		dec.noteConformantValue(v, ndrTag)
		return nil
	}
	for i := 0; i < v.NumField(); i++ {
		if err := dec.conformantScan(v.Field(i), v.Type().Field(i).Tag); err != nil {
			return err
		}
	}
	return nil
}

// noteConformantValue reserves one maximum-count slot for each conformant
// dimension in v. String arrays have an additional shared string maximum.
func (dec *Decoder) noteConformantValue(v reflect.Value, tag tags) {
	if !tag.HasValue(TagConformant) {
		return
	}
	switch v.Kind() {
	case reflect.String:
		dec.conformantMax = append(dec.conformantMax, 0)
	case reflect.Slice:
		dimensions, base := sliceDimensions(v.Type())
		for i := 0; i < dimensions; i++ {
			dec.conformantMax = append(dec.conformantMax, 0)
		}
		if base.Kind() == reflect.String {
			dec.conformantMax = append(dec.conformantMax, 0)
		}
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32,
		reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array,
		reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr,
		reflect.Struct, reflect.UnsafePointer:
		return
	}
}

func (dec *Decoder) isPointer(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) (bool, error) {
	// Pointer so defer filling the referent
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagPointer) {
		p, err := dec.readUint32()
		if err != nil {
			return true, fmt.Errorf("could not read pointer: %w", err)
		}
		ndrTag.delete(TagPointer)
		if p != 0 {
			// if pointer is not zero add to the deferred items at end of stream
			*def = append(*def, deferedPtr{v, ndrTag.StructTag()})
		}
		return true, nil
	}
	return false, nil
}

func getReflectValue(s interface{}) reflect.Value {
	var v reflect.Value
	if r, ok := s.(reflect.Value); ok {
		v = r
	} else if reflect.ValueOf(s).Kind() == reflect.Ptr {
		v = reflect.ValueOf(s).Elem()
	}
	return v
}

// fill populates fields with values from the NDR byte stream.
func (dec *Decoder) fill(s interface{}, tag reflect.StructTag, localDef *[]deferedPtr) error {
	v := getReflectValue(s)

	//// Pointer so defer filling the referent
	ptr, err := dec.isPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %w", strings.Join(dec.current, "/"), err)
	}
	if ptr {
		return nil
	}

	// Populate the value from the byte stream
	switch v.Kind() {
	case reflect.Struct:
		return dec.fillStruct(v, localDef)
	case reflect.Bool, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Float32, reflect.Float64:
		return dec.fillScalar(v)
	case reflect.String:
		return dec.fillString(v, tag, localDef)
	case reflect.Array:
		return dec.fillFixedArray(v, tag, localDef)
	case reflect.Slice:
		return dec.fillSlice(v, tag, localDef)
	case reflect.Invalid, reflect.Int, reflect.Uint, reflect.Uintptr,
		reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func,
		reflect.Interface, reflect.Map, reflect.Ptr, reflect.UnsafePointer:
		return fmt.Errorf("unsupported type")
	}
	return fmt.Errorf("unsupported type")
}

// readBytes returns a number of bytes from the NDR byte stream.
func (dec *Decoder) readBytes(n int) ([]byte, error) {
	// TODO make this take an int64 as input to allow for larger values on all systems?
	if n < 0 {
		return nil, fmt.Errorf("cannot read a negative NDR byte count: %d", n)
	}
	if n > dec.r.Buffered() {
		cause := io.ErrUnexpectedEOF
		if dec.r.Buffered() == 0 {
			cause = io.EOF
		}
		return nil, fmt.Errorf("cannot read %d bytes from %d remaining NDR bytes: %w", n, dec.r.Buffered(), cause)
	}
	b := make([]byte, n)
	m, err := dec.r.Read(b)
	if err != nil || m != n {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return b, fmt.Errorf("error reading bytes from stream: %w", err)
	}
	return b, nil
}
