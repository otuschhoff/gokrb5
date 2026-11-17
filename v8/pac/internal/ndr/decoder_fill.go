package ndr

import (
	"fmt"
	"reflect"
	"strings"
)

type unionSelection struct {
	tag   reflect.Value
	field string
}

func (dec *Decoder) fillStruct(v reflect.Value, localDef *[]deferedPtr) error {
	dec.current = append(dec.current, v.Type().Name())
	var selection unionSelection
	for i := 0; i < v.NumField(); i++ {
		fieldName := v.Type().Field(i).Name
		if !v.Field(i).CanSet() {
			return fmt.Errorf("NDR field %s cannot be set", fieldName)
		}
		dec.current = append(dec.current, fieldName)
		skip, err := dec.skipUnionField(v, i, &selection)
		if err != nil {
			return err
		}
		if skip {
			dec.current = dec.current[:len(dec.current)-1]
			continue
		}
		if err := dec.fillStructField(v, i, localDef); err != nil {
			return err
		}
		dec.current = dec.current[:len(dec.current)-1]
	}
	// Keep the full field path on errors, including errors in nested structs.
	dec.current = dec.current[:len(dec.current)-1]
	return nil
}

func (dec *Decoder) skipUnionField(v reflect.Value, i int, selection *unionSelection) (bool, error) {
	structTag := v.Type().Field(i).Tag
	ndrTag := parseTags(structTag)
	if !selection.tag.IsValid() {
		selection.tag = dec.isUnion(v.Field(i), structTag)
		return false, nil
	}
	if selection.field == "" {
		var err error
		selection.field, err = unionSelectedField(v, selection.tag)
		if err != nil {
			return false, fmt.Errorf("could not determine selected union value field for %s with discriminat"+
				" tag %s: %v", v.Type().Name(), selection.tag, err)
		}
	}
	return ndrTag.HasValue(TagUnionField) && v.Type().Field(i).Name != selection.field, nil
}

func (dec *Decoder) fillStructField(parent reflect.Value, i int, localDef *[]deferedPtr) error {
	v := parent.Field(i)
	tag := parent.Type().Field(i).Tag
	if v.Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) &&
		v.Type().Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
		return dec.fillRawField(parent, v, tag, localDef)
	}
	if err := dec.fill(v, tag, localDef); err != nil {
		return fmt.Errorf("could not fill struct field(%s): %w", strings.Join(dec.current, "/"), err)
	}
	return nil
}

func (dec *Decoder) fillRawField(
	parent reflect.Value,
	v reflect.Value,
	tag reflect.StructTag,
	localDef *[]deferedPtr,
) error {
	tag, err := addSizeToTag(parent, v, tag)
	if err != nil {
		return fmt.Errorf("could not get rawbytes field(%s) size: %w", strings.Join(dec.current, "/"), err)
	}
	ptr, err := dec.isPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %w", strings.Join(dec.current, "/"), err)
	}
	if ptr {
		return nil
	}
	if err := dec.readRawBytes(v, tag); err != nil {
		return fmt.Errorf("could not fill raw bytes struct field(%s): %w", strings.Join(dec.current, "/"), err)
	}
	return nil
}

func (dec *Decoder) fillScalar(v reflect.Value) error {
	i, err := dec.readScalar(v.Kind())
	if err != nil {
		return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
	}
	v.Set(reflect.ValueOf(i))
	return nil
}

func (dec *Decoder) readScalar(kind reflect.Kind) (interface{}, error) {
	switch kind {
	case reflect.Bool:
		return dec.readBool()
	case reflect.Uint8:
		return dec.readUint8()
	case reflect.Uint16:
		return dec.readUint16()
	case reflect.Uint32:
		return dec.readUint32()
	case reflect.Uint64:
		return dec.readUint64()
	case reflect.Int8:
		return dec.readInt8()
	case reflect.Int16:
		return dec.readInt16()
	case reflect.Int32:
		return dec.readInt32()
	case reflect.Int64:
		return dec.readInt64()
	case reflect.Float32:
		return dec.readFloat32()
	case reflect.Float64:
		return dec.readFloat64()
	case reflect.Invalid, reflect.Int, reflect.Uint, reflect.Uintptr, reflect.Complex64, reflect.Complex128,
		reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer,
		reflect.Slice, reflect.String, reflect.Struct, reflect.UnsafePointer:
		return nil, fmt.Errorf("unsupported type")
	default:
		return nil, fmt.Errorf("unsupported type")
	}
}

func (dec *Decoder) fillString(v reflect.Value, tag reflect.StructTag, localDef *[]deferedPtr) error {
	// Strings are always varying, even without an explicit tag.
	ndrTag := parseTags(tag)
	var s string
	var err error
	if ndrTag.HasValue(TagConformant) {
		s, err = dec.readConformantVaryingString(localDef)
		if err != nil {
			return fmt.Errorf("could not fill with conformant varying string: %w", err)
		}
	} else {
		s, err = dec.readVaryingString(localDef)
		if err != nil {
			return fmt.Errorf("could not fill with varying string: %w", err)
		}
	}
	v.Set(reflect.ValueOf(s))
	return nil
}

func (dec *Decoder) fillSlice(v reflect.Value, tag reflect.StructTag, localDef *[]deferedPtr) error {
	if v.Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) && v.Type().Elem().Kind() == reflect.Uint8 {
		if err := dec.readRawBytes(v, tag); err != nil {
			return fmt.Errorf("could not fill raw bytes struct field(%s): %w", strings.Join(dec.current, "/"), err)
		}
		return nil
	}
	ndrTag := parseTags(tag)
	conformant := ndrTag.HasValue(TagConformant)
	varying := ndrTag.HasValue(TagVarying)
	if ndrTag.HasValue(TagPipe) {
		return dec.fillPipe(v, tag)
	}
	_, t := sliceDimensions(v.Type())
	if t.Kind() == reflect.String && !ndrTag.HasValue(subStringArrayValue) {
		return dec.readStringsArray(v, tag, localDef)
	}
	if conformant && varying {
		return dec.fillConformantVaryingArray(v, tag, localDef)
	}
	if !conformant && varying {
		return dec.fillVaryingArray(v, tag, localDef)
	}
	return dec.fillConformantArray(v, tag, localDef)
}
