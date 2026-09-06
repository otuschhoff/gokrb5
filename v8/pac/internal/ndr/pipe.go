package ndr

import (
	"fmt"
	"reflect"
)

func (dec *Decoder) fillPipe(v reflect.Value, tag reflect.StructTag) error {
	s, err := dec.readUint32() // read element count of first chunk
	if err != nil {
		return err
	}
	if uint64(s) > uint64(dec.size) {
		return fmt.Errorf("pipe chunk count %d exceeds NDR input size %d", s, dec.size)
	}
	if uint64(s) > uint64(dec.size) {
		return fmt.Errorf("pipe chunk count %d exceeds NDR input size %d", s, dec.size)
	}
	a := reflect.MakeSlice(v.Type(), 0, 0)
	c := reflect.MakeSlice(v.Type(), int(s), int(s))
	for s != 0 {
		for i := 0; i < int(s); i++ {
			err := dec.fill(c.Index(i), tag, &[]deferedPtr{})
			if err != nil {
				return fmt.Errorf("could not fill element %d of pipe: %v", i, err)
			}
		}
		if uint64(c.Len()) > uint64(dec.size)-uint64(a.Len()) {
			return fmt.Errorf("pipe element count exceeds NDR input size %d", dec.size)
		}
		a = reflect.AppendSlice(a, c)
		s, err = dec.readUint32() // read element count of next chunk
		if err != nil {
			return err
		}
		if uint64(s) > uint64(dec.size)-uint64(a.Len()) {
			return fmt.Errorf("pipe element count exceeds NDR input size %d", dec.size)
		}
		c = reflect.MakeSlice(v.Type(), int(s), int(s))
	}
	v.Set(a)
	return nil
}
