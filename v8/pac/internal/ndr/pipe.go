package ndr

import (
	"fmt"
	"reflect"
)

func (dec *Decoder) fillPipe(v reflect.Value, tag reflect.StructTag) error {
	count, err := dec.readPipeCount(0)
	if err != nil {
		return err
	}
	all := reflect.MakeSlice(v.Type(), 0, 0)
	for count != 0 {
		chunk := reflect.MakeSlice(v.Type(), count, count)
		if fillErr := dec.fillPipeChunk(chunk, tag); fillErr != nil {
			return fillErr
		}
		if uint64(chunk.Len()) > uint64(dec.size)-uint64(all.Len()) { // #nosec G115 -- decoder lengths are nonnegative.
			return fmt.Errorf("pipe element count exceeds NDR input size %d", dec.size)
		}
		all = reflect.AppendSlice(all, chunk)
		count, err = dec.readPipeCount(all.Len())
		if err != nil {
			return err
		}
	}
	v.Set(all)
	return nil
}

func (dec *Decoder) readPipeCount(existing int) (int, error) {
	count, err := dec.readUint32()
	if err != nil {
		return 0, err
	}
	available := dec.size - existing
	if available < 0 || uint64(count) > uint64(available) { // #nosec G115 -- available is checked nonnegative.
		return 0, fmt.Errorf("pipe element count exceeds NDR input size %d", dec.size)
	}
	return ndrUint32ToInt(count)
}

func (dec *Decoder) fillPipeChunk(chunk reflect.Value, tag reflect.StructTag) error {
	for i := 0; i < chunk.Len(); i++ {
		if err := dec.fill(chunk.Index(i), tag, &[]deferedPtr{}); err != nil {
			return fmt.Errorf("could not fill element %d of pipe: %w", i, err)
		}
	}
	return nil
}
