package ndr

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

// intFromTag returns an int that is a value in a struct tag key/value pair
func intFromTag(tag reflect.StructTag, key string) (int, error) {
	ndrTag := parseTags(tag)
	d := 1
	if n, ok := ndrTag.Map[key]; ok {
		i, err := strconv.Atoi(n)
		if err != nil {
			return d, fmt.Errorf("invalid dimensions tag [%s]: %w", n, err)
		}
		d = i
	}
	return d, nil
}

// parseDimensions returns the a slice of the size of each dimension and type of the member at the deepest level.
func parseDimensions(v reflect.Value) ([]int, reflect.Type) {
	var l []int
	var tb reflect.Type
	if !v.IsValid() {
		return l, tb
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v = reflect.Zero(v.Type().Elem())
		} else {
			v = v.Elem()
		}
	}
	t := v.Type()
	if t.Kind() != reflect.Array && t.Kind() != reflect.Slice {
		return l, tb
	}
	l = append(l, v.Len())
	if t.Elem().Kind() == reflect.Array || t.Elem().Kind() == reflect.Slice {
		// contains array or slice
		var m []int
		element := reflect.Zero(t.Elem())
		if v.Len() > 0 {
			element = v.Index(0)
		}
		m, tb = parseDimensions(element)
		l = append(l, m...)
	} else {
		tb = t.Elem()
	}
	return l, tb
}

// sliceDimensions returns the count of dimensions a slice has.
func sliceDimensions(t reflect.Type) (int, reflect.Type) {
	var d int
	var tb reflect.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice {
		d++
		var n int
		n, tb = sliceDimensions(t.Elem())
		d += n
	} else {
		tb = t
	}
	return d, tb
}

// makeSubSlices is a deep recursive creation/initialisation of multi-dimensional slices.
// Takes the reflect.Value of the 1st dimension and a slice of the lengths of the sub dimensions
func makeSubSlices(v reflect.Value, l []int) {
	if len(l) == 0 {
		return
	}
	ty := v.Type().Elem()
	if ty.Kind() != reflect.Slice {
		return
	}
	nextLength := l[0]
	for i := 0; i < v.Len(); i++ {
		s := reflect.MakeSlice(ty, nextLength, nextLength)
		v.Index(i).Set(s)
		// Are there more sub dimensions?
		if len(l) > 1 {
			makeSubSlices(v.Index(i), l[1:])
		}
	}
}

// multiDimensionalIndexPermutations returns all the permutations of the indexes of a multi-dimensional slice.
// The input is a slice of integers that indicates the max size/length of each dimension
func multiDimensionalIndexPermutations(l []int) [][]int {
	var ps [][]int
	for _, length := range l {
		if length <= 0 {
			return nil
		}
	}
	z := make([]int, len(l)) // The zeros permutation
	ps = append(ps, z)
	// for each dimension, in reverse
	for i := len(l) - 1; i >= 0; i-- {
		ws := make([][]int, len(ps))
		copy(ws, ps)
		// create a permutation for each of the iterations of the current dimension
		for j := 1; j <= l[i]-1; j++ {
			// For each existing permutation
			for _, p := range ws {
				np := make([]int, len(p))
				copy(np, p)
				np[i] = j
				ps = append(ps, np)
			}
		}
	}
	return ps
}

// precedingMax reads off the next conformant max value
func ndrUint32ToInt(value uint32) (int, error) {
	converted := uint64(value)
	if converted > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("NDR count %d exceeds platform int range", value)
	}
	return int(converted), nil // #nosec G115 -- conversion is bounded by the platform max int above.
}

func ndrUint64ToInt(value uint64) (int, error) {
	if value > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("NDR count %d exceeds platform int range", value)
	}
	return int(value), nil // #nosec G115 -- conversion is bounded by the platform max int above.
}

func (dec *Decoder) validateDimensions(lengths []int) error {
	elements := uint64(1)
	for _, length := range lengths {
		if length < 0 || int64(length) > int64(dec.size) {
			return fmt.Errorf("array dimension %d exceeds NDR input size %d", length, dec.size)
		}
		elements *= uint64(length)       // #nosec G115 -- slice lengths and validated dimensions are nonnegative.
		if elements > uint64(dec.size) { // #nosec G115 -- decoder size is validated as nonnegative when created.
			return fmt.Errorf("array element count %d exceeds NDR input size %d", elements, dec.size)
		}
	}
	return nil
}

func (dec *Decoder) precedingMax() uint32 {
	if len(dec.conformantMax) == 0 {
		dec.resourceErr = errors.New("missing conformant array maximum")
		return 0
	}
	m := dec.conformantMax[0]
	dec.conformantMax = dec.conformantMax[1:]
	if int64(m) > int64(dec.size) {
		dec.resourceErr = fmt.Errorf("conformant array count %d exceeds NDR input size %d", m, dec.size)
		return 0
	}
	return m
}

// fillFixedArray establishes if the fixed array is uni or multi dimensional and then fills it.
func (dec *Decoder) fillFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	l, t := parseDimensions(v)
	if t == nil {
		return errors.New("could not establish fixed array element type")
	}
	if t.Kind() == reflect.String {
		tag = reflect.StructTag(subStringArrayTag)
	}
	if len(l) < 1 {
		return errors.New("could not establish dimensions of fixed array")
	}
	if len(l) == 1 {
		err := dec.fillUniDimensionalFixedArray(v, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill uni-dimensional fixed array: %w", err)
		}
		return nil
	}
	// Fixed array is multidimensional
	ps := multiDimensionalIndexPermutations(l[:len(l)-1])
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		// fill with the last dimension array
		err := dec.fillUniDimensionalFixedArray(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill dimension %v of multi-dimensional fixed array: %w", p, err)
		}
	}
	return nil
}

// readUniDimensionalFixedArray reads an array (not slice) from the byte stream.
func (dec *Decoder) fillUniDimensionalFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	for i := 0; i < v.Len(); i++ {
		err := dec.fill(v.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of fixed array: %w", i, err)
		}
	}
	return nil
}

// fillConformantArray establishes if the conformant array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillConformantArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalConformantArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalConformantArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalConformantArray fills the uni-dimensional slice value.
func (dec *Decoder) fillUniDimensionalConformantArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	m := dec.precedingMax()
	n, err := ndrUint32ToInt(m)
	if err != nil {
		return err
	}
	a := reflect.MakeSlice(v.Type(), n, n)
	for i := range n {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional conformant array: %w", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalConformantArray fills the multi-dimensional slice value provided from conformant array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalConformantArray(
	v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr,
) error {
	// Read the max size of each dimensions from the ndr stream
	l := make([]int, d)
	for i := range l {
		maximum := dec.precedingMax()
		maximumInt, err := ndrUint32ToInt(maximum)
		if err != nil {
			return err
		}
		l[i] = maximumInt
	}
	if err := dec.validateDimensions(l); err != nil {
		return err
	}
	// Initialise size of slices
	//   Initialise the size of the 1st dimension
	ty := v.Type()
	v.Set(reflect.MakeSlice(ty, l[0], l[0]))
	// Initialise the size of the other dimensions recursively
	makeSubSlices(v, l[1:])

	// Get all permutations of the indexes and go through each and fill
	ps := multiDimensionalIndexPermutations(l)
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		err := dec.fill(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %v of slice: %w", p, err)
		}
	}
	return nil
}

// fillVaryingArray establishes if the varying array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalVaryingArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalVaryingArray fills the uni-dimensional slice value.
func (dec *Decoder) fillUniDimensionalVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	o, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not read offset of uni-dimensional varying array: %w", err)
	}
	s, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not establish actual count of uni-dimensional varying array: %w", err)
	}
	t := v.Type()
	// Total size of the array is the offset in the index being passed plus the actual count of elements being passed.
	n64 := uint64(s) + uint64(o)
	if n64 > uint64(dec.size) { // #nosec G115 -- decoder size is validated as nonnegative when created.
		return fmt.Errorf("varying array length %d exceeds NDR input size %d", n64, dec.size)
	}
	n, err := ndrUint64ToInt(n64)
	if err != nil {
		return err
	}
	a := reflect.MakeSlice(t, n, n)
	// Populate the array starting at the offset specified
	offset, err := ndrUint32ToInt(o)
	if err != nil {
		return err
	}
	for i := offset; i < n; i++ {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional varying array: %w", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalVaryingArray fills the multi-dimensional slice value provided from varying array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalVaryingArray(
	v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr,
) error {
	offsets, lengths, err := dec.readVaryingDimensions(d)
	if err != nil {
		return err
	}
	if err := dec.validateDimensions(lengths); err != nil {
		return err
	}
	initializeMultiDimensionalSlice(v, lengths)
	return dec.fillMultiDimensionalValues(v, offsets, lengths, lengths, tag, def)
}

// readVaryingDimensions reads each dimension's offset and actual count and
// returns the resulting total length, offset+count, for every dimension.
func (dec *Decoder) readVaryingDimensions(d int) ([]int, []int, error) {
	offsets := make([]int, d)
	lengths := make([]int, d)
	for i := range lengths {
		offset, err := dec.readUint32()
		if err != nil {
			return nil, nil, fmt.Errorf("could not read offset of dimension %d: %w", i+1, err)
		}
		offsets[i], err = ndrUint32ToInt(offset)
		if err != nil {
			return nil, nil, err
		}
		count, err := dec.readUint32()
		if err != nil {
			return nil, nil, fmt.Errorf("could not read size of dimension %d: %w", i+1, err)
		}
		length := uint64(count) + uint64(offset)
		if length > uint64(dec.size) { // #nosec G115 -- decoder size is validated as nonnegative when created.
			return nil, nil, fmt.Errorf("dimension %d length %d exceeds NDR input size %d", i+1, length, dec.size)
		}
		lengths[i], err = ndrUint64ToInt(length)
		if err != nil {
			return nil, nil, err
		}
	}
	return offsets, lengths, nil
}

// fillConformantVaryingArray establishes if the varying array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillConformantVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalConformantVaryingArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalConformantVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalConformantVaryingArray fills the uni-dimensional slice value.
func (dec *Decoder) fillUniDimensionalConformantVaryingArray(
	v reflect.Value, tag reflect.StructTag, def *[]deferedPtr,
) error {
	m := dec.precedingMax()
	o, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not read offset of uni-dimensional conformant varying array: %w", err)
	}
	s, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not establish actual count of uni-dimensional conformant varying array: %w", err)
	}
	if uint64(m) < uint64(o)+uint64(s) {
		return errors.New("max count is less than the offset plus actual count")
	}
	t := v.Type()
	n := int(o) + int(s)
	a := reflect.MakeSlice(t, n, n)
	for i := int(o); i < n; i++ {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional conformant varying array: %w", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalConformantVaryingArray fills a slice from conformant varying array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalConformantVaryingArray(
	v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr,
) error {
	maximums, offsets, lengths, err := dec.readConformantVaryingDimensions(d)
	if err != nil {
		return err
	}
	if err := dec.validateDimensions(maximums); err != nil {
		return err
	}
	initializeMultiDimensionalSlice(v, maximums)
	return dec.fillMultiDimensionalValues(v, offsets, lengths, maximums, tag, def)
}

// readConformantVaryingDimensions reads the preceding maximum counts and the
// per-dimension offset/actual-count pairs. lengths contains offset+count;
// maximums define the allocated storage.
func (dec *Decoder) readConformantVaryingDimensions(d int) ([]int, []int, []int, error) {
	maximums := make([]int, d)
	for i := range maximums {
		maximum, err := ndrUint32ToInt(dec.precedingMax())
		if err != nil {
			return nil, nil, nil, err
		}
		maximums[i] = maximum
	}
	offsets := make([]int, d)
	lengths := make([]int, d)
	for i := range lengths {
		offset, length, err := dec.readConformantVaryingDimension(maximums[i], i+1)
		if err != nil {
			return nil, nil, nil, err
		}
		offsets[i], lengths[i] = offset, length
	}
	return maximums, offsets, lengths, nil
}

func (dec *Decoder) readConformantVaryingDimension(maximum, dimension int) (int, int, error) {
	offset, err := dec.readUint32()
	if err != nil {
		return 0, 0, fmt.Errorf("could not read offset of dimension %d: %w", dimension, err)
	}
	count, err := dec.readUint32()
	if err != nil {
		return 0, 0, fmt.Errorf("could not read actual count of dimension %d: %w", dimension, err)
	}
	combined := uint64(count) + uint64(offset)
	if uint64(maximum) < combined { // #nosec G115 -- maximum is a validated nonnegative int.
		return 0, 0, errors.New("max count is less than the offset plus actual count")
	}
	offsetInt, err := ndrUint32ToInt(offset)
	if err != nil {
		return 0, 0, err
	}
	length, err := ndrUint64ToInt(combined)
	return offsetInt, length, err
}

// initializeMultiDimensionalSlice allocates the nested slices described by
// dimensions.
func initializeMultiDimensionalSlice(v reflect.Value, dimensions []int) {
	v.Set(reflect.MakeSlice(v.Type(), dimensions[0], dimensions[0]))
	makeSubSlices(v, dimensions[1:])
}

// fillMultiDimensionalValues visits every in-range index and decodes values in
// row-major order while retaining the original zero-filled offset regions.
func (dec *Decoder) fillMultiDimensionalValues(
	v reflect.Value, offsets, lengths, dimensions []int, tag reflect.StructTag, def *[]deferedPtr,
) error {
	for _, index := range multiDimensionalIndexPermutations(dimensions) {
		value, ok := multidimensionalValue(v, index, offsets, lengths)
		if !ok {
			continue
		}
		if err := dec.fill(value, tag, def); err != nil {
			return fmt.Errorf("could not fill index %v of slice: %w", index, err)
		}
	}
	return nil
}

// multidimensionalValue returns the value at index when every coordinate is
// inside the offset/length interval for that dimension.
func multidimensionalValue(v reflect.Value, index, offsets, lengths []int) (reflect.Value, bool) {
	for dimension, coordinate := range index {
		if coordinate < offsets[dimension] || coordinate >= lengths[dimension] {
			return reflect.Value{}, false
		}
		v = v.Index(coordinate)
	}
	return v, true
}
