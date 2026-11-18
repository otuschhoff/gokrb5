package keytab

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// characterizationKeytab assembles a version 2 keytab image from raw record
// bodies.
func characterizationKeytab(records ...[]byte) []byte {
	b := []byte{keytabFirstByte, 2}
	for _, record := range records {
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, mustKeytabUint32NoTest("record length", len(record)))
		b = append(b, l...)
		b = append(b, record...)
	}
	return b
}

// characterizationV2Record is a minimal version 2 record body: one component,
// realm "R", name type 1, zero timestamp, eight bit key version 7, enctype 18,
// and a one byte key. The returned slice is 22 bytes with no KVNO32 trailer.
func characterizationV2Record() []byte {
	body := []byte{0, 1}            // component count
	body = append(body, 0, 1, 'R')  // realm
	body = append(body, 0, 1, 'a')  // component
	body = append(body, 0, 0, 0, 1) // name type
	body = append(body, 0, 0, 0, 0) // timestamp
	body = append(body, 7)          // eight bit key version
	body = append(body, 0, 18)      // enctype
	body = append(body, 0, 1, 0xAA) // key length and key
	return body
}

func TestUnmarshalRejectsNegativeProtocolIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		size   int
		want   string
	}{
		{name: "name type", offset: 8, size: 4, want: "principal name type cannot be negative"},
		{name: "enctype", offset: 17, size: 2, want: "encryption type cannot be negative"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := characterizationV2Record()
			for i := test.offset; i < test.offset+test.size; i++ {
				record[i] = 0xff
			}
			err := New().Unmarshal(characterizationKeytab(record))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

// TestUnmarshalHeaderCharacterization pins the header validation order, exact
// error text, and which Keytab fields are mutated on each failure path.
func TestUnmarshalHeaderCharacterization(t *testing.T) {
	t.Run("short input", func(t *testing.T) {
		kt := new(Keytab)
		err := kt.Unmarshal([]byte{keytabFirstByte})
		require.EqualError(t, err, "byte array is less than 2 bytes: 1")
		assert.Equal(t, uint8(0), kt.version, "version must not be assigned")
		assert.Nil(t, kt.byteOrder, "byte order must not be assigned")
		assert.Nil(t, kt.Entries)
	})
	t.Run("bad first byte", func(t *testing.T) {
		kt := new(Keytab)
		err := kt.Unmarshal([]byte{4, 2})
		require.EqualError(t, err, "invalid keytab data. First byte does not equal 5")
		assert.Equal(t, uint8(0), kt.version, "version must not be assigned")
		assert.Nil(t, kt.byteOrder, "byte order must not be assigned")
	})
	t.Run("bad version", func(t *testing.T) {
		kt := new(Keytab)
		err := kt.Unmarshal([]byte{keytabFirstByte, 3})
		require.EqualError(t, err, "invalid keytab data. Keytab version is neither 1 nor 2")
		assert.Equal(t, uint8(3), kt.version, "rejected version remains assigned")
		assert.Nil(t, kt.byteOrder, "byte order must not be assigned")
	})
	t.Run("header only v2", func(t *testing.T) {
		kt := new(Keytab)
		require.NoError(t, kt.Unmarshal([]byte{keytabFirstByte, 2}))
		assert.Equal(t, uint8(2), kt.version)
		assert.Equal(t, binary.BigEndian, kt.byteOrder)
		assert.Empty(t, kt.Entries)
	})
	t.Run("header only v1 uses native order", func(t *testing.T) {
		kt := new(Keytab)
		require.NoError(t, kt.Unmarshal([]byte{keytabFirstByte, 1}))
		assert.Equal(t, uint8(1), kt.version)
		assert.Equal(t, binary.NativeEndian, kt.byteOrder)
	})
}

// TestUnmarshalHoleCharacterization pins negative record length handling:
// the minimum int32 rejection, holes exceeding the remaining data, skipping
// a hole to reach a later record, and a hole ending exactly at EOF.
func TestUnmarshalHoleCharacterization(t *testing.T) {
	t.Run("minimum int32 hole rejected", func(t *testing.T) {
		b := []byte{keytabFirstByte, 2, 0x80, 0, 0, 0}
		err := New().Unmarshal(b)
		require.EqualError(t, err, "invalid keytab hole length at offset 2")
	})
	t.Run("hole exceeds remaining data", func(t *testing.T) {
		b := []byte{keytabFirstByte, 2, 0xFF, 0xFF, 0xFF, 0xFE} // hole of 2 with nothing left
		err := New().Unmarshal(b)
		require.EqualError(t, err, "keytab hole at offset 2 exceeds remaining data")
	})
	t.Run("entry after hole", func(t *testing.T) {
		hole := []byte{0xFF, 0xFF, 0xFF, 0xFC} // hole of 4
		filler := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		record := characterizationV2Record()
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, mustKeytabUint32NoTest("record length", len(record)))
		b := append([]byte{keytabFirstByte, 2}, hole...)
		b = append(b, filler...)
		b = append(b, l...)
		b = append(b, record...)
		kt := New()
		require.NoError(t, kt.Unmarshal(b))
		require.Len(t, kt.Entries, 1)
		assert.Equal(t, "R", kt.Entries[0].Principal.Realm)
	})
	t.Run("hole ending at EOF", func(t *testing.T) {
		b := []byte{keytabFirstByte, 2, 0xFF, 0xFF, 0xFF, 0xFC, 1, 2, 3, 4}
		kt := New()
		require.NoError(t, kt.Unmarshal(b))
		assert.Empty(t, kt.Entries)
	})
}

// TestUnmarshalRecordBoundsCharacterization pins record length validation and
// the silent termination on trailing bytes too short for another length.
func TestUnmarshalRecordBoundsCharacterization(t *testing.T) {
	t.Run("record length exceeds remaining", func(t *testing.T) {
		b := []byte{keytabFirstByte, 2, 0, 0, 0, 10, 1, 2, 3}
		err := New().Unmarshal(b)
		require.EqualError(t, err, "keytab record at offset 2 has length 10 with only 3 bytes remaining")
	})
	t.Run("first record length truncated", func(t *testing.T) {
		err := New().Unmarshal([]byte{keytabFirstByte, 2, 0})
		require.EqualError(t, err, "need 4 bytes at offset 2, input length is 3")
	})
	t.Run("trailing garbage below length size ignored", func(t *testing.T) {
		for _, trailing := range [][]byte{{0xAA}, {0xAA, 0xBB}, {0xAA, 0xBB, 0xCC}} {
			b := append(characterizationKeytab(characterizationV2Record()), trailing...)
			kt := New()
			require.NoError(t, kt.Unmarshal(b), "trailing %v", trailing)
			assert.Len(t, kt.Entries, 1)
		}
	})
}

// TestUnmarshalEntryFieldErrors truncates a record body at every field
// boundary and pins the exact error text and wrap behavior of each stage:
// principal failures are wrapped with the record offset, later field failures
// are returned unwrapped.
func TestUnmarshalEntryFieldErrors(t *testing.T) {
	record := characterizationV2Record()
	tests := map[string]struct {
		bodyLength int
		err        string
		principal  bool
	}{
		"component count truncated":   {1, "need 2 bytes at offset 0, input length is 1", true},
		"component count only":        {2, "need 2 bytes at offset 2, input length is 2", true},
		"principal without name type": {8, "need 4 bytes at offset 8, input length is 8", true},
		"timestamp missing":           {12, "need 4 bytes at offset 12, input length is 12", false},
		"timestamp truncated":         {14, "need 4 bytes at offset 12, input length is 14", false},
		"key version missing":         {16, "need 1 byte at offset 16, input length is 16", false},
		"enctype truncated":           {17, "need 2 bytes at offset 17, input length is 17", false},
		"key length truncated":        {19, "need 2 bytes at offset 19, input length is 19", false},
		"key bytes missing":           {21, "need 1 bytes at offset 21, input length is 21", false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.LessOrEqual(t, test.bodyLength, len(record))
			b := characterizationKeytab(record[:test.bodyLength])
			err := New().Unmarshal(b)
			require.Error(t, err)
			if test.principal {
				require.EqualError(t, err, "invalid principal in keytab record at offset 2: "+test.err)
				inner := errors.Unwrap(err)
				require.NotNil(t, inner, "principal error must wrap the read failure")
				assert.EqualError(t, inner, test.err)
				assert.Nil(t, errors.Unwrap(inner), "read errors do not wrap further")
			} else {
				require.EqualError(t, err, test.err)
				assert.Nil(t, errors.Unwrap(err), "field errors after the principal are not wrapped")
			}
		})
	}

	t.Run("second component truncated", func(t *testing.T) {
		body := []byte{0, 2, 0, 1, 'R', 0, 1, 'a'}
		err := New().Unmarshal(characterizationKeytab(body))
		require.EqualError(t, err, "invalid principal in keytab record at offset 2: need 2 bytes at offset 8, input length is 8")
	})
}

// TestReadHelpersDefensiveBounds exercises the defensive bounds of the
// unsigned read helpers directly, mirroring TestReadBytes.
func TestReadHelpersDefensiveBounds(t *testing.T) {
	endian := binary.ByteOrder(binary.BigEndian)

	p := -1
	if _, err := readUint8([]byte{1}, &p); err == nil {
		t.Fatal("readUint8 should error on a negative offset")
	}
	p = 1
	if _, err := readUint8([]byte{1}, &p); err == nil {
		t.Fatal("readUint8 should error when no byte remains")
	}

	p = -1
	if _, err := readUint32([]byte{1, 2, 3, 4}, &p, &endian); err == nil {
		t.Fatal("readUint32 should error on a negative offset")
	}
	p = 1
	if _, err := readUint32([]byte{1, 2, 3, 4}, &p, &endian); err == nil {
		t.Fatal("readUint32 should error when fewer than 4 bytes remain")
	}

	p = -1
	ke := newEntry()
	if err := readEntryKVNO([]byte{1, 2, 3, 4}, &p, &ke, &endian); err == nil {
		t.Fatal("readEntryKVNO should propagate the read failure")
	}
}

// TestUnmarshalKVNOTrailerCharacterization pins the 32-bit key version trailer
// rules: absent or short trailers are ignored, zero trailers keep the 8-bit
// version, and non-zero trailers override it bit-exactly, including values
// above the int32 range.
func TestUnmarshalKVNOTrailerCharacterization(t *testing.T) {
	tests := map[string]struct {
		kvno8         byte
		trailer       []byte
		expectedKVNO  uint32
		expected32Bit bool
	}{
		"no trailer":            {7, nil, 7, false},
		"short trailer ignored": {7, []byte{0, 0, 1}, 7, false},
		"zero trailer":          {7, []byte{0, 0, 0, 0}, 7, false},
		"trailer overrides":     {7, []byte{1, 2, 3, 4}, 0x01020304, true},
		"trailer above int31":   {7, []byte{0x80, 0, 0, 0}, 0x80000000, true},
		"zero key version":      {0, nil, 0, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			record := characterizationV2Record()
			record[16] = test.kvno8
			record = append(record, test.trailer...)
			kt := New()
			require.NoError(t, kt.Unmarshal(characterizationKeytab(record)))
			require.Len(t, kt.Entries, 1)
			assert.Equal(t, test.expectedKVNO, kt.Entries[0].KVNO)
			assert.Equal(t, test.expected32Bit, kt.Entries[0].kvno32Present)
		})
	}
}

// TestUnmarshalPartialStateOnError pins that entries decoded before a failing
// record are retained when Unmarshal returns an error.
func TestUnmarshalPartialStateOnError(t *testing.T) {
	t.Run("entry before bad principal retained", func(t *testing.T) {
		b := characterizationKeytab(characterizationV2Record(), []byte{0, 1})
		kt := New()
		err := kt.Unmarshal(b)
		require.EqualError(t, err, "invalid principal in keytab record at offset 28: need 2 bytes at offset 2, input length is 2")
		require.Len(t, kt.Entries, 1, "entries decoded before the failure are retained")
		assert.Equal(t, "R", kt.Entries[0].Principal.Realm)
	})
	t.Run("entry before oversized record retained", func(t *testing.T) {
		b := characterizationKeytab(characterizationV2Record())
		b = append(b, 0, 0, 0, 10, 1)
		kt := New()
		err := kt.Unmarshal(b)
		require.EqualError(t, err, "keytab record at offset 28 has length 10 with only 1 bytes remaining")
		require.Len(t, kt.Entries, 1)
	})
}

// TestKeytabByteOrderV1PrefersNativeWhenBothPlausible checks that a plausible
// opposite-endian length does not override an equally plausible native length.
func TestKeytabByteOrderV1PrefersNativeWhenBothPlausible(t *testing.T) {
	t.Parallel()

	// 0x00010000 is 65536 big endian and 256 little endian. Both fit.
	b := make([]byte, 6+65536)
	copy(b, []byte{keytabFirstByte, 1, 0, 1, 0, 0})

	order := keytabByteOrder(b, 1)
	assert.Equal(t, binary.NativeEndian.Uint32(b[2:6]), order.Uint32(b[2:6]))
}

// TestUnmarshalV1AmbiguousByteOrderKeepsNative pins that a version 1 keytab
// whose first record length is invalid in both byte orders keeps the native
// order for the subsequent record parse.
func TestUnmarshalV1AmbiguousByteOrderKeepsNative(t *testing.T) {
	// 0x7FFFFFFF big endian (record of 2 GiB) and -129 little endian (hole of
	// 129 bytes) are both invalid with zero bytes remaining.
	b := []byte{keytabFirstByte, 1, 0x7F, 0xFF, 0xFF, 0xFF}
	kt := new(Keytab)
	err := kt.Unmarshal(b)
	require.Error(t, err)
	if binary.NativeEndian.Uint32(b[2:6]) == 0x7fffffff {
		assert.EqualError(t, err, "keytab record at offset 2 has length 2147483647 with only 0 bytes remaining")
	} else {
		assert.EqualError(t, err, "keytab hole at offset 2 exceeds remaining data")
	}
	assert.Equal(t, binary.NativeEndian, kt.byteOrder)
}
