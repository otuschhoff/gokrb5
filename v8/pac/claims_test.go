package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

// claimsSetBytesFromVector decodes the ClaimsSetMetadata of the supplied
// marshaled PAC_CLIENT_CLAIMS_INFO test vector and returns its ClaimsSetBytes.
func claimsSetBytesFromVector(t *testing.T, hexVector string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexVector)
	require.NoError(t, err, "could not decode test data hex string")
	m := new(mstypes.ClaimsSetMetadata)
	require.NoError(t, ndr.NewDecoder(bytes.NewReader(b)).Decode(m), "could not decode ClaimsSetMetadata")
	require.NotEmpty(t, m.ClaimsSetBytes, "test vector carries no ClaimsSetBytes")
	return m.ClaimsSetBytes
}

func TestDecodeClaimsSetRejectsOversizedConformantCount(t *testing.T) {
	t.Parallel()
	claims := claimsSetBytesFromVector(t, testdata.MarshaledPAC_ClientClaimsInfoStr)
	// The ClaimsArrays conformant max count heads the deferred pointer
	// referent: 16-byte NDR header, 4-byte RPC unique pointer referent, then
	// the 20-byte ClaimsSet body. Inflate it beyond the input size; the
	// bounded decoder must reject it instead of allocating from it.
	binary.LittleEndian.PutUint32(claims[40:], 0xffffffff)
	m := &mstypes.ClaimsSetMetadata{
		ClaimsSetSize:     mustPACUint32(t, len(claims)),
		ClaimsSetBytes:    claims,
		CompressionFormat: mstypes.CompressionFormatNone,
	}
	start := time.Now()
	_, err := decodeClaimsSet(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds NDR input size")
	assert.Less(t, time.Since(start), 5*time.Second, "oversized count must be rejected promptly")
}

func TestDecodeClaimsSetNoBytes(t *testing.T) {
	t.Parallel()
	_, err := decodeClaimsSet(&mstypes.ClaimsSetMetadata{CompressionFormat: mstypes.CompressionFormatNone})
	require.EqualError(t, err, "no bytes available for ClaimsSet")
}

func TestDecodeClaimsSetUnsupportedCompression(t *testing.T) {
	t.Parallel()
	claims := []byte{1, 2, 3, 4}
	encoded := hex.EncodeToString(claims)
	for _, format := range []uint16{mstypes.CompressionFormatLZNT1, mstypes.CompressionFormatXPress} {
		name := "LZNT1"
		if format == mstypes.CompressionFormatXPress {
			name = "XPress"
		}
		m := &mstypes.ClaimsSetMetadata{ClaimsSetBytes: claims, CompressionFormat: format}
		_, err := decodeClaimsSet(m)
		require.EqualError(t, err, "ClaimsSet compressed, format "+name+" not currently supported: "+encoded)
	}
}

func TestDecodeClaimsSetXPressHuffDeflateError(t *testing.T) {
	t.Parallel()
	// Trailing one bits are not valid Huffman coding or padding.
	m := &mstypes.ClaimsSetMetadata{
		ClaimsSetBytes:    bytes.Repeat([]byte{0xff}, 16),
		CompressionFormat: mstypes.CompressionFormatXPressHuff,
	}
	_, err := decodeClaimsSet(m)
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "error deflating: "), "unexpected error: %v", err)
}

func TestPAC_DeviceClaimsInfoStr_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoStr)
	require.NoError(t, err, "could not decode test data hex string")
	var k DeviceClaimsInfo
	require.NoError(t, k.Unmarshal(b))
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrayCount, "claims array count not as expected")
	assert.Equal(t, mstypes.ClaimsSourceTypeAD, k.ClaimsSet.ClaimsArrays[0].ClaimsSourceType, "claims source type not as expected")
	assert.Equal(t, uint32(1), k.ClaimsSet.ClaimsArrays[0].ClaimsCount, "claims count not as expected")
	assert.Equal(t, uint16(3), k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].Type, "claims entry type not as expected")
	assert.Equal(t, ClaimsEntryIDStr, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].ID, "claims entry ID not as expected")
	assert.Equal(t, []mstypes.LPWSTR{{Value: ClaimsEntryValueStr}}, k.ClaimsSet.ClaimsArrays[0].ClaimEntries[0].TypeString.Value, "claims value not as expected")
	assert.Equal(t, mstypes.CompressionFormatNone, k.ClaimsSetMetadata.CompressionFormat, "compression format not as expected")
}

func TestPAC_DeviceClaimsInfoRejectsOversizedClaims(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_ClientClaimsInfoStr)
	require.NoError(t, err, "could not decode test data hex string")
	// Locate the embedded ClaimsSet stream inside the metadata and inflate its
	// first conformant max count. The metadata carries the ClaimsSetBytes at
	// the tail of the deferred referents, so search for the known valid
	// 20-byte ClaimsSet preamble (NDR header, referent, count of 1) and patch
	// the count that follows it.
	valid := claimsSetBytesFromVector(t, testdata.MarshaledPAC_ClientClaimsInfoStr)
	idx := bytes.Index(b, valid)
	require.NotEqual(t, -1, idx, "ClaimsSet stream not found in test vector")
	patched := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(patched[idx+40:], 0xffffffff)
	var k DeviceClaimsInfo
	err = k.Unmarshal(patched)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds NDR input size")
	assert.Contains(t, err.Error(), "error unmarshaling ClientClaimsInfo ClaimsSet")
}
