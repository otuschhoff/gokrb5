package pac

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttributesInfoRoundTrip(t *testing.T) {
	want := AttributesInfo{Flags: PACWasRequested}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "0200000001000000", hex.EncodeToString(b))

	var got AttributesInfo
	if err := got.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(2), got.FlagsLength)
	assert.Equal(t, want.Flags, got.Flags)
}

func TestAttributesInfoRejectsInvalidValues(t *testing.T) {
	for _, b := range [][]byte{
		make([]byte, 7),
		{1, 0, 0, 0, 0, 0, 0, 0},
		{2, 0, 0, 0, 4, 0, 0, 0},
	} {
		var attributes AttributesInfo
		assert.Error(t, attributes.Unmarshal(b))
	}
}
