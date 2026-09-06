package pac

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/stretchr/testify/assert"
)

func TestRequestorRoundTrip(t *testing.T) {
	want := Requestor{SID: mstypes.RPCSID{
		Revision:            1,
		SubAuthorityCount:   4,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 500},
	}}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "0104000000000005150000000100000002000000f4010000", hex.EncodeToString(b))

	var got Requestor
	if err := got.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "S-1-5-21-1-2-500", got.SID.String())
}

func TestRequestorRejectsMalformedSID(t *testing.T) {
	for _, b := range [][]byte{
		make([]byte, 7),
		{2, 0, 0, 0, 0, 0, 0, 5},
		{1, 1, 0, 0, 0, 0, 0, 5},
	} {
		var requestor Requestor
		assert.Error(t, requestor.Unmarshal(b))
	}
}
