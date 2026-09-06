package kadmin

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalReply(t *testing.T) {
	t.Parallel()
	var a Reply
	b, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 236, a.MessageLength, "message length not as expected")
	assert.Equal(t, 1, a.Version, "message version not as expected")
	assert.Equal(t, 140, a.APREPLength, "AP_REP length not as expected")
	assert.Equal(t, iana.PVNO, a.APREP.PVNO, "AP_REP within reply not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.APREP.MsgType, "AP_REP message type within reply not as expected")
	assert.Equal(t, int32(18), a.APREP.EncPart.EType, "AP_REQ etype not as expected")
	assert.Equal(t, iana.PVNO, a.KRBPriv.PVNO, "KRBPriv within reply not as expected")
	assert.Equal(t, msgtype.KRB_PRIV, a.KRBPriv.MsgType, "KRBPriv type within reply not as expected")
	assert.Equal(t, int32(18), a.KRBPriv.EncPart.EType, "KRBPriv etype not as expected")
}

func TestParseResponsePasswordPolicy(t *testing.T) {
	t.Parallel()
	policy := make([]byte, 30)
	binary.BigEndian.PutUint32(policy[2:6], 13)
	binary.BigEndian.PutUint32(policy[6:10], 9)
	binary.BigEndian.PutUint32(policy[10:14], 1)
	binary.BigEndian.PutUint64(policy[14:22], 864000000000)
	binary.BigEndian.PutUint64(policy[22:30], 1728000000000)

	response := append([]byte{0, 4}, []byte("policy: ")...)
	response = append(response, policy...)
	code, result, got, err := parseResponse(response)

	assert.NoError(t, err)
	assert.Equal(t, uint16(4), code)
	assert.Equal(t, "policy: ", result)
	if assert.NotNil(t, got) {
		assert.Equal(t, uint16(0), got.Version)
		assert.Equal(t, uint32(13), got.MinLength)
		assert.Equal(t, uint32(9), got.History)
		assert.Equal(t, uint32(1), got.Properties)
		assert.Equal(t, uint64(864000000000), got.ExpireIn)
		assert.Equal(t, uint64(1728000000000), got.MinAge)
	}
}

func TestParseResponseRejectsMissingResultCode(t *testing.T) {
	t.Parallel()
	_, _, _, err := parseResponse([]byte{0})
	assert.Error(t, err)
}

func TestReplyUnmarshalRejectsInvalidLengths(t *testing.T) {
	t.Parallel()
	var reply Reply
	assert.Error(t, reply.Unmarshal([]byte{0, 1}))
	assert.Error(t, reply.Unmarshal([]byte{0, 10, 0, 1, 0, 0}))
	assert.Error(t, reply.Unmarshal([]byte{0, 6, 0, 1, 0, 1}))
}

// Request marshal is tested via integration test in the client package due to the dynamic keys and encryption.
