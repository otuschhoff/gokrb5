package kadmin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
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

func TestReplyUnmarshalRejectsInvalidContents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "version", data: []byte{0, 6, 0, 2, 0, 0}},
		{name: "AP-REP", data: []byte{0, 7, 0, 1, 0, 1, 0}},
		{name: "KRB-ERROR", data: []byte{0, 7, 0, 1, 0, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var reply Reply
			if err := reply.Unmarshal(test.data); err == nil {
				t.Fatal("malformed reply was accepted")
			}
		})
	}

	data, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		t.Fatal(err)
	}
	const truncatedLength = 6 + 140 + 1
	data = data[:truncatedLength]
	binary.BigEndian.PutUint16(data[:2], truncatedLength)
	var reply Reply
	if err := reply.Unmarshal(data); err == nil {
		t.Fatal("malformed KRB-PRIV was accepted")
	}
}

func TestChangePasswordRequestAndReply(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "kadmin/changepw")
	serviceKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{1}, 32)}
	ticket, sessionKey, err := messages.NewTicketWithKey(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), serviceKey, 1, now, now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request, replyKey, err := ChangePasswdMsg(cname, "EXAMPLE.ORG", "new-password", ticket, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := request.Marshal()
	if err != nil || len(encoded) < 6 || int(binary.BigEndian.Uint16(encoded[:2])) != len(encoded) || binary.BigEndian.Uint16(encoded[2:4]) != 0xff80 {
		t.Fatalf("marshaled request = %x, %v", encoded, err)
	}

	part := messages.EncKrbPrivPart{UserData: []byte{0, 0, 'o', 'k'}, Timestamp: now}
	private := messages.NewKRBPriv(part)
	if err := private.EncryptEncPart(replyKey); err != nil {
		t.Fatal(err)
	}
	reply := Reply{KRBPriv: private}
	if err := reply.Decrypt(replyKey); err != nil || reply.ResultCode != 0 || reply.Result != "ok" {
		t.Fatalf("decrypted reply = %d/%q, %v", reply.ResultCode, reply.Result, err)
	}
	reply.KRBPriv.EncPart.Cipher[0] ^= 0xff
	if err := reply.Decrypt(replyKey); err == nil {
		t.Fatal("tampered reply decrypted")
	}

	krbError := messages.NewKRBError(sname, "EXAMPLE.ORG", 1, "denied")
	errorReply := Reply{IsKRBError: true, KRBError: krbError}
	if err := errorReply.Decrypt(replyKey); err == nil {
		t.Fatal("KRB error reply returned no error")
	}
	if _, _, err := ChangePasswdMsg(cname, "EXAMPLE.ORG", "password", ticket, types.EncryptionKey{KeyType: -1}); err == nil {
		t.Fatal("unsupported session key accepted")
	}
}

// Request marshal is tested via integration test in the client package due to the dynamic keys and encryption.
