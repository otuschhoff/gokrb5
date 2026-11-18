package kadmin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestUnmarshalReply(t *testing.T) {
	t.Parallel()
	var a Reply
	b, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	// The declared frame length delimits the reply even with bytes following it.
	err = a.Unmarshal(append(b, 0xab))
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
	assert.ErrorContains(t, reply.Unmarshal([]byte{0, 6, 0, 2, 0, 0}), "incorrect protocol version")
}

func TestReplyUnmarshalRejectsInvalidContents(t *testing.T) {
	t.Parallel()

	protected, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		t.Fatal(err)
	}
	const truncatedLength = 6 + 140 + 1
	truncated := protected[:truncatedLength]
	binary.BigEndian.PutUint16(truncated, truncatedLength)
	truncated[truncatedLength-1] = 0x75 // KRB-PRIV application tag without a length.

	tests := []struct {
		name        string
		data        []byte
		wantContext string
	}{
		{name: "ap-rep", data: []byte{0, 7, 0, 1, 0, 1, 0x6f}, wantContext: "decode kpasswd AP-REP:"},
		{name: "krb-priv", data: truncated, wantContext: "decode kpasswd KRB-PRIV:"},
		{name: "krb-error", data: []byte{0, 7, 0, 1, 0, 0, 0x7e}, wantContext: "decode kpasswd KRB-ERROR:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var reply Reply
			err := reply.Unmarshal(test.data)
			if _, ok := errors.AsType[asn1.SyntaxError](err); !ok || !strings.HasPrefix(err.Error(), test.wantContext) {
				t.Fatalf("want %q with ASN.1 syntax cause, got %v", test.wantContext, err)
			}
		})
	}
}

func TestReplyUnmarshalReplacesEarlierReply(t *testing.T) {
	t.Parallel()

	// Version-zero AD password policy, following the result code and text.
	response := append([]byte{0, 4, 'n', 'o'}, make([]byte, 30)...)
	errorFrame := kpasswdErrorFrame(t, response)
	protectedFrame, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	require.NoError(t, err)
	var reply Reply
	require.NoError(t, reply.Unmarshal(errorFrame))
	assert.True(t, reply.IsKRBError)
	assert.Equal(t, uint16(4), reply.ResultCode)
	assert.Equal(t, "no", reply.Result)
	assert.NotNil(t, reply.PasswordPolicy)
	var unusedKey types.EncryptionKey
	serverErr, ok := errors.AsType[messages.KRBError](reply.Decrypt(unusedKey))
	assert.True(t, ok, "server error was not returned as a typed KRB-ERROR")
	assert.EqualValues(t, errorcode.KRB_ERR_GENERIC, serverErr.ErrorCode)

	require.NoError(t, reply.Unmarshal(protectedFrame))
	assert.False(t, reply.IsKRBError)
	assert.Zero(t, reply.ResultCode)
	assert.Empty(t, reply.Result)
	assert.Nil(t, reply.PasswordPolicy)
	assert.Zero(t, reply.KRBError.ErrorCode)
	assert.Equal(t, msgtype.KRB_AP_REP, reply.APREP.MsgType)

	prior := reply
	assert.ErrorContains(t, reply.Unmarshal(kpasswdErrorFrame(t, nil)), "decode kpasswd result:")
	if !reflect.DeepEqual(reply, prior) {
		t.Error("failed decode changed the previously decoded reply")
	}
	require.NoError(t, reply.Unmarshal(errorFrame))
	assert.True(t, reply.IsKRBError)
	assert.Zero(t, reply.APREP.MsgType)
	assert.Zero(t, reply.KRBPriv.MsgType)
}

func kpasswdErrorFrame(t testing.TB, response []byte) []byte {
	t.Helper()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "kadmin/changepw")
	reply := messages.NewKRBError(sname, "EXAMPLE.ORG", errorcode.KRB_ERR_GENERIC, "denied")
	reply.STime = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	reply.Susec = 0
	reply.EData = response
	payload, err := reply.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	length, err := kadminUint16("test reply", 6+len(payload))
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 6, 6+len(payload))
	binary.BigEndian.PutUint16(header, length)
	binary.BigEndian.PutUint16(header[2:4], 1)
	return append(header, payload...)
}

func FuzzReplyUnmarshal(f *testing.F) {
	protected, err := hex.DecodeString(testdata.MarshaledKpasswd_Rep)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(protected)
	f.Add(kpasswdErrorFrame(f, []byte{0, 4, 'n', 'o'}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var reply Reply
		reply.Version = -1
		if err := reply.Unmarshal(data); err != nil {
			if reply.Version != -1 {
				t.Fatal("failed decode changed the prior reply")
			}
			return
		}
		if reply.IsKRBError != (reply.APREPLength == 0) {
			t.Fatalf("reply classification does not match AP-REP length %d", reply.APREPLength)
		}
	})
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
	decryptErr := reply.Decrypt(replyKey)
	assert.ErrorContains(t, decryptErr, "decrypt kpasswd KRB-PRIV:")
	assert.Error(t, errors.Unwrap(decryptErr), "kpasswd decryption error lost its cause")

	krbError := messages.NewKRBError(sname, "EXAMPLE.ORG", 1, "denied")
	errorReply := Reply{IsKRBError: true, KRBError: krbError}
	if err := errorReply.Decrypt(replyKey); err == nil {
		t.Fatal("KRB error reply returned no error")
	}
	if _, _, err := ChangePasswdMsg(cname, "EXAMPLE.ORG", "password", ticket, types.EncryptionKey{KeyType: -1}); err == nil {
		t.Fatal("unsupported session key accepted")
	}
}
