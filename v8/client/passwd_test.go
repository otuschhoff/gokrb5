package client

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/kadmin"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const passwdTestRealm = "KPASSWD.TEST"

func TestChangePasswdProtectedReply(t *testing.T) {
	for _, tt := range []struct {
		name   string
		result []byte
		want   string
	}{
		{name: "success", result: []byte{0, KRB5_KPASSWD_SUCCESS}, want: ""},
		{name: "policy rejection", result: []byte{0, KRB5_KPASSWD_SOFTERROR}, want: "code: 4"},
		{name: "invalid result", result: []byte{0}, want: "process protected kpasswd reply"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sessionKey := s4uTestKey(6)
			cl := passwordChangeClient(t, sessionKey, func(wire []byte) []byte {
				return protectedPasswordReply(t, sessionKey, wire, tt.result)
			})
			before := cl.Credentials.Password()
			const replacement = "replacement-password-for-test"
			ok, err := cl.ChangePasswd(replacement)
			if tt.want == "" {
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, replacement, cl.Credentials.Password())
				return
			}
			require.ErrorContains(t, err, tt.want)
			require.False(t, ok)
			require.Equal(t, before, cl.Credentials.Password())
			require.NotContains(t, err.Error(), replacement)
			_, hasKDCError := errors.AsType[messages.KRBError](err)
			require.False(t, hasKDCError, "a protected result does not carry a KRB-ERROR")
		})
	}
}

func TestChangePasswdKDCErrorRemainsConcrete(t *testing.T) {
	server := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "kadmin/changepw")
	cause := messages.NewKRBError(server, passwdTestRealm, errorcode.KRB_ERR_GENERIC, "rejected")
	cause.EData = []byte{0, KRB5_KPASSWD_AUTHERROR}
	encoded, err := cause.Marshal()
	require.NoError(t, err)
	cl := passwordChangeClient(t, s4uTestKey(6), func([]byte) []byte {
		return framePasswordReply(t, nil, encoded)
	})
	before := cl.Credentials.Password()

	ok, err := cl.ChangePasswd("unused-replacement")
	require.False(t, ok)
	require.IsType(t, cause, err)
	got, found := errors.AsType[messages.KRBError](err)
	require.True(t, found)
	require.Equal(t, cause.ErrorCode, got.ErrorCode)
	require.Equal(t, cause.EData, got.EData)
	require.Equal(t, before, cl.Credentials.Password())
}

func TestChangePasswdRequestBuildError(t *testing.T) {
	sessionKey := s4uTestKey(6)
	sessionKey.KeyType = -1
	cl := passwordChangeClient(t, sessionKey, func([]byte) []byte {
		t.Fatal("invalid request reached password transport")
		return nil
	})
	before := cl.Credentials.Password()
	ok, err := cl.ChangePasswd("unused-replacement")
	require.False(t, ok)
	require.ErrorContains(t, err, "build kpasswd request")
	var classified krberror.Krberror
	require.ErrorAs(t, err, &classified)
	require.Equal(t, krberror.KRBMsgError, classified.RootCause)
	require.Equal(t, before, cl.Credentials.Password())
}

func TestSendToKPasswdRetainsStageErrors(t *testing.T) {
	t.Run("discovery", func(t *testing.T) {
		cfg := config.New()
		cfg.LibDefaults.DNSLookupKDC = false
		cl := NewWithPassword("user", passwdTestRealm, "unused", cfg)
		var request kadmin.Request
		reply, err := cl.sendToKPasswd(request)
		require.ErrorContains(t, err, "discover kpasswd servers")
		require.ErrorContains(t, errors.Unwrap(err), "no kpasswd or kadmin defined in configuration")
		require.Zero(t, reply)
	})
	t.Run("encode", func(t *testing.T) {
		cl := passwordChangeClient(t, s4uTestKey(6), func([]byte) []byte {
			t.Fatal("oversized request reached password transport")
			return nil
		})
		var request kadmin.Request
		request.KRBPriv.EncPart.Cipher = make([]byte, math.MaxUint16)
		reply, err := cl.sendToKPasswd(request)
		require.ErrorContains(t, err, "marshal kpasswd request")
		require.ErrorContains(t, errors.Unwrap(err), "max Uint16 size")
		require.Zero(t, reply)
	})
	t.Run("decode", func(t *testing.T) {
		cl := passwordChangeClient(t, s4uTestKey(6), func([]byte) []byte { return []byte{0} })
		var request kadmin.Request
		reply, err := cl.sendToKPasswd(request)
		require.ErrorContains(t, err, "decode kpasswd reply")
		require.ErrorContains(t, errors.Unwrap(err), "shorter than the 6-byte header")
		require.Zero(t, reply)
	})
}

func passwordChangeClient(t *testing.T, sessionKey types.EncryptionKey, respond func([]byte) []byte) *Client {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1
	var realm config.Realm
	realm.Realm = passwdTestRealm
	realm.KDC = []string{"unused.test"}
	realm.KPasswdServer = []string{"https://kpasswd.test"}
	cfg.Realms = []config.Realm{realm}
	var httpClient http.Client
	httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Helper()
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.NoError(t, request.Body.Close())
		var envelope types.KDCProxyMessage
		require.NoError(t, envelope.Unmarshal(body))
		wire, err := envelope.KerberosMessage()
		require.NoError(t, err)
		response, err := types.NewKDCProxyMessage(respond(wire), "", 0)
		require.NoError(t, err)
		encoded, err := response.Marshal()
		require.NoError(t, err)
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", kkdcpContentType)
		_, err = recorder.Write(encoded)
		require.NoError(t, err)
		return recorder.Result(), nil
	})
	cl := NewWithPassword("user", passwdTestRealm, "old-password-for-test", cfg,
		DisablePAReqEncPARep(true), KKDCPClient(&httpClient))
	et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	replyKey, _, err := cl.Key(et, 0, nil)
	require.NoError(t, err)
	cl.sendToKDCFunc = func(wire []byte, _ string) ([]byte, error) {
		return passwordChangeASReply(t, wire, replyKey, sessionKey), nil
	}
	return cl
}

func passwordChangeASReply(t *testing.T, wire []byte, replyKey, sessionKey types.EncryptionKey) []byte {
	t.Helper()
	var request messages.ASReq
	require.NoError(t, request.Unmarshal(wire))
	body := request.ReqBody
	now := time.Now().UTC()
	var part messages.EncKDCRepPart
	part.Key, part.Nonce, part.Flags = sessionKey, body.Nonce, types.NewKrbFlags()
	part.AuthTime, part.StartTime, part.EndTime = now, now, now.Add(time.Hour)
	part.SRealm, part.SName = body.Realm, body.SName
	plain, err := part.Marshal()
	require.NoError(t, err)
	encPart, err := crypto.GetEncryptedData(plain, replyKey, keyusage.AS_REP_ENCPART, 0)
	require.NoError(t, err)
	var reply messages.ASRep
	reply.PVNO, reply.MsgType = iana.PVNO, msgtype.KRB_AS_REP
	reply.CRealm, reply.CName = body.Realm, body.CName
	reply.Ticket = s4uTestTicket(body.Realm, body.SName.PrincipalNameString())
	reply.EncPart = encPart
	encoded, err := reply.Marshal()
	require.NoError(t, err)
	return encoded
}

func protectedPasswordReply(t *testing.T, sessionKey types.EncryptionKey, wire, result []byte) []byte {
	t.Helper()
	const headerLength = 6
	require.GreaterOrEqual(t, len(wire), headerLength)
	endAPReq := headerLength + int(binary.BigEndian.Uint16(wire[4:6]))
	require.LessOrEqual(t, endAPReq, len(wire))
	var apReq messages.APReq
	require.NoError(t, apReq.Unmarshal(wire[headerLength:endAPReq]))
	require.NoError(t, apReq.DecryptAuthenticator(sessionKey))
	auth := apReq.Authenticator
	apRep, err := messages.NewAPRepFromAuthenticator(auth, sessionKey, auth.SubKey, auth.SeqNumber)
	require.NoError(t, err)
	encoded, err := apRep.Marshal()
	require.NoError(t, err)
	var part messages.EncKrbPrivPart
	part.UserData, part.Timestamp, part.Usec, part.SequenceNumber = result, auth.CTime, auth.Cusec, auth.SeqNumber
	reply := messages.NewKRBPriv(part)
	require.NoError(t, reply.EncryptEncPart(auth.SubKey))
	private, err := reply.Marshal()
	require.NoError(t, err)
	return framePasswordReply(t, encoded, private)
}

func framePasswordReply(t *testing.T, apRep, payload []byte) []byte {
	t.Helper()
	const headerLength = 6
	size, err := clientUint16FromInt("kpasswd reply size", headerLength+len(apRep)+len(payload))
	require.NoError(t, err)
	apLength, err := clientUint16FromInt("kpasswd reply AP-REP size", len(apRep))
	require.NoError(t, err)
	wire := make([]byte, headerLength, int(size))
	binary.BigEndian.PutUint16(wire, size)
	binary.BigEndian.PutUint16(wire[2:], 1)
	binary.BigEndian.PutUint16(wire[4:], apLength)
	wire = append(wire, apRep...)
	return append(wire, payload...)
}
