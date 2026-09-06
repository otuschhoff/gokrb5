package client

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func phase5Keytab(t *testing.T, etypes ...int32) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	principal := keytab.Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}, NameType: nametype.KRB_NT_PRINCIPAL}
	for _, id := range etypes {
		et, err := crypto.GetEtype(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := kt.AddKey(principal, 1, types.EncryptionKey{KeyType: id, KeyValue: make([]byte, et.GetKeyByteSize())}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return kt
}

func TestASReqETypesRestrictedToKeytab(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, 17, 18), cfg)
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []int32{18, 17}, req.ReqBody.EType)
}

func TestASReqETypesIntersectionError(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18}
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, 17), cfg)
	_, err := cl.newASReq()
	assert.EqualError(t, err, "no supported encryption types (config file error?)")
}

func TestSetPADataETypeFromTktEnctypes(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17}
	cfg.LibDefaults.PreferredPreauthTypes = []int{2}
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, 17), cfg, AssumePreAuthentication(true))
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	if err := setPAData(cl, nil, &req); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, int32(17), cl.settings.preAuthEType)
	assert.Equal(t, int32(patype.PA_ENC_TIMESTAMP), cl.settings.preAuthType)
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}
		var encrypted types.PAEncTimestamp
		if err := encrypted.Unmarshal(pa.PADataValue); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, int32(17), encrypted.EType)
		return
	}
	t.Fatal("PA-ENC-TIMESTAMP not found")
}

func TestSetPADataDoesNotRecordTimestampWithoutPreAuth(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New())
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	if err := setPAData(cl, nil, &req); err != nil {
		t.Fatal(err)
	}
	assert.Zero(t, cl.settings.preAuthType)
	assert.False(t, req.PAData.Contains(patype.PA_ENC_TIMESTAMP))
}

func TestPreAuthETypeUsesFirstRequestedKDCOffer(t *testing.T) {
	entries := types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96}, {EType: etypeID.AES128_CTS_HMAC_SHA1_96}}
	info, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	et, err := preAuthEType(&messages.KRBError{EData: methodData}, []int32{etypeID.AES128_CTS_HMAC_SHA1_96})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, et.GetETypeID())
}

func TestPreAuthETypeAcceptsETypeInfoOnly(t *testing.T) {
	entries := types.ETypeInfo{{EType: etypeID.DES3_CBC_SHA1_KD, Salt: []byte("legacy-salt")}}
	info, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	et, err := preAuthEType(&messages.KRBError{EData: methodData}, []int32{etypeID.DES3_CBC_SHA1_KD})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.DES3_CBC_SHA1_KD, et.GetETypeID())
}

func TestASExchangePasswordReplyUsesPreAuthSalt(t *testing.T) {
	const salt = "non-default-kdc-salt"
	entries := types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: salt}}
	info, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	replyKey, err := et.StringToKey("password", salt, et.GetDefaultStringToKeyParams())
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, DisablePAReqEncPARep(true))
	request, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			preAuthError := messages.NewKRBError(request.ReqBody.CName, request.ReqBody.Realm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "pre-authentication required")
			preAuthError.EData = methodData
			return nil, preAuthError
		}
		var retried messages.ASReq
		if err := retried.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		part := messages.EncKDCRepPart{
			Key:       types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("session-key-1234")},
			Nonce:     retried.ReqBody.Nonce,
			Flags:     types.NewKrbFlags(),
			AuthTime:  now,
			StartTime: now,
			EndTime:   now.Add(time.Hour),
			SRealm:    retried.ReqBody.Realm,
			SName:     retried.ReqBody.SName,
		}
		partBytes, err := part.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_AS_REP,
			CRealm:  retried.ReqBody.Realm,
			CName:   retried.ReqBody.CName,
			Ticket:  s4uTestTicket(retried.ReqBody.Realm, retried.ReqBody.SName.PrincipalNameString()),
		}}
		reply.EncPart, err = crypto.GetEncryptedData(partBytes, types.EncryptionKey{KeyType: et.GetETypeID(), KeyValue: replyKey}, keyusage.AS_REP_ENCPART, 0)
		if err != nil {
			t.Fatal(err)
		}
		return reply.Marshal()
	}

	if _, err := cl.ASExchange("EXAMPLE.ORG", request, 0); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, calls)
}

func TestClientCCacheExportRoundTrip(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	original := new(credentials.CCache)
	if err := original.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	cl, err := NewFromCCache(original, config.New())
	if err != nil {
		t.Fatal(err)
	}
	cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP
	exported, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, exported.GetEntries(), len(original.GetEntries()))
	_, found := exported.GetConfig("fast_avail", "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
	assert.False(t, found)
	paType, found := exported.GetConfig("pa_type", "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
	wantOffset, wantOffsetPresent := original.KDCTimeOffset()
	gotOffset, gotOffsetPresent := exported.KDCTimeOffset()
	assert.Equal(t, wantOffsetPresent, gotOffsetPresent)
	assert.Equal(t, wantOffset, gotOffset)

	encoded, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed := new(credentials.CCache)
	if err := reparsed.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	cl2, err := NewFromCCache(reparsed, config.New())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, int32(patype.PA_ENC_TIMESTAMP), cl2.settings.preAuthType)
	exportedAgain, err := cl2.CCache()
	if err != nil {
		t.Fatal(err)
	}
	encodedAgain, err := exportedAgain.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, encoded, encodedAgain)
}

func TestClientCCacheExportAssociatesPATypeWithInitialService(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	original := new(credentials.CCache)
	if err := original.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	credential := original.GetEntries()[0]
	var ticket messages.Ticket
	if err := ticket.Unmarshal(credential.Ticket); err != nil {
		t.Fatal(err)
	}
	ticket.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.example.org")
	ticket.Realm = "EXAMPLE.ORG"
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New())
	cl.cache.addEntryWithDetails(ticket, credential.AuthTime, credential.StartTime, credential.EndTime,
		credential.RenewTill, credential.Key, credential.TicketFlags, credential.Addresses,
		credential.AuthData, credential.IsSKey, credential.SecondTicket)
	cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP

	exported, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	paType, found := exported.GetConfig("pa_type", "HTTP/host.example.org@EXAMPLE.ORG")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
	_, found = exported.GetConfig("pa_type", "krbtgt/EXAMPLE.ORG@EXAMPLE.ORG")
	assert.False(t, found)

	reloaded, err := NewFromCCache(exported, config.New())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := reloaded.CCache()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, roundTrip.GetEntries(), 1)
	paType, found = roundTrip.GetConfig("pa_type", "HTTP/host.example.org@EXAMPLE.ORG")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
}

func TestClockSkewRetry(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96), cfg, AssumePreAuthentication(true))
	serverTime := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second).Add(123456 * time.Microsecond)
	calls := 0
	var retriedRequest []byte
	cl.sendToKDCFunc = func(request []byte, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			err := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KRB_AP_ERR_SKEW, "skew")
			err.STime = serverTime
			err.Susec = serverTime.Nanosecond() / int(time.Microsecond)
			return nil, err
		}
		retriedRequest = append([]byte(nil), request...)
		return nil, messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_CLIENT_REVOKED, "stop")
	}
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.ASExchange("EXAMPLE.ORG", req, 0)
	assert.Error(t, err)
	assert.Equal(t, 2, calls)
	assert.InDelta(t, float64(10*time.Minute), float64(cl.KDCTimeOffset()), float64(2*time.Second))

	var retried messages.ASReq
	if err := retried.Unmarshal(retriedRequest); err != nil {
		t.Fatal(err)
	}
	for _, pa := range retried.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}
		var encrypted types.PAEncTimestamp
		if err := encrypted.Unmarshal(pa.PADataValue); err != nil {
			t.Fatal(err)
		}
		et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
		if err != nil {
			t.Fatal(err)
		}
		key, _, err := cl.Key(et, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := crypto.DecryptMessage(encrypted.Cipher, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
		if err != nil {
			t.Fatal(err)
		}
		var timestamp types.PAEncTSEnc
		if err := timestamp.Unmarshal(plain); err != nil {
			t.Fatal(err)
		}
		assert.WithinDuration(t, serverTime, timestamp.PATimestamp.Add(time.Duration(timestamp.PAUSec)*time.Microsecond), 2*time.Second)
		return
	}
	t.Fatal("retried PA-ENC-TIMESTAMP not found")
}

func TestClockSkewRetryDisabled(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.KDCTimeSync = 0
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96), cfg, AssumePreAuthentication(true))
	calls := 0
	cl.sendToKDCFunc = func(_ []byte, _ string) ([]byte, error) {
		calls++
		return nil, messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KRB_AP_ERR_SKEW, "skew")
	}
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.ASExchange("EXAMPLE.ORG", req, 0)
	assert.Error(t, err)
	assert.Equal(t, 1, calls)
	assert.Zero(t, cl.KDCTimeOffset())
}
